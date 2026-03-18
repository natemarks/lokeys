package lokeys

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"golang.org/x/crypto/scrypt"
)

func encryptBytes(plaintext []byte, secret []byte) ([]byte, error) {
	return encryptBytesWithRand(plaintext, secret, rand.Reader)
}

func encryptBytesWithRand(plaintext []byte, secret []byte, random io.Reader) ([]byte, error) {
	return encryptBytesWithOptions(plaintext, secret, false, kmsRuntimeConfig{}, random)
}

func encryptBytesWithOptions(plaintext []byte, secret []byte, useKMS bool, kmsCfg kmsRuntimeConfig, random io.Reader) ([]byte, error) {
	innerCiphertext, err := encryptBytesV2WithRand(plaintext, secret, random)
	if err != nil {
		return nil, err
	}
	if !useKMS {
		return innerCiphertext, nil
	}
	return encryptKMSWrapper(innerCiphertext, kmsCfg, random)
}

func encryptBytesV2WithRand(plaintext []byte, secret []byte, random io.Reader) ([]byte, error) {
	salt := make([]byte, kdfSaltSize)
	if _, err := io.ReadFull(random, salt); err != nil {
		return nil, err
	}
	key, err := deriveFileKey(secret, salt)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, err
	}
	enc := gcm.Seal(nil, nonce, plaintext, nil)

	buf := bytes.NewBuffer(nil)
	buf.WriteString(fileMagicV2)
	buf.WriteByte(kdfScryptID)
	if err := binary.Write(buf, binary.BigEndian, uint32(kdfScryptN)); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, uint32(kdfScryptR)); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, uint32(kdfScryptP)); err != nil {
		return nil, err
	}
	buf.WriteByte(byte(len(salt)))
	buf.Write(salt)
	buf.WriteByte(byte(len(nonce)))
	buf.Write(nonce)
	buf.Write(enc)
	return buf.Bytes(), nil
}

func encryptKMSWrapper(innerCiphertext []byte, kmsCfg kmsRuntimeConfig, random io.Reader) ([]byte, error) {
	if kmsCfg.KeyID == "" {
		return nil, fmt.Errorf("%w: kms key id is required", ErrKMSOperation)
	}
	client, resolvedRegion, err := newKMSClient(kmsCfg.Region)
	if err != nil {
		return nil, err
	}

	resp, err := client.GenerateDataKey(context.Background(), &kms.GenerateDataKeyInput{
		KeyId:             &kmsCfg.KeyID,
		KeySpec:           kmstypes.DataKeySpecAes256,
		EncryptionContext: kmsCfg.EncryptionContext,
	})
	if err != nil {
		return nil, wrapKMSError("generate data key", err)
	}
	if len(resp.Plaintext) != 32 || len(resp.CiphertextBlob) == 0 {
		return nil, fmt.Errorf("%w: unexpected GenerateDataKey response", ErrKMSOperation)
	}

	dataKey := make([]byte, len(resp.Plaintext))
	copy(dataKey, resp.Plaintext)
	defer zeroBytes(dataKey)

	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, err
	}
	outerCiphertext := gcm.Seal(nil, nonce, innerCiphertext, nil)

	ctxJSON, err := marshalKMSContext(kmsCfg.EncryptionContext)
	if err != nil {
		return nil, err
	}
	if len(kmsCfg.KeyID) > 255 || len(resolvedRegion) > 255 {
		return nil, fmt.Errorf("kms metadata too long")
	}
	if len(ctxJSON) > 65535 || len(resp.CiphertextBlob) > 65535 {
		return nil, fmt.Errorf("kms payload metadata too large")
	}

	buf := bytes.NewBuffer(nil)
	buf.WriteString(fileMagicV3)
	buf.WriteByte(byte(len(kmsCfg.KeyID)))
	buf.WriteString(kmsCfg.KeyID)
	buf.WriteByte(byte(len(resolvedRegion)))
	buf.WriteString(resolvedRegion)
	if err := binary.Write(buf, binary.BigEndian, uint16(len(ctxJSON))); err != nil {
		return nil, err
	}
	buf.Write(ctxJSON)
	if err := binary.Write(buf, binary.BigEndian, uint16(len(resp.CiphertextBlob))); err != nil {
		return nil, err
	}
	buf.Write(resp.CiphertextBlob)
	buf.WriteByte(byte(len(nonce)))
	buf.Write(nonce)
	buf.Write(outerCiphertext)
	return buf.Bytes(), nil
}

func decryptBytes(ciphertext []byte, secret []byte) ([]byte, error) {
	if len(ciphertext) < len(fileMagicV1) {
		return nil, fmt.Errorf("ciphertext too short")
	}
	magic := string(ciphertext[:len(fileMagicV1)])
	if magic == fileMagicV3 {
		return decryptBytesV3(ciphertext[len(fileMagicV3):], secret)
	}
	if magic == fileMagicV2 {
		return decryptBytesV2(ciphertext[len(fileMagicV2):], secret)
	}
	if magic == fileMagicV1 {
		return decryptBytesV1(ciphertext[len(fileMagicV1):], secret)
	}
	return nil, fmt.Errorf("invalid ciphertext header")
}

func decryptBytesV1(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := ciphertext[:nonceSize]
	enc := ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, enc, nil)
}

func decryptBytesV2(ciphertext []byte, secret []byte) ([]byte, error) {
	if len(ciphertext) < 1+(4*3)+1+1 {
		return nil, fmt.Errorf("ciphertext too short")
	}
	offset := 0
	kdfID := ciphertext[offset]
	offset++
	if kdfID != kdfScryptID {
		return nil, fmt.Errorf("unsupported kdf id: %d", kdfID)
	}
	n := int(binary.BigEndian.Uint32(ciphertext[offset : offset+4]))
	offset += 4
	r := int(binary.BigEndian.Uint32(ciphertext[offset : offset+4]))
	offset += 4
	p := int(binary.BigEndian.Uint32(ciphertext[offset : offset+4]))
	offset += 4
	saltLen := int(ciphertext[offset])
	offset++
	if saltLen <= 0 || len(ciphertext) < offset+saltLen+1 {
		return nil, fmt.Errorf("invalid ciphertext header")
	}
	salt := ciphertext[offset : offset+saltLen]
	offset += saltLen
	nonceLen := int(ciphertext[offset])
	offset++
	if nonceLen <= 0 || len(ciphertext) < offset+nonceLen {
		return nil, fmt.Errorf("invalid ciphertext header")
	}
	nonce := ciphertext[offset : offset+nonceLen]
	enc := ciphertext[offset+nonceLen:]

	key, err := scrypt.Key(secret, salt, n, r, p, kdfDerivedKeySize)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid ciphertext nonce size")
	}
	return gcm.Open(nil, nonce, enc, nil)
}

func decryptBytesV3(ciphertext []byte, secret []byte) ([]byte, error) {
	if len(ciphertext) < 1+1+2+2+1 {
		return nil, fmt.Errorf("ciphertext too short")
	}
	offset := 0
	keyIDLen := int(ciphertext[offset])
	offset++
	if len(ciphertext) < offset+keyIDLen+1 {
		return nil, fmt.Errorf("invalid ciphertext header")
	}
	keyID := string(ciphertext[offset : offset+keyIDLen])
	offset += keyIDLen

	regionLen := int(ciphertext[offset])
	offset++
	if len(ciphertext) < offset+regionLen+2 {
		return nil, fmt.Errorf("invalid ciphertext header")
	}
	region := string(ciphertext[offset : offset+regionLen])
	offset += regionLen

	ctxLen := int(binary.BigEndian.Uint16(ciphertext[offset : offset+2]))
	offset += 2
	if len(ciphertext) < offset+ctxLen+2 {
		return nil, fmt.Errorf("invalid ciphertext header")
	}
	ctxRaw := ciphertext[offset : offset+ctxLen]
	offset += ctxLen

	edkLen := int(binary.BigEndian.Uint16(ciphertext[offset : offset+2]))
	offset += 2
	if len(ciphertext) < offset+edkLen+1 {
		return nil, fmt.Errorf("invalid ciphertext header")
	}
	edk := ciphertext[offset : offset+edkLen]
	offset += edkLen

	nonceLen := int(ciphertext[offset])
	offset++
	if nonceLen <= 0 || len(ciphertext) < offset+nonceLen {
		return nil, fmt.Errorf("invalid ciphertext header")
	}
	nonce := ciphertext[offset : offset+nonceLen]
	outerCiphertext := ciphertext[offset+nonceLen:]

	ctx, err := unmarshalKMSContext(ctxRaw)
	if err != nil {
		return nil, err
	}
	client, _, err := newKMSClient(region)
	if err != nil {
		return nil, err
	}
	decryptInput := &kms.DecryptInput{
		CiphertextBlob:    edk,
		EncryptionContext: ctx,
		KeyId:             nil,
	}
	if keyID != "" {
		decryptInput.KeyId = &keyID
	}
	resp, err := client.Decrypt(context.Background(), decryptInput)
	if err != nil {
		return nil, wrapKMSError("decrypt data key", err)
	}
	if len(resp.Plaintext) != 32 {
		return nil, fmt.Errorf("%w: unexpected Decrypt response", ErrKMSOperation)
	}
	dataKey := make([]byte, len(resp.Plaintext))
	copy(dataKey, resp.Plaintext)
	defer zeroBytes(dataKey)

	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid ciphertext nonce size")
	}
	innerCiphertext, err := gcm.Open(nil, nonce, outerCiphertext, nil)
	if err != nil {
		return nil, err
	}
	return decryptBytes(innerCiphertext, secret)
}

func deriveFileKey(secret []byte, salt []byte) ([]byte, error) {
	return scrypt.Key(secret, salt, kdfScryptN, kdfScryptR, kdfScryptP, kdfDerivedKeySize)
}

func encryptFile(src, dst string, key []byte, useKMS bool, kmsCfg kmsRuntimeConfig) error {
	vlogf("encrypt file src=%s dst=%s use_kms=%t", src, dst, useKMS)
	plaintext, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	var ciphertext []byte
	if useKMS {
		ciphertext, err = encryptBytesWithOptions(plaintext, key, true, kmsCfg, rand.Reader)
	} else {
		ciphertext, err = encryptBytes(plaintext, key)
	}
	if err != nil {
		return err
	}
	return os.WriteFile(dst, ciphertext, 0600)
}

func decryptFile(src, dst string, key []byte, _ bool, _ kmsRuntimeConfig) error {
	vlogf("decrypt file src=%s dst=%s", src, dst)
	ciphertext, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	plaintext, err := decryptBytes(ciphertext, key)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, plaintext, 0600)
}

func marshalKMSContext(ctx map[string]string) ([]byte, error) {
	if len(ctx) == 0 {
		return []byte("{}"), nil
	}
	keys := make([]string, 0, len(ctx))
	for k := range ctx {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered := make(map[string]string, len(ctx))
	for _, k := range keys {
		ordered[k] = ctx[k]
	}
	raw, err := json.Marshal(ordered)
	if err != nil {
		return nil, fmt.Errorf("marshal kms encryption context: %w", err)
	}
	return raw, nil
}

func unmarshalKMSContext(raw []byte) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	ctx := map[string]string{}
	if err := json.Unmarshal(raw, &ctx); err != nil {
		return nil, fmt.Errorf("invalid kms encryption context: %w", err)
	}
	if len(ctx) == 0 {
		return nil, nil
	}
	return ctx, nil
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func isKMSError(err error) bool {
	return errors.Is(err, ErrKMSOperation)
}
