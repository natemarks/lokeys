package lokeys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/scrypt"
)

func encryptBytes(plaintext []byte, secret []byte) ([]byte, error) {
	salt := make([]byte, kdfSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
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
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
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

func decryptBytes(ciphertext []byte, secret []byte) ([]byte, error) {
	if len(ciphertext) < len(fileMagicV1) {
		return nil, fmt.Errorf("ciphertext too short")
	}
	magic := string(ciphertext[:len(fileMagicV1)])
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

func deriveFileKey(secret []byte, salt []byte) ([]byte, error) {
	return scrypt.Key(secret, salt, kdfScryptN, kdfScryptR, kdfScryptP, kdfDerivedKeySize)
}

func encryptFile(src, dst string, key []byte) error {
	plaintext, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	ciphertext, err := encryptBytes(plaintext, key)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, ciphertext, 0600)
}

func decryptFile(src, dst string, key []byte) error {
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
