package lokeys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"testing"
)

func TestEncryptDecryptV2RoundTrip(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	plaintext := []byte("secret value")

	ciphertext, err := encryptBytes(plaintext, secret)
	if err != nil {
		t.Fatalf("encryptBytes: %v", err)
	}
	if !bytes.HasPrefix(ciphertext, []byte(fileMagicV2)) {
		t.Fatalf("expected %s header", fileMagicV2)
	}

	decrypted, err := decryptBytes(ciphertext, secret)
	if err != nil {
		t.Fatalf("decryptBytes: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestDecryptBytesSupportsLegacyV1Format(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	plaintext := []byte("legacy payload")

	legacyCiphertext, err := legacyEncryptV1(plaintext, secret)
	if err != nil {
		t.Fatalf("legacyEncryptV1: %v", err)
	}
	if !bytes.HasPrefix(legacyCiphertext, []byte(fileMagicV1)) {
		t.Fatalf("expected %s header", fileMagicV1)
	}

	decrypted, err := decryptBytes(legacyCiphertext, secret)
	if err != nil {
		t.Fatalf("decryptBytes legacy: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("legacy plaintext mismatch")
	}
}

func legacyEncryptV1(plaintext []byte, key []byte) ([]byte, error) {
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
	out := make([]byte, 0, len(fileMagicV1)+len(nonce)+len(enc))
	out = append(out, []byte(fileMagicV1)...)
	out = append(out, nonce...)
	out = append(out, enc...)
	return out, nil
}
