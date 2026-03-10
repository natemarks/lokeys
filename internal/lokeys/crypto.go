package lokeys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

func encryptBytes(plaintext []byte, key []byte) ([]byte, error) {
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
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	buf := bytes.NewBuffer(nil)
	buf.WriteString(fileMagic)
	buf.Write(nonce)
	buf.Write(ciphertext)
	return buf.Bytes(), nil
}

func decryptBytes(ciphertext []byte, key []byte) ([]byte, error) {
	if len(ciphertext) < len(fileMagic) {
		return nil, fmt.Errorf("ciphertext too short")
	}
	if string(ciphertext[:len(fileMagic)]) != fileMagic {
		return nil, fmt.Errorf("invalid ciphertext header")
	}
	ciphertext = ciphertext[len(fileMagic):]
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
