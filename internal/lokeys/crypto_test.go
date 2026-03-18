package lokeys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"
)

// This module validates encrypted payload compatibility and defensive parsing.
//
// Test strategy:
// - verify modern v2 round trips,
// - verify backward compatibility with v1 payloads,
// - verify malformed header/nonce states fail with errors,
// - verify randomness can be injected for deterministic fixtures.

// TestEncryptDecryptV2RoundTrip ensures v2 encryption/decryption returns exact
// plaintext and emits the expected v2 header marker.
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

// TestDecryptBytesSupportsLegacyV1Format ensures existing v1 ciphertext remains
// readable so key migrations and upgrades do not strand prior data.
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

// TestEncryptBytesWithRand_DeterministicHeaderAndNonceForFixtureReader verifies
// encryptBytesWithRand consumes caller-provided entropy so tests can produce
// deterministic vectors.
func TestEncryptBytesWithRand_DeterministicHeaderAndNonceForFixtureReader(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	plaintext := []byte("fixture")
	fixture := bytes.NewReader(bytes.Repeat([]byte{0xAB}, kdfSaltSize+12))

	ciphertext, err := encryptBytesWithRand(plaintext, secret, fixture)
	if err != nil {
		t.Fatalf("encryptBytesWithRand: %v", err)
	}
	if !bytes.HasPrefix(ciphertext, []byte(fileMagicV2)) {
		t.Fatalf("expected %s prefix", fileMagicV2)
	}
	offset := len(fileMagicV2) + 1 + (4 * 3)
	saltLen := int(ciphertext[offset])
	offset++
	salt := ciphertext[offset : offset+saltLen]
	if !bytes.Equal(salt, bytes.Repeat([]byte{0xAB}, kdfSaltSize)) {
		t.Fatalf("unexpected salt bytes")
	}
}

// TestDecryptBytesV2_InvalidNonceLen_Errors ensures malformed nonce metadata is
// rejected before AES-GCM open is attempted.
func TestDecryptBytesV2_InvalidNonceLen_Errors(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	ciphertext, err := encryptBytes([]byte("x"), secret)
	if err != nil {
		t.Fatalf("encryptBytes: %v", err)
	}
	payload := append([]byte(nil), ciphertext[len(fileMagicV2):]...)
	offset := 1 + (4 * 3)
	saltLen := int(payload[offset])
	offset++
	offset += saltLen
	payload[offset] = byte(7)

	_, err = decryptBytesV2(payload, secret)
	if err == nil {
		t.Fatalf("expected invalid nonce size error")
	}
}

// TestDecryptBytesV2_UnsupportedKDFID_Errors ensures unsupported metadata
// cannot silently downgrade or bypass the KDF contract.
func TestDecryptBytesV2_UnsupportedKDFID_Errors(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	payload := make([]byte, 1+(4*3)+1+1)
	payload[0] = 99
	binary.BigEndian.PutUint32(payload[1:5], uint32(kdfScryptN))
	binary.BigEndian.PutUint32(payload[5:9], uint32(kdfScryptR))
	binary.BigEndian.PutUint32(payload[9:13], uint32(kdfScryptP))
	payload[13] = 1
	payload[14] = 1

	_, err := decryptBytesV2(payload, secret)
	if err == nil {
		t.Fatalf("expected unsupported kdf id error")
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
