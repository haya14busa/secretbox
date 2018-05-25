// Package secretbox provides utility wrapper of
// https://godoc.org/golang.org/x/crypto/nacl/secretbox
package secretbox

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

type SecretBox struct {
	key [32]byte
}

func New(key [32]byte) *SecretBox {
	return &SecretBox{key: key}
}

func NewFromHexKey(key string) (*SecretBox, error) {
	secretKeyBytes, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}
	s := &SecretBox{}
	copy(s.key[:], secretKeyBytes)
	return s, nil
}

func (s *SecretBox) Encrypt(plaintext []byte) []byte {
	return Encrypt(plaintext, s.key)
}

func (s *SecretBox) Decrypt(ciphertext []byte) ([]byte, error) {
	return Decrypt(ciphertext, s.key)
}

func Encrypt(plaintext []byte, key [32]byte) []byte {
	nonce := generateNonce()
	return secretbox.Seal(nonce[:], plaintext, &nonce, &key)
}

func Decrypt(ciphertext []byte, key [32]byte) ([]byte, error) {
	var nonce [24]byte
	copy(nonce[:], ciphertext[:24])
	decrypted, ok := secretbox.Open(nil, ciphertext[24:], &nonce, &key)
	if !ok {
		return nil, errors.New("failed to decript given message")
	}
	return decrypted, nil
}

func generateNonce() [24]byte {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}
	return nonce
}
