package secretbox

import (
	"crypto/rand"
	"encoding/hex"
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

func (s *SecretBox) Encrypt(msg []byte) []byte {
	return Encrypt(msg, s.key)
}

func (s *SecretBox) Decrypt(msg []byte) (bool, []byte) {
	return Decrypt(msg, s.key)
}

func Encrypt(msg []byte, key [32]byte) []byte {
	nonce := generateNonce()
	return secretbox.Seal(nonce[:], msg, &nonce, &key)
}

func Decrypt(msg []byte, key [32]byte) (bool, []byte) {
	var nonce [24]byte
	copy(nonce[:], msg[:24])
	decrypted, ok := secretbox.Open(nil, msg[24:], &nonce, &key)
	if !ok {
		return false, nil
	}
	return true, decrypted
}

func generateNonce() [24]byte {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}
	return nonce
}
