package secretbox

import (
	"errors"
	"fmt"
	"testing"
)

func TestSecretBox(t *testing.T) {
	const key = "0f5297b6f0114171e9de547801b1e8bb929fe1d091e63c6377a392ec1baa3d0b"
	s, err := NewFromHexKey(key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := "vim vim vim"

	ciphertext := s.Encrypt([]byte(plaintext))

	ok, b := s.Decrypt(ciphertext)
	if !ok {
		t.Fatal("failed to decrypt a message")
	}
	got := string(b)

	if got != plaintext {
		t.Errorf("Decrypt(Encrypt(%q)) = %q, want %q", plaintext, got, plaintext)
	}
}

func ExampleEncrypt() {
	const key = "0f5297b6f0114171e9de547801b1e8bb929fe1d091e63c6377a392ec1baa3d0b"
	s, err := NewFromHexKey(key)
	if err != nil {
		panic(err)
	}
	plaintext := "vim vim vim"

	// Encrypt
	ciphertext := s.Encrypt([]byte(plaintext))

	// Decrypt
	ok, b := s.Decrypt(ciphertext)
	if !ok {
		panic(errors.New(("failed to decrypt a message")))
	}
	fmt.Printf("%s", b)
	// OUTPUT: vim vim vim
}
