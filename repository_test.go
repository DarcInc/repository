package repository

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestKeylength(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("Failed to generate key for testing: %v", err)
	}

	repo := &Repository{privateKey: key}
	if repo.keylength() != 128 {
		t.Errorf("Expected key length of 128 but got %d", repo.keylength())
	}

	repo = &Repository{publicKey: &key.PublicKey}
	if repo.keylength() != 128 {
		t.Errorf("Expected key length of 128 but got %d", repo.keylength())
	}
}

func TestWriteHeader(t *testing.T) {
	repo := &WriteRepository{}
	repo.AesKey = []byte("AESKEY256-32-Character1234567890")
	repo.iv = []byte("1234567890123456")
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("Failed to generate key for testing: %v", err)
	}
	repo.publicKey = &key.PublicKey

	buffer := new(bytes.Buffer)
	repo.writeHeader(buffer)

	if len(buffer.Bytes()) != repo.keylength() {
		t.Errorf("Expected %d bytes but got %d", repo.keylength(), len(buffer.Bytes()))
	}
}
