package repository

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
)

var (
	testAes = []byte("AESKEY256-32-Character1234567890")
	testIv  = []byte("1234567890123456")
	testKey = generateTestKey(1024)
)

func generateTestKey(bits int) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate random key with %d bits", bits))
	}

	return key
}

func TestKeylength(t *testing.T) {
	repo := &Repository{privateKey: testKey}
	if repo.keylength() != 128 {
		t.Errorf("Expected key length of 128 but got %d", repo.keylength())
	}

	repo = &Repository{publicKey: &testKey.PublicKey}
	if repo.keylength() != 128 {
		t.Errorf("Expected key length of 128 but got %d", repo.keylength())
	}
}

func TestWriteHeader(t *testing.T) {
	repo := &WriteRepository{}
	repo.AesKey = testAes
	repo.iv = testIv
	repo.publicKey = &testKey.PublicKey

	buffer := new(bytes.Buffer)
	repo.writeHeader(buffer)

	if len(buffer.Bytes()) != repo.keylength() {
		t.Errorf("Expected %d bytes but got %d", repo.keylength(), len(buffer.Bytes()))
	}
}

func TestWriteSignature(t *testing.T) {
	repo := &WriteRepository{}
	repo.AesKey = testAes
	repo.iv = testIv
	repo.privateKey = testKey
	repo.publicKey = &testKey.PublicKey

	buffer := new(bytes.Buffer)
	repo.writeSignature(buffer)

	if len(buffer.Bytes()) != repo.keylength() {
		t.Errorf("Expected %d bytes but got %d", repo.keylength(), len(buffer.Bytes()))
	}

}
