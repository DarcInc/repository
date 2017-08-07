package repository

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
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

func TestCreateRepository(t *testing.T) {
	buffer := new(bytes.Buffer)
	_, err := CreateRepository(&testKey.PublicKey, testKey, buffer)
	if err != nil {
		log.Fatalf("Unable to write out repository: %v", err)
	}

	reader := bytes.NewReader(buffer.Bytes())
	_, err = OpenRepository(testKey, &testKey.PublicKey, reader)
	if err != nil {
		log.Fatalf("Failed to open repository: %v", err)
	}
}
