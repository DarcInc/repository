package repository

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

var (
	testAes  = []byte("AESKEY256-32-Character1234567890")
	testIv   = []byte("1234567890123456")
	testKey  = generateTestKey(1024)
	shortKey = generateTestKey(1024)
	medKey   = generateTestKey(2048)
	longKey  = generateTestKey(4096)
	keys     = []*rsa.PrivateKey{shortKey, medKey, longKey}
)

func generateTestKey(bits int) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate random key with %d bits", bits))
	}

	return key
}
