package commands

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
)

//CreateKeys builds a public and private key and saves them to a file
func CreateKeys(name string, cipherStrength int) {
	privateKey, err := rsa.GenerateKey(rand.Reader, cipherStrength)
	if err != nil {
		log.Fatalf("Failed to generate keys %s: %v", name, err)
	}

	if err = writeKeyPairToFile(privateKey, name); err != nil {
		log.Fatalf("Failed to write keys to file: %v", err)
	}
}
