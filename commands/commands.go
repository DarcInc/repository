package commands

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

func writeKeyPairToFile(key *rsa.PrivateKey, filename string) error {
	privateKeyName := fmt.Sprintf("%s.key", filename)
	publicKeyName := fmt.Sprintf("%s-pub.key", filename)

	privateKeyData := x509.MarshalPKCS1PrivateKey(key)
	publicKeyData, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		log.Printf("Failed to marshal public key: %v", err)
		return err
	}

	err = ioutil.WriteFile(privateKeyName, privateKeyData, 0644)
	if err != nil {
		log.Printf("Failed to write private key: %s: %v", privateKeyName, err)
		return err
	}

	ioutil.WriteFile(publicKeyName, publicKeyData, 0644)
	if err != nil {
		log.Printf("Failed to write public key: %s: %v", publicKeyName, err)
		os.Remove(privateKeyName)
		return err
	}

	return nil
}

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
