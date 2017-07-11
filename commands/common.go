package commands

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

// ValidateArguments checks to see that all arguments are correct.
func ValidateArguments(action, archive, files, publicKey, privateKey, keyName string) bool {
	result := true
	switch action {
	case "pack":
		if files == "" {
			log.Printf("Packing an archive requires a list of files")
			result = false
		}
		if publicKey == "" {
			log.Printf("Packing an archive requires a key name")
			result = false
		}
		if privateKey == "" {
			log.Printf("Packing an archive requries a private key name")
			result = false
		}
	case "unpack":
		if archive == "" {
			log.Printf("When unpacking contents you must specify an archive")
			result = false
		}
		if privateKey == "" {
			log.Printf("When unpacking contents you must specify a key name")
			result = false
		}
		if publicKey == "" {
			log.Printf("When unpacking contetns you must specify a public key")
			result = false
		}
	case "create-keys":
		if keyName == "" {
			log.Printf("When creating keys you must specify a keyname")
			result = false
		}
	}
	return result
}

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

func readPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(fmt.Sprintf("%s.key", filename))
	if err != nil {
		log.Printf("Failed to read private key %s.key: %v", filename, err)
		return nil, err
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(data)
	if err != nil {
		log.Printf("Failed to parse private key: %v", err)
		return nil, err
	}

	return privateKey, nil
}

func readPublicKeyFromFile(filename string) (*rsa.PublicKey, error) {
	data, err := ioutil.ReadFile(fmt.Sprintf("%s-pub.key", filename))
	if err != nil {
		log.Printf("Failed to read public key %s-pub.key from file: %v", filename, err)
		return nil, err
	}

	publicKey, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		log.Printf("Failed to parse public key: %v", err)
		return nil, err
	}

	rsaPublicKey := publicKey.(*rsa.PublicKey)
	return rsaPublicKey, nil
}
