package main

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/darcinc/repository"
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

func temp() {
	publicKey, err := readPublicKeyFromFile("keyname")
	if err != nil {
		log.Fatalf("Failed to read public key from file: %v", err)
	}

	repo, err := repository.CreateRepository("myrepo.repo", publicKey)
	if err != nil {
		log.Fatalf("Failed to create repository: %v", err)
	}

	if err = repo.AddFile("cluster.pdf"); err != nil {
		log.Fatalf("Failed to add file to repository: %v", err)
	}

	if err = repo.Seal(); err != nil {
		log.Fatalf("Failed to seal repo: %v", err)
	}
}

func main() {
	privateKey, err := readPrivateKeyFromFile("keyname")
	if err != nil {
		log.Fatalf("Failed to read private key from file: %v", err)
	}

	repo, err := repository.OpenRepository("myrepo.repo", privateKey)
	if err != nil {
		log.Fatalf("Failed to open repository: %v", err)
	}

	if err = repo.ExtractFile(); err != nil {
		log.Fatalf("Failed to extract file: %v", err)
	}

	if err = repo.Close(); err != nil {
		log.Fatalf("Failed to close file: %v", err)
	}
}
