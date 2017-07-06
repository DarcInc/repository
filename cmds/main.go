package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

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

func packRepository(archive, files, keyName string) {
	parts := strings.Split(files, ",")
	if len(parts) < 1 {
		log.Printf("At least one file must be specified when create a repository")
		return
	}

	publicKey, err := readPublicKeyFromFile(keyName)
	if err != nil {
		log.Fatalf("Failed to read public key from file: %v", err)
	}

	repo, err := repository.CreateRepository(archive, publicKey)
	if err != nil {
		log.Fatalf("Failed to create repository %s: %v", archive, err)
	}

	for _, filepath := range parts {
		if err = repo.AddFile(filepath); err != nil {
			log.Printf("Failed to add file %s to repository: %v", filepath, err)
		}
	}

	if err = repo.Seal(); err != nil {
		log.Fatalf("Failed to seal %s repo: %v", archive, err)
	}
}

func listContents(archive string) {

}

func unpackRepository(archive, keyname string) {
	privateKey, err := readPrivateKeyFromFile(keyname)
	if err != nil {
		log.Fatalf("Failed to read private key %s from file: %v", keyname, err)
	}

	repo, err := repository.OpenRepository(archive, privateKey)
	if err != nil {
		log.Fatalf("Failed to open repository %s: %v", archive, err)
	}

	for err = nil; err == nil; {
		err = repo.ExtractFile()
		if err != nil {
			if err != io.EOF {
				log.Fatalf("Failed to extract file: %v", err)
			} else {
				break
			}
		}
	}

	if err = repo.Close(); err != nil {
		log.Fatalf("Failed to close file: %v", err)
	}
}

func createKeys(keyName string) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate keys %s: %v", keyName, err)
	}

	if err = writeKeyPairToFile(privateKey, keyName); err != nil {
		log.Fatalf("Failed to write keys to file: %v", err)
	}
}

func about() {
	flag.Usage()
}

func validateArguments(action, archive, files, keyName string) bool {
	result := true
	switch action {
	case "pack":
		if files == "" {
			log.Printf("Packing an archive requires a list of files")
			result = false
		}
		if keyName == "" {
			log.Printf("Packing an archive requires a key name")
			result = false
		}
	case "list":
		if archive == "" {
			log.Printf("When listing contents you must specify an archive")
			result = false
		}
	case "unpack":
		if archive == "" {
			log.Printf("When unpacking contents you must specify an archive")
			result = false
		}
		if keyName == "" {
			log.Printf("When unpacking contents you must specify a key name")
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

func main() {
	var (
		action, archive, files, keyName string
	)
	flag.StringVar(&action, "action", "about", "What to do (pack, list, unpack, create-keys, about)")
	flag.StringVar(&archive, "archive", "", "The name of the archive (required for pack, list, and unpack)")
	flag.StringVar(&files, "files", "", "Comma separated list of files (required for pack)")
	flag.StringVar(&keyName, "keyName", "", "Public key to use for encryption (required for pack)")

	flag.Parse()

	if !validateArguments(action, archive, files, keyName) {
		log.Printf("Unable to continue")
		about()
		return
	}

	switch action {
	case "pack":
		packRepository(archive, files, keyName)
	case "list":
		listContents(archive)
	case "unpack":
		unpackRepository(archive, keyName)
	case "create-keys":
		createKeys(keyName)
	case "about":
		about()
	}
}
