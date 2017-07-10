package main

import (
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
	"github.com/darcinc/repository/commands"
)

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

func packRepository(archive, files, pubKeyName, privKeyName string) {
	parts := strings.Split(files, ",")
	if len(parts) < 1 {
		log.Printf("At least one file must be specified when create a repository")
		return
	}

	publicKey, err := readPublicKeyFromFile(pubKeyName)
	if err != nil {
		log.Fatalf("Failed to read public key from file: %v", err)
	}

	privateKey, err := readPrivateKeyFromFile(privKeyName)
	if err != nil {
		log.Fatalf("Failed to read public key from file: %v", err)
	}

	file, err := os.OpenFile(archive, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("Failed to open archive %s: %v", archive, err)
	}

	repo, err := repository.CreateRepository(publicKey, privateKey, file)
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

func unpackRepository(archive, privKeyName, pubKeyName string) {
	privateKey, err := readPrivateKeyFromFile(privKeyName)
	if err != nil {
		log.Fatalf("Failed to read private key %s from file: %v", privKeyName, err)
	}

	publicKey, err := readPublicKeyFromFile(pubKeyName)
	if err != nil {
		log.Fatalf("Failed to read public key %s from file: %v", pubKeyName, err)
	}

	file, err := os.Open(archive)
	if err != nil {
		log.Fatalf("Failed to open archive %s: %v", archive, err)
	}
	defer file.Close()

	repo, err := repository.OpenRepository(privateKey, publicKey, file)
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
}

func about() {
	flag.Usage()
}

func validateArguments(action, archive, files, publicKey, privateKey, keyName string) bool {
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

func main() {
	var (
		action, archive, files, publicKey, privateKey, keyName string
		cipherStrength                                         int
	)
	flag.StringVar(&action, "action", "about", "What to do (pack, list, unpack, create-keys, about)")
	flag.StringVar(&archive, "archive", "", "The name of the archive (required for pack, list, and unpack)")
	flag.StringVar(&files, "files", "", "Comma separated list of files (required for pack)")
	flag.StringVar(&publicKey, "publicKey", "", "Public key to use for encryption (required for pack)")
	flag.StringVar(&privateKey, "privateKey", "", "Private key to use for signing or decryption (required for pack and unpack)")
	flag.StringVar(&keyName, "keyName", "", "The name of the key (required for create key)")
	flag.IntVar(&cipherStrength, "bits", 4096, "The number of bits for the RSA key")
	flag.Parse()

	if !validateArguments(action, archive, files, privateKey, publicKey, keyName) {
		log.Printf("Unable to continue")
		about()
		return
	}

	switch action {
	case "pack":
		packRepository(archive, files, publicKey, privateKey)
	case "list":
		listContents(archive)
	case "unpack":
		unpackRepository(archive, publicKey, privateKey)
	case "create-keys":
		commands.CreateKeys(keyName, cipherStrength)
	case "about":
		about()
	}
}
