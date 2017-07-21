package commands

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"os"
	"path/filepath"

	"github.com/darcinc/afero"
	"github.com/darcinc/repository"
)

//CreateKeys builds a public and private key and saves them to a file
func CreateKeys(fs afero.Fs, name, keyfile string, cipherStrength int) {
	if !filepath.IsAbs(keyfile) {
		keyfile = repository.NamedKeystoreFile(keyfile)
	}

	_, err := fs.Stat(keyfile)
	if err != nil {
		repository.CreateKeystore(fs, keyfile)
	}

	file, err := fs.Open(keyfile)
	if err != nil {
		log.Fatalf("Failed to open keystore file: %v", err)
	}

	keystore, err := repository.OpenKeystore(file)
	file.Close()

	privateKey, err := rsa.GenerateKey(rand.Reader, cipherStrength)
	if err != nil {
		log.Fatalf("Failed to generate keys %s: %v", name, err)
	}

	keystore.AddPrivateKey(name, privateKey)
	file, err = fs.OpenFile(keyfile, os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	err = keystore.Save(file)
	if err != nil {
		panic(err)
	}
}
