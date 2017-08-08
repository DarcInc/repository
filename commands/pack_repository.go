package commands

import (
	"log"
	"os"
	"strings"

	"github.com/darcinc/afero"
	"github.com/darcinc/repository"
)

// PackRepository packages a repository
func PackRepository(archive, files, pubKeyName, privKeyName string) {
	parts := strings.Split(files, ",")
	if len(parts) < 1 {
		log.Printf("At least one file must be specified when creating a repository")
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

	key := repository.Key{PublicKey: publicKey, PrivateKey: privateKey}
	repo, err := repository.NewTapeWriter(key, file)
	if err != nil {
		log.Fatalf("Failed to create repository %s: %v", archive, err)
	}

	fs := afero.NewOsFs()
	for _, filepath := range parts {
		if err = repo.AddFile(fs, filepath); err != nil {
			log.Printf("Failed to add file %s to repository: %v", filepath, err)
		}
	}
}
