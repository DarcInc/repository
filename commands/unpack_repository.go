package commands

import (
	"io"
	"log"
	"os"

	"github.com/darcinc/repository"
)

// UnpackRepository unpacks a repository
func UnpackRepository(archive, privKeyName, pubKeyName string) {
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
