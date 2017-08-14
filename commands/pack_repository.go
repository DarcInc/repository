package commands

import (
	"log"
	"os"
	"strings"

	"github.com/darcinc/afero"
	"github.com/darcinc/repository"
)

// PackRepository packages a repository
func PackRepository(fs afero.Fs, archive, files, keystoreName, pubKeyName, privKeyName string) {
	parts := strings.Split(files, ",")
	if len(parts) < 1 {
		log.Printf("At least one file must be specified when creating a repository")
		return
	}

	privateKey, publicKey, err := readKeysFromKeystore(fs, keystoreName, privKeyName, pubKeyName)
	if err != nil {
		log.Fatalf("Failed to find privte or public key: %v", err)
	}

	file, err := fs.OpenFile(archive, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("Failed to open archive %s: %v", archive, err)
	}
	defer file.Close()

	key := repository.Key{PublicKey: publicKey, PrivateKey: privateKey}
	repo, err := repository.NewTapeWriter(key, file)
	if err != nil {
		log.Fatalf("Failed to create repository %s: %v", archive, err)
	}

	for _, filepath := range parts {
		if err = repo.AddFile(fs, filepath); err != nil {
			log.Printf("Failed to add file %s to repository: %v", filepath, err)
		}
	}
}
