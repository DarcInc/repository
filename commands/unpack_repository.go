package commands

import (
	"io"
	"log"

	"github.com/darcinc/afero"
	"github.com/darcinc/repository"
)

// UnpackRepository unpacks a repository
func UnpackRepository(fs afero.Fs, archive, keystore, privKeyName, pubKeyName string) {
	privateKey, publicKey, err := readKeysFromKeystore(fs, keystore, privKeyName, pubKeyName)
	if err != nil {
		log.Fatalf("Failed to find public or private keys: %v", err)
	}

	file, err := fs.Open(archive)
	if err != nil {
		log.Fatalf("Failed to open archive %s: %v", archive, err)
	}
	defer file.Close()

	repo, err := repository.OpenTape(privateKey, publicKey, file)
	if err != nil {
		log.Fatalf("Failed to open repository %s: %v", archive, err)
	}

	for err = nil; err == nil; {
		err = repo.ExtractFile(fs)
		if err != nil {
			if err != io.EOF {
				log.Fatalf("Failed to extract file: %v", err)
			} else {
				break
			}
		}
	}
}
