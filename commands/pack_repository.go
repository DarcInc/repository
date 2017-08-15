package commands

import (
	"log"
	"os"
	"strings"

	"github.com/darcinc/afero"
	"github.com/darcinc/repository"
)

// PackRepository packages a repository
func PackRepository(fs afero.Fs, args map[string]string) {
	parts := strings.Split(args["files"], ",")
	if len(parts) == 1 && parts[0] == "" && args["directory"] == "" {
		panic("At least one file or directory must be specified when creating a repository")
	}

	privateKey, publicKey, err := readKeysFromKeystore(fs, args["keystore"], args["privkey"], args["pubkey"])
	if err != nil {
		log.Fatalf("Failed to find privte or public key: %v", err)
	}

	file, err := fs.OpenFile(args["archive"], os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("Failed to open archive %s: %v", args["archive"], err)
	}
	defer file.Close()

	key := repository.Key{PublicKey: publicKey, PrivateKey: privateKey}
	repo, err := repository.NewTapeWriter(key, file)
	if err != nil {
		log.Fatalf("Failed to create repository %s: %v", args["archive"], err)
	}

	if len(parts) >= 1 && parts[0] != "" {
		for _, filepath := range parts {
			if err = repo.AddFile(fs, filepath); err != nil {
				log.Printf("Failed to add file %s to repository: %v", filepath, err)
			}
		}
	} else {
		repo.AddDirectory(fs, args["directory"])
	}
}
