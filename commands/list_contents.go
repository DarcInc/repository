package commands

import (
	"io"
	"log"

	"github.com/darcinc/repository"

	"github.com/darcinc/afero"
)

// ListContents lists the contents of an archive
func ListContents(fs afero.Fs, archive, keystore, pubkey, privkey string, output io.Writer) {

	file, err := fs.Open(archive)
	if err != nil {
		log.Fatalf("Failed to open archive: %v", err)
	}

	privateKey, publicKey, err := readKeysFromKeystore(fs, keystore, pubkey, privkey)
	if err != nil {
		log.Fatalf("Failed to read keys from keystore: %v", err)
	}

	tr, err := repository.OpenTape(privateKey, publicKey, file)
	if err != nil {
		log.Fatalf("Failed to open tape: %v", err)
	}

	contents, err := tr.Contents()
	if err != nil {
		log.Fatalf("Failed to read tape contents: %v", err)
	}

	for _, c := range contents {
		output.Write([]byte(c))
		output.Write([]byte("\n"))
	}
}
