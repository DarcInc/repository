package commands

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"strings"

	"github.com/darcinc/repository"

	"github.com/darcinc/afero"
)

// ImportKey imports a key into the repository with the given key name.  The
// PEM encoded key is read from the io.Reader.  The function then saves the
// keystore with the new key.
func ImportKey(fs afero.Fs, repoName, keyName, fileName string) error {
	file, err := fs.Open(fileName)
	if err != nil {
		return err
	}
	defer file.Close()
	return importKey(fs, repoName, keyName, file)
}

func importKey(fs afero.Fs, repoName, keyName string, from io.Reader) error {
	filename := repository.KeystorePath(repoName)
	file, err := fs.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	keystore, err := repository.OpenKeystore(file)
	if err != nil {
		return err
	}

	buffer := new(bytes.Buffer)
	io.Copy(buffer, from)
	block, _ := pem.Decode(buffer.Bytes())

	if strings.Contains(block.Type, "PRIVATE") {
		pk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		keystore.AddPrivateKey(keyName, pk)
	} else {
		pk, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}
		pubkey := pk.(*rsa.PublicKey)
		keystore.AddPublicKey(keyName, pubkey)
	}

	file, err = fs.OpenFile(filename, os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	return keystore.Save(file)
}
