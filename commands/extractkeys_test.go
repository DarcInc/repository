package commands

import (
	"bytes"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/darcinc/repository"
)

func TestExtractPrivateKeys(t *testing.T) {
	fs := createFSWithKeystore(t)
	addTestKeys(fs, t)

	bfr := new(bytes.Buffer)

	extractKeys(fs, "foo", "test1", bfr)

	re1 := regexp.MustCompile("RSA PRIVATE KEY")
	re2 := regexp.MustCompile("RSA PUBLIC KEY")

	if !re1.Match(bfr.Bytes()) {
		t.Error("Did not find private key")
	}

	if !re2.Match(bfr.Bytes()) {
		t.Error("Did not find public key")
	}
}

func TestExtractPublicKeys(t *testing.T) {
	fs := createFSWithKeystore(t)
	addTestKeys(fs, t)

	bfr := new(bytes.Buffer)
	extractKeys(fs, "foo", "test2", bfr)

	re1 := regexp.MustCompile("RSA PUBLIC KEY")

	if !re1.Match(bfr.Bytes()) {
		t.Error("Did not match public key")
	}
}

func TestExtractKeysToFile(t *testing.T) {
	fs := createFSWithKeystore(t)
	addTestKeys(fs, t)

	exportFile := filepath.Join(repository.HomeDir(), "somefile.txt")
	ExtractKeys(fs, "foo", "test2", exportFile)

	if _, err := fs.Stat(exportFile); err != nil {
		t.Errorf("Failed to export file to somefile.txt: %v", err)
	}
}

func TestExtractKeysBadKeystoreName(t *testing.T) {
	fs := createFSWithKeystore(t)
	addTestKeys(fs, t)

	defer func() {
		recover()
	}()

	bfr := new(bytes.Buffer)
	extractKeys(fs, "baz", "test2", bfr)
	t.Error("Should have failed with bad keystore name")
}

func TestExtractKeysBadKeystoreFormat(t *testing.T) {
	fs := createFSWithKeystore(t)
	addTestKeys(fs, t)

	f, err := fs.Create(repository.KeystorePath("baz"))
	if err != nil {
		t.Fatalf("Error creating bad repo file: %v", err)
	}
	f.Close()

	defer func() {
		recover()
	}()

	bfr := new(bytes.Buffer)
	extractKeys(fs, "baz", "test2", bfr)
	t.Error("Should have failed with bad keystore name")
}
