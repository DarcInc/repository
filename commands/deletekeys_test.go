package commands

import (
	"path/filepath"
	"testing"

	"github.com/darcinc/repository"
)

func TestDeleteKeys(t *testing.T) {
	fs := createFSWithKeystore(t)
	addTestKeys(fs, t)

	DeleteKeys(fs, "foo", "test1")

	filename := repository.NamedKeystoreFile("foo")
	file, err := fs.Open(filename)
	if err != nil {
		t.Fatal(err)
	}

	keystore, err := repository.OpenKeystore(file)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := keystore.FindPrivateKey("test1")
	if ok {
		t.Error("Key should have been deleted")
	}
}

func TestInvalidKeystorePanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {

		}
	}()

	fs := createFSWithKeystore(t)
	DeleteKeys(fs, "bar", "test1")
	t.Error("Failed to panic with invalid keystore")
}

func TestBadKeystorePanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {

		}
	}()

	fs := createFSWithKeystore(t)
	f, err := fs.Create(filepath.Join(repository.HomeDir(), "bad.keys"))
	if err != nil {
		t.Fatalf("Unable to create bad input file")
	}
	f.Close()

	DeleteKeys(fs, filepath.Join(repository.HomeDir(), "bad.keys"), "test1")
	t.Error("Failed to panic with invalid keystore")
}
