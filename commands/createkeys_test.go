package commands

import (
	"os"
	"testing"

	"github.com/darcinc/afero"
	"github.com/darcinc/repository"
)

func createFSWithKeystore(t *testing.T) afero.Fs {
	fs := afero.NewMemMapFs()

	keystore, err := repository.CreateKeystore(fs, "foo")
	if err != nil {
		t.Fatal(err)
	}

	filepath := repository.NamedKeystoreFile("foo")
	file, err := fs.OpenFile(filepath, os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	err = keystore.Save(file)
	if err != nil {
		t.Fatal(err)
	}

	return fs
}

func TestCreateKeysInExistingKeystore(t *testing.T) {
	fs := createFSWithKeystore(t)
	CreateKeys(fs, "test", "foo", 2048)

	filepath := repository.NamedKeystoreFile("foo")
	file, err := fs.OpenFile(filepath, os.O_RDONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}

	keystore, err := repository.OpenKeystore(file)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := keystore.FindPrivateKey("test")
	if !ok {
		t.Error("Unable to find newly created key")
	}

	_, ok = keystore.FindPublicKey("test")
	if !ok {
		t.Error("Unable to find newly created public key")
	}
}

func TestCreateKeysInNewKeystore(t *testing.T) {
	fs := createFSWithKeystore(t)
	CreateKeys(fs, "test2", "foo2", 2048)

	filepath := repository.NamedKeystoreFile("foo2")
	file, err := fs.OpenFile(filepath, os.O_RDONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}

	keystore, err := repository.OpenKeystore(file)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := keystore.FindPrivateKey("test2")
	if !ok {
		t.Errorf("Failed to find private key")
	}
}
