package commands

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"regexp"
	"testing"

	"github.com/darcinc/afero"
	"github.com/darcinc/repository"
)

func addTestKeys(fs afero.Fs, t *testing.T) {
	keysName := repository.NamedKeystoreFile("foo")
	file, err := fs.OpenFile(keysName, os.O_RDONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}

	keys, err := repository.OpenKeystore(file)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()

	priv1, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	keys.AddPrivateKey("test1", priv1)
	priv2, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	keys.AddPublicKey("test2", &priv2.PublicKey)

	file, err = fs.OpenFile(keysName, os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	err = keys.Save(file)
	if err != nil {
		t.Fatal(err)
	}
}

func TestListKeys(t *testing.T) {
	fs := createFSWithKeystore(t)
	addTestKeys(fs, t)
	bf := new(bytes.Buffer)

	listKeys(fs, "foo", bf)
	re1 := regexp.MustCompile("Private Keys.*\\s+test1")
	re2 := regexp.MustCompile("Public Keys.*\\s+test2")

	if !re1.Match(bf.Bytes()) {
		t.Error("Failed to find private keys in list")
	}

	if !re2.Match(bf.Bytes()) {
		t.Error("Failed to find public keys in list")
	}
}

func TestListKeysNoKeystore(t *testing.T) {
	fs := createFSWithKeystore(t)
	bf := new(bytes.Buffer)

	listKeys(fs, "bar", bf)

	re1 := regexp.MustCompile("No such repo.*bar")

	if !re1.Match(bf.Bytes()) {
		t.Error("No not found message")
	}
}
