package commands

import "testing"
import "github.com/darcinc/repository"

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
