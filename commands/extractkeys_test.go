package commands

import "testing"
import "bytes"
import "regexp"

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
