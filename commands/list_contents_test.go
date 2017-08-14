package commands

import (
	"bytes"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/darcinc/repository"
)

func TestListContents(t *testing.T) {
	fs := createFSWithKeystore(t)
	addTestKeys(fs, t)
	createTestData(fs)
	packTestRepository(fs)

	outf := new(bytes.Buffer)
	archive := filepath.Join(repository.HomeDir(), "archive1")

	ListContents(fs, archive, "foo", "test1", "test3", outf)

	re1 := regexp.MustCompile("data1\\.dat")
	re2 := regexp.MustCompile("data2\\.dat")

	if !re1.Match(outf.Bytes()) || !re2.Match(outf.Bytes()) {
		t.Error("Failed to find data files in the listing")
	}
}
