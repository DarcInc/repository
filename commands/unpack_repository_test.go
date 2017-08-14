package commands

import (
	"path/filepath"
	"testing"

	"github.com/darcinc/repository"
)

func TestUnpackRepository(t *testing.T) {
	fs := createFSWithKeystore(t)
	addTestKeys(fs, t)
	createTestData(fs)
	packTestRepository(fs)

	if err := fs.Remove(filepath.Join(repository.HomeDir(), "data1.dat")); err != nil {
		t.Fatalf("Failed to remove data file: %v", err)
	}
	if err := fs.Remove(filepath.Join(repository.HomeDir(), "data2.dat")); err != nil {
		t.Fatalf("Failed to remove data file: %v", err)
	}

	UnpackRepository(fs, filepath.Join(repository.HomeDir(), "archive1"), "foo", "test1", "test3")

	if _, err := fs.Stat(filepath.Join(repository.HomeDir(), "data1.dat")); err != nil {
		t.Errorf("Failed to find file: %v", err)
	}

	if _, err := fs.Stat(filepath.Join(repository.HomeDir(), "data2.dat")); err != nil {
		t.Errorf("Failed to find file: %v", err)
	}
}
