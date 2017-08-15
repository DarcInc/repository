package commands

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/darcinc/afero"
	"github.com/darcinc/repository"
)

func createTestData(fs afero.Fs) {
	home := repository.HomeDir()
	datafile, err := fs.OpenFile(filepath.Join(home, "data1.dat"), os.O_WRONLY|os.O_CREATE, 0660)
	if err != nil {
		panic(err)
	}
	defer datafile.Close()
	datafile.Write([]byte("Hello World"))

	datafile, err = fs.OpenFile(filepath.Join(home, "data2.dat"), os.O_WRONLY|os.O_CREATE, 0660)
	if err != nil {
		panic(err)
	}
	defer datafile.Close()
	datafile.Write([]byte("Goodbye World"))

}

func packTestRepository(fs afero.Fs) {
	files := []string{
		filepath.Join(repository.HomeDir(), "data1.dat"),
		filepath.Join(repository.HomeDir(), "data2.dat"),
	}
	archive := filepath.Join(repository.HomeDir(), "archive1")

	args := make(map[string]string)
	args["archive"] = archive
	args["files"] = strings.Join(files, ",")
	args["keystore"] = "foo"
	args["pubkey"] = "test1"
	args["privkey"] = "test3"

	PackRepository(fs, args)
}

func packTestRepositoryDirectory(fs afero.Fs) {
	archive := filepath.Join(repository.HomeDir(), "archive1")

	args := make(map[string]string)
	args["archive"] = archive
	args["directory"] = repository.HomeDir()
	args["keystore"] = "foo"
	args["pubkey"] = "test1"
	args["privkey"] = "test3"

	PackRepository(fs, args)
}

func TestPackFilesRepository(t *testing.T) {
	fs := createFSWithKeystore(t)
	addTestKeys(fs, t)
	createTestData(fs)
	packTestRepository(fs)

	archive := filepath.Join(repository.HomeDir(), "archive1")

	if fileinfo, err := fs.Stat(archive); err != nil {
		t.Errorf("Failed to find archive: %v", err)
	} else {
		if fileinfo.Size() < 23 {
			t.Errorf("Invalid file size")
		}

		file, err := fs.Open(archive)
		if err != nil {
			t.Fatalf("Failed to open archive: %v", err)
		}
		defer file.Close()

		s := bufio.NewScanner(file)
		s.Split(bufio.ScanWords)
		for s.Scan() {
			if s.Text() == "World" || s.Text() == "Goodbye" || s.Text() == "Hello" {
				t.Errorf("Found cleartext in archive")
			}
		}
	}
}

func TestPackDirectoryRepository(t *testing.T) {
	fs := createFSWithKeystore(t)
	addTestKeys(fs, t)
	createTestData(fs)
	packTestRepositoryDirectory(fs)

	archive := filepath.Join(repository.HomeDir(), "archive1")

	if fileinfo, err := fs.Stat(archive); err != nil {
		t.Errorf("Failed to find archive: %v", err)
	} else {
		if fileinfo.Size() < 23 {
			t.Errorf("Invalid file size")
		}

		file, err := fs.Open(archive)
		if err != nil {
			t.Fatalf("Failed to open archive: %v", err)
		}
		defer file.Close()

		s := bufio.NewScanner(file)
		s.Split(bufio.ScanWords)
		for s.Scan() {
			if s.Text() == "World" || s.Text() == "Goodbye" || s.Text() == "Hello" {
				t.Errorf("Found cleartext in archive")
			}
		}
	}
}
