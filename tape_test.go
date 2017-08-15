package repository

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/darcinc/afero"
)

var (
	tapeKey = Key{
		Label:      Label{AesKey: testAes, iv: testIv},
		PrivateKey: medKey,
		PublicKey:  &medKey.PublicKey,
	}
)

func pathFor(parts ...string) string {
	if runtime.GOOS == "windows" {
		parts = append([]string{"C:\\"}, parts...)
	} else {
		parts = append([]string{"/"}, parts...)
	}
	return filepath.Join(parts...)
}

func setupFs() afero.Fs {
	fs := afero.NewMemMapFs()

	if err := fs.MkdirAll(pathFor("data", "db", "files"), 0755); err != nil {
		panic(err)
	}

	if err := fs.MkdirAll(pathFor("data", "config"), 0755); err != nil {
		panic(err)
	}

	if err := fs.MkdirAll(pathFor("backups"), 0700); err != nil {
		panic(err)
	}

	if file, err := fs.OpenFile(pathFor("data", "db", "files", "db1.dat"), os.O_CREATE|os.O_WRONLY, 0666); err != nil {
		panic(err)
	} else {
		for i := 0; i < 128*1024; i++ {
			bytes := []byte{1, 2, 3, 4, 5, 6, 7, 8}
			if _, err := file.Write(bytes); err != nil {
				panic(err)
			}
		}
		file.Close()
	}

	if file, err := fs.OpenFile(pathFor("data", "db", "files", "db2.dat"), os.O_CREATE|os.O_WRONLY, 0666); err != nil {
		panic(err)
	} else {
		for i := 0; i < 64*1024; i++ {
			bytes := []byte("12345678")
			if _, err := file.Write(bytes); err != nil {
				panic(err)
			}
		}
		file.Close()
	}

	return fs
}

func createSimpleTape(fs afero.Fs, files []string) afero.Fs {
	backFile, err := fs.OpenFile(pathFor("backups", "bk1.bak"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		panic(fmt.Sprintf("Failed to open backup file: %v", err))
	}

	tape, err := NewTapeWriter(tapeKey, backFile)
	if err != nil {
		panic(fmt.Sprintf("Failed to create new tape: %v", err))
	}

	for _, f := range files {
		tape.AddFile(fs, f)
	}
	backFile.Close()

	return fs
}

func TestCreateTape(t *testing.T) {
	buffer := new(bytes.Buffer)
	_, err := NewTapeWriter(Key{PublicKey: &testKey.PublicKey, PrivateKey: testKey}, buffer)
	if err != nil {
		log.Fatalf("Unable to write out repository: %v", err)
	}

	reader := bytes.NewReader(buffer.Bytes())
	_, err = OpenTape(testKey, &testKey.PublicKey, reader)
	if err != nil {
		log.Fatalf("Failed to open repository: %v", err)
	}
}

func TestTapeCreation(t *testing.T) {
	fs := setupFs()
	backFile, err := fs.OpenFile(pathFor("backups", "bk1.bak"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open backup file: %v", err)
	}

	tape, err := NewTapeWriter(tapeKey, backFile)
	if err != nil {
		t.Fatalf("Failed to create new tape: %v", err)
	}

	tape.AddFile(fs, pathFor("data", "db", "files", "db1.dat"))
	backFile.Close()

	fileinfo, err := fs.Stat(pathFor("backups", "bk1.bak"))
	if err != nil {
		t.Fatalf("Failed to stat backup file: %v", err)
	}

	if fileinfo.Size() < 1024*1024 {
		t.Errorf("Expected at least 1MB in size but got: %d", fileinfo.Size())
	}

	file, err := fs.Open(pathFor("backups", "bk1.bak"))
	if err != nil {
		t.Fatalf("Unable to open backup file: %v", err)
	}
	defer file.Close()

	_, err = file.Seek(4096, 0)
	if err != nil {
		t.Fatalf("Unabel to seek in file: %v", err)
	}

	temp := make([]byte, 16)
	_, err = file.Read(temp)
	if err != nil {
		t.Fatalf("Failed to read data from file: %v", err)
	}

	for idx := range temp {
		if temp[idx] == 1 && temp[idx+1] == 2 && temp[idx+2] == 3 {
			t.Errorf("Possible failure - It's unlikely to get three values in a row")
		}
	}
}

func TestSimpleTapeReading(t *testing.T) {
	fs := setupFs()
	createSimpleTape(fs, []string{pathFor("data", "db", "files", "db1.dat")})

	file, err := fs.Open(pathFor("backups", "bk1.bak"))
	if err != nil {
		t.Fatalf("Unable to open backup file: %v", err)
	}

	tr, err := OpenTape(tapeKey.PrivateKey, tapeKey.PublicKey, file)
	if err != nil {
		t.Fatalf("Unable open tape for reading")
	}

	fs.Remove(pathFor("data", "db", "files", "db1.dat"))

	err = tr.ExtractFile(fs)
	if err != nil {
		t.Fatalf("Failed to extract file: %v", err)
	}

	fileinfo, err := fs.Stat(pathFor("data", "db", "files", "db1.dat"))
	if err != nil {
		t.Fatalf("Failed to get file info: %v", err)
	}

	if fileinfo.Size() < 1024*1024 {
		t.Errorf("Expected file size to be at last 1MB but got %d instead", fileinfo.Size())
	}
}

func TestMultipleFiles(t *testing.T) {
	fs := setupFs()
	files := []string{
		pathFor("data", "db", "files", "db1.dat"),
		pathFor("data", "db", "files", "db2.dat"),
	}
	createSimpleTape(fs, files)

	for _, f := range files {
		if err := fs.Remove(f); err != nil {
			t.Fatalf("Failed to remove file: %s", f)
		}
	}

	file, err := fs.Open(pathFor("backups", "bk1.bak"))
	if err != nil {
		t.Fatalf("Unable to open backup file: %v", err)
	}

	tr, err := OpenTape(tapeKey.PrivateKey, tapeKey.PublicKey, file)
	if err != nil {
		t.Fatalf("Unable open tape for reading")
	}

	err = tr.ExtractFile(fs)
	if err != nil {
		t.Fatalf("Failed to extract file: %v", err)
	}

	err = tr.ExtractFile(fs)
	if err != nil {
		t.Fatalf("Failed to extract file: %v", err)
	}

	for _, f := range files {
		_, err := fs.Stat(f)
		if err != nil {
			t.Fatalf("Failed to get file info: %v", err)
		}
	}
}

func TestListContents(t *testing.T) {
	fs := setupFs()
	files := []string{
		pathFor("data", "db", "files", "db1.dat"),
		pathFor("data", "db", "files", "db2.dat"),
	}
	createSimpleTape(fs, files)

	file, err := fs.Open(pathFor("backups", "bk1.bak"))
	if err != nil {
		t.Fatalf("Unable to open backup file: %v", err)
	}

	tr, err := OpenTape(tapeKey.PrivateKey, tapeKey.PublicKey, file)
	if err != nil {
		t.Fatalf("Unable open tape for reading")
	}

	entries, err := tr.Contents()
	if err != nil {
		t.Fatalf("Unable to read contents")
	}

	if len(entries) != 2 {
		t.Errorf("Expected 2 entries but got %d", len(entries))
	}

	for e := range files {
		if files[e] != entries[e] {
			t.Errorf("Expected %s but got %s", files[e], entries[e])
		}
	}
}

func TestAddDirectory(t *testing.T) {
	fs := setupFs()
	file, err := fs.OpenFile(pathFor("backups", "bk1.bak"), os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		t.Fatalf("Failed to open backup file: %v", err)
	}

	tape, err := NewTapeWriter(tapeKey, file)
	if err != nil {
		t.Fatalf("Unable to open tape for writing: %v", err)
	}

	tape.AddDirectory(fs, pathFor("data", "db"))
	file.Close()

	fs.Remove(pathFor("data", "db", "files", "db1.dat"))
	fs.Remove(pathFor("data", "db", "files", "db2.dat"))

	file, err = fs.Open(pathFor("backups", "bk1.bak"))
	if err != nil {
		t.Fatalf("Unable to open backup tape file: %v", err)
	}
	defer file.Close()

	tr, err := OpenTape(tapeKey.PrivateKey, tapeKey.PublicKey, file)
	if err != nil {
		t.Fatalf("Unable to open backup tape: %v", err)
	}

	if err = tr.ExtractFile(fs); err != nil {
		t.Fatalf("Unable to extract file from archive: %v", err)
	}

	if err = tr.ExtractFile(fs); err != nil {
		t.Fatalf("Unable to extract file from archive: %v", err)
	}

	if _, err = fs.Stat(pathFor("data", "db", "files", "db1.dat")); err != nil {
		t.Errorf("Unable to find restored file: %v", err)
	}

	if _, err = fs.Stat(pathFor("data", "db", "files", "db2.dat")); err != nil {
		t.Errorf("Unable to find restored file: %v", err)
	}
}
