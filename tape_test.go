package repository

import (
	"bytes"
	"fmt"
	"log"
	"os"
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

func setupFs() afero.Fs {
	fs := afero.NewMemMapFs()

	if err := fs.MkdirAll("/data/db/files", 0755); err != nil {
		panic(err)
	}

	if err := fs.MkdirAll("/data/config", 0755); err != nil {
		panic(err)
	}

	if err := fs.MkdirAll("/backups", 0700); err != nil {
		panic(err)
	}

	if file, err := fs.OpenFile("/data/db/files/db1.dat", os.O_CREATE|os.O_WRONLY, 0666); err != nil {
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

	if file, err := fs.OpenFile("/data/db/files/db2.dat", os.O_CREATE|os.O_WRONLY, 0666); err != nil {
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

func createSimpleTape(fs afero.Fs) afero.Fs {
	backFile, err := fs.OpenFile("/backups/bk1.bak", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		panic(fmt.Sprintf("Failed to open backup file: %v", err))
	}

	tape, err := NewTapeWriter(tapeKey, backFile)
	if err != nil {
		panic(fmt.Sprintf("Failed to create new tape: %v", err))
	}

	tape.AddFile(fs, "/data/db/files/db1.dat")
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
	backFile, err := fs.OpenFile("/backups/bk1.bak", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open backup file: %v", err)
	}

	tape, err := NewTapeWriter(tapeKey, backFile)
	if err != nil {
		t.Fatalf("Failed to create new tape: %v", err)
	}

	tape.AddFile(fs, "/data/db/files/db1.dat")
	backFile.Close()

	fileinfo, err := fs.Stat("/backups/bk1.bak")
	if err != nil {
		t.Fatalf("Failed to stat backup file: %v", err)
	}

	if fileinfo.Size() < 1024*1024 {
		t.Errorf("Expected at least 1MB in size but got: %d", fileinfo.Size())
	}

	file, err := fs.Open("/backups/bk1.bak")
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
	createSimpleTape(fs)

	file, err := fs.Open("/backups/bk1.bak")
	if err != nil {
		t.Fatalf("Unable to open backup file: %v", err)
	}

	tr, err := OpenTape(tapeKey.PrivateKey, tapeKey.PublicKey, file)
	if err != nil {
		t.Fatalf("Unable open tape for reading")
	}

	fs.Remove("/data/db/files/db1.dat")

	err = tr.ExtractFile(fs)
	if err != nil {
		t.Fatalf("Failed to extract file: %v", err)
	}

	fileinfo, err := fs.Stat("/data/db/files/db1.dat")
	if err != nil {
		t.Fatalf("Failed to get file info: %v", err)
	}

	if fileinfo.Size() < 1024*1024 {
		t.Errorf("Expected file size to be at last 1MB but got %d instead", fileinfo.Size())
	}
}
