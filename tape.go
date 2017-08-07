package repository

import (
	"archive/tar"
	"crypto/cipher"
	"crypto/rsa"
	"io"
	"log"
	"os"
)

// Key is the key necessary to unlock a tape.
type Key struct {
	Label      Label
	PublicKey  *rsa.PublicKey
	PrivateKey *rsa.PrivateKey
}

// TapeReader is the mechanism for reading from an encrypted tape.
type TapeReader struct {
	Key          Key
	tarReader    *tar.Reader
	cryptoReader *cipher.StreamReader
}

// TapeWriter is the mechanism for writing an encrypted tape
type TapeWriter struct {
	Key          Key
	tarWriter    *tar.Writer
	cryptoWriter io.Writer
}

// Seal completes writing the data and closes the repository
func (r *TapeWriter) Seal() error {
	if err := r.tarWriter.Flush(); err != nil {
		log.Printf("Repository#Seal - Failed to flush the tar writer.")
	}

	return nil
}

// AddFile adds data from a file to the tape.
func (r *TapeWriter) AddFile(filePath string) error {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		log.Printf("Repository#AddFile - Unable to stat file %s: %v", filePath, err)
		return err
	}

	header, err := tar.FileInfoHeader(fileInfo, filePath)
	if err != nil {
		log.Printf("Repository#AddFile - Unable create new info header for file %s: %v", filePath, err)
		return err
	}

	err = r.tarWriter.WriteHeader(header)
	if err != nil {
		log.Printf("Repository#AddFile - Unable to write header into file %s: %v", filePath, err)
		return err
	}

	infile, err := os.Open(filePath)
	if err != nil {
		log.Printf("Repository#AddFile - Unable to open input file %s: %v", filePath, err)
		return err
	}
	defer infile.Close()

	_, err = io.Copy(r.tarWriter, infile)
	if err != nil {
		log.Printf("Repository#AddFile - Failed to copy data from input file to tar writer %s: %v", filePath, err)
		return err
	}

	return nil
}

// NewTapeWriter creates a new tape writer.  Returns
// a writeable repository or nil and an error if there's an error.  The repository
// is conceptually a tape with a label and then the tape contents.  The label
// contains a random AES256 key and a random initialization vector for the AES
// algorithm.  A SHA256 signature is generated for the two values.  The two values are
// encrypted.  The complete label is considered the encrypted key, initialization
// vector and the unencrypted signature.
func NewTapeWriter(key Key, repoFile io.Writer) (*TapeWriter, error) {
	result := &TapeWriter{Key: key}
	var err error

	result.Key.Label, err = RandomLabel()
	if err != nil {
		return nil, NewError(err, "Unable to generate new, random label")
	}

	err = result.Key.Label.WriteLabel(repoFile, key.PublicKey, key.PrivateKey)
	if err != nil {
		return nil, NewError(err, "Unable to write label into output writer")
	}

	result.cryptoWriter, err = result.Key.Label.OpenWriter(repoFile)
	if err != nil {
		return nil, NewError(err, "Unable to open respository writer")
	}

	result.tarWriter = tar.NewWriter(result.cryptoWriter)

	return result, nil
}

// ExtractFile extracts a file from the repository
func (r *TapeReader) ExtractFile() error {
	header, err := r.tarReader.Next()
	if err == io.EOF {
		return err
	}
	if err != nil {
		log.Printf("Repository#ExtractFile - Failed to extract file from repository: %v", err)
		return err
	}

	file, err := os.OpenFile(header.Name, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Printf("Repository#ExtractFile - Failed to open file %s for writing: %v", header.Name, err)
		return err
	}

	_, err = io.Copy(file, r.tarReader)
	if err != nil {
		log.Printf("Repository#ExtractFile - Failed to extract data for file %s: %v", header.Name, err)
		return err
	}

	return nil
}

// OpenTape opens a tape for reading
func OpenTape(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, tape io.Reader) (*TapeReader, error) {
	result := &TapeReader{}
	result.Key.PrivateKey = privateKey
	result.Key.PublicKey = publicKey
	var err error

	result.Key.Label, err = ReadLabel(tape, privateKey, publicKey)
	if err != nil {
		return nil, NewError(err, "Unable to read respository label")
	}

	cryptoReader, err := result.Key.Label.OpenReader(tape)
	if err != nil {
		return nil, NewError(err, "Unable to open a new crypto reader")
	}

	result.tarReader = tar.NewReader(cryptoReader)
	return result, nil
}
