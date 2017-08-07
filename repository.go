package repository

import (
	"archive/tar"
	"crypto/cipher"
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	"os"
)

// Repository is an encrypted bunch of stuff
type Repository struct {
	Label      Label
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

// ReadRepository is a repository opened for reading
type ReadRepository struct {
	Repository
	tarReader    *tar.Reader
	cryptoReader *cipher.StreamReader
}

// WriteRepository is a repository opened for writing
type WriteRepository struct {
	Repository
	tarWriter    *tar.Writer
	cryptoWriter io.Writer
}

// Error describes an error when reading, writing or creating repositories.
// It retains the original error and an error message to assist in debugging.
type Error struct {
	OriginalError error
	Message       string
}

// Error implements the error interface, returning the string representation
// of the error.
func (re *Error) Error() string {
	return fmt.Sprintf("%s: %v", re.Message, re.OriginalError)
}

// NewError is a convenience method for creating new repository
// errors from a message and original error.
func NewError(err error, message string) *Error {
	return &Error{
		OriginalError: err,
		Message:       message,
	}
}

func (r *Repository) keylength() int {
	if r.publicKey != nil {
		return len(r.publicKey.N.Bytes())
	}

	if r.privateKey != nil {
		return len(r.privateKey.N.Bytes())
	}

	return 0
}

// Seal completes writing the data and closes the repository
func (r *WriteRepository) Seal() error {
	if err := r.tarWriter.Flush(); err != nil {
		log.Printf("Repository#Seal - Failed to flush the tar writer.")
	}

	return nil
}

// AddFile adds data from a file
func (r *WriteRepository) AddFile(filePath string) error {
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

// CreateRepository creates a new repository in the given writer.  Returns
// a writeable repository or nil and an error if there's an error.  The repository
// is conceptually a tape with a label and then the tape contents.  The label
// contains a random AES256 key and a random initialization vector for the AES
// algorithm.  A SHA256 signature is generated for the two values.  The two values are
// encrypted.  The complete label is considered the encrypted key, initialization
// vector and the unencrypted signature.
//
// The public key is the key used for encryption.
// The private key is used for signatures.
// The writer is where they repoistory will be created.
func CreateRepository(key *rsa.PublicKey, privateKey *rsa.PrivateKey, repoFile io.Writer) (*WriteRepository, error) {
	result := &WriteRepository{}
	result.publicKey = key
	result.privateKey = privateKey
	var err error

	result.Label, err = RandomLabel()
	if err != nil {
		return nil, NewError(err, "Unable to generate new, random label")
	}

	result.cryptoWriter, err = result.Label.OpenWriter(repoFile)
	if err != nil {
		return nil, NewError(err, "Unable to open respository writer")
	}

	result.tarWriter = tar.NewWriter(result.cryptoWriter)

	return result, nil
}

// ExtractFile extracts a file from the repository
func (r *ReadRepository) ExtractFile() error {
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

// OpenRepository opens a repository for reading
func OpenRepository(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, repoFile io.Reader) (*ReadRepository, error) {
	result := &ReadRepository{}
	result.privateKey = privateKey
	result.publicKey = publicKey
	var err error

	result.Label, err = ReadLabel(repoFile, privateKey, publicKey)
	if err != nil {
		return nil, NewError(err, "Unable to read respository label")
	}

	cryptoReader, err := result.Label.OpenReader(repoFile)
	if err != nil {
		return nil, NewError(err, "Unable to open a new crypto reader")
	}

	result.tarReader = tar.NewReader(cryptoReader)
	return result, nil
}
