package repository

import (
	"archive/tar"
	"crypto/cipher"
	"crypto/rsa"
	"fmt"
	"io"
	"os"

	"github.com/darcinc/afero"
)

// Key is the key necessary to unlock a tape.  A key contains the
// label (which contains the random AES key IV necessary to
// decipher the tape).  When creating tapes, it contains the
// public key used to encrypt the label and the private key
// used to sign the label.  When deciphering tapes, it contains
// the private key to unencrypt the label and the public
// to to veify the label signature.
type Key struct {
	Label      Label
	PublicKey  *rsa.PublicKey
	PrivateKey *rsa.PrivateKey
}

// TapeReader is used to read from and unpack an encrypted
// tape.  It contains the key necessary to decipher the tape
// and the archive reader necessary to read data from the
// tape.
type TapeReader struct {
	Key          Key
	tarReader    *tar.Reader
	cryptoReader *cipher.StreamReader
}

// TapeWriter is used to write data into a tape.  It contains
// the Key used to set up encryption and the archive writer
// to write data into the tape.
type TapeWriter struct {
	Key          Key
	tarWriter    *tar.Writer
	cryptoWriter io.Writer
}

// NewTapeWriter creates a new tape writer.  It returns
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

// AddFile adds data to the tape by reading the contents of a file
// a given path.  The writing occurs in two parts.  First in the
// metadata about the file and then are the actual file contents.
func (r *TapeWriter) AddFile(fs afero.Fs, filePath string) error {
	fileInfo, err := fs.Stat(filePath)
	if err != nil {
		return NewError(err, fmt.Sprintf("Unable to stat file %s", filePath))
	}

	header, err := tar.FileInfoHeader(fileInfo, filePath)
	if err != nil {
		return NewError(err, fmt.Sprintf("Unable to create info header for %s", filePath))
	}
	header.Name = filePath

	err = r.tarWriter.WriteHeader(header)
	if err != nil {
		return NewError(err, fmt.Sprintf("Unable to write header into file %s", filePath))
	}

	infile, err := fs.Open(filePath)
	if err != nil {
		return NewError(err, fmt.Sprintf("Unable to open input file %s", filePath))
	}
	defer infile.Close()

	_, err = io.Copy(r.tarWriter, infile)
	if err != nil {
		return NewError(err, fmt.Sprintf("Failed to copy data from input file %s to tar writer", filePath))
	}

	return nil
}

// AddDirectory adds an entire directory and its contents at one time
func (r *TapeWriter) AddDirectory(fs afero.Fs, dirpath string) error {
	err := afero.Walk(fs, dirpath, func(path string, info os.FileInfo, err error) error {
		if err == nil {
			if !info.IsDir() {
				return r.AddFile(fs, path)
			}
		}
		return nil
	})
	return err
}

// OpenTape opens a tape for reading.  It decrypts and verifies the label
// and then set up the arhicve reader to read from the tape.
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

// ExtractFile reads a file out of the tape and writes it onto the disk.
// it uses metadata stored about the file to determine the file name
// and any other characterisitics to set on the created file.
func (r *TapeReader) ExtractFile(fs afero.Fs) error {
	header, err := r.tarReader.Next()
	if err == io.EOF {
		return err
	}
	if err != nil {
		return NewError(err, "Failed to extract file from repository")
	}

	file, err := fs.OpenFile(header.Name, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return NewError(err, fmt.Sprintf("Failed to open file %s for writing", header.Name))
	}
	defer file.Close()

	_, err = io.Copy(file, r.tarReader)
	if err != nil {
		return NewError(err, fmt.Sprintf("Failed to extract file %s", header.Name))
	}

	return nil
}

// Contents returns the contents of a tape.  Each is an en
func (r *TapeReader) Contents() ([]string, error) {
	result := []string{}

	for header, err := r.tarReader.Next(); header != nil && err == nil; header, err = r.tarReader.Next() {
		if err != nil {
			return nil, err
		}

		result = append(result, header.Name)
	}
	return result, nil
}
