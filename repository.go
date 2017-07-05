package repository

import (
	"archive/tar"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"log"
	"os"
)

// Repository is an encrypted bunch of stuff
type Repository struct {
	AesKey       []byte
	RepoFile     *os.File
	publicKey    *rsa.PublicKey
	privateKey   *rsa.PrivateKey
	tarWriter    *tar.Writer
	tarReader    *tar.Reader
	iv           []byte
	cryptoWriter *cipher.StreamWriter
	cryptoReader *cipher.StreamReader
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

func (r *Repository) writeHeader() error {
	keyBytes := make([]byte, r.keylength()/2)
	copy(keyBytes[0:32], r.AesKey)
	copy(keyBytes[32:48], r.iv)

	log.Printf("%d bytes", len(r.publicKey.N.Bytes()))
	encryptedHeader, err := rsa.EncryptPKCS1v15(rand.Reader, r.publicKey, keyBytes)
	if err != nil {
		log.Printf("Repository#writeHeader - Failed to encrypt header: %v", err)
		return err
	}

	_, err = r.RepoFile.Write(encryptedHeader)
	if err != nil {
		log.Printf("Repository#writeHeader - Failed to write encrypted header: %v", err)
		return err
	}

	return nil
}

// CreateRepository creates a new repository with the given filename
//
// AesKey contains the random AES encryption key
// RepoFile points to the open file
func CreateRepository(filename string, key *rsa.PublicKey) (*Repository, error) {
	result := &Repository{publicKey: key}

	result.AesKey = make([]byte, 32)
	_, err := rand.Read(result.AesKey)
	if err != nil {
		log.Printf("Repository#CreateRepository - Unable to read random data while creating %s: %v", filename, err)
		return nil, err
	}

	result.iv = make([]byte, 16)
	_, err = rand.Read(result.iv)
	if err != nil {
		log.Printf("Repository#CreateRepository - Unable to generate new initializtion vector: %v", err)
		return nil, err
	}

	block, err := aes.NewCipher(result.AesKey)
	if err != nil {
		log.Printf("Repository#CreateRepository - Unable to create a new cipher block: %v", err)
		return nil, err
	}

	result.RepoFile, err = os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0600)
	if err != nil {
		log.Printf("Repository#CreateRepository - Unable to create repository file %s: %v", filename, err)
		return nil, err
	}

	if err = result.writeHeader(); err != nil {
		log.Printf("Repository#CreateRepository - Unable to create header for %s: %v", filename, err)
		result.RepoFile.Close()
		return nil, err
	}

	stream := cipher.NewCTR(block, result.iv)
	result.cryptoWriter = &cipher.StreamWriter{
		S: stream,
		W: result.RepoFile,
	}

	result.tarWriter = tar.NewWriter(result.cryptoWriter)

	return result, nil
}

func (r *Repository) readHeader() error {
	encryptedHeader := make([]byte, r.keylength())
	if _, err := r.RepoFile.Read(encryptedHeader); err != nil {
		log.Printf("Repository#readHeader - Unable to read header out of file: %v", err)
		return err
	}

	header, err := rsa.DecryptPKCS1v15(rand.Reader, r.privateKey, encryptedHeader)
	if err != nil {
		log.Printf("Repository#readHeader - Failed to decrypt header: %v", err)
		return err
	}

	r.AesKey = header[0:32]
	r.iv = header[32:48]

	return nil
}

// OpenRepository opens a repository for reading
func OpenRepository(filename string, privateKey *rsa.PrivateKey) (*Repository, error) {
	result := &Repository{}
	result.privateKey = privateKey
	var err error

	result.RepoFile, err = os.OpenFile(filename, os.O_RDONLY, 0600)
	if err != nil {
		log.Printf("Repository#OpenRepository - Unable to open repository %s for reading: %v", filename, err)
		return nil, err
	}

	if err = result.readHeader(); err != nil {
		log.Printf("Repository#OpenRepository - Failed to read the header for %s: %v", filename, err)
		result.RepoFile.Close()
		return nil, err
	}

	block, err := aes.NewCipher(result.AesKey)
	if err != nil {
		log.Printf("Repository#OpenRepository - Failed to create new block cipher for %s: %v", filename, err)
		result.RepoFile.Close()
		return nil, err
	}

	stream := cipher.NewCTR(block, result.iv)
	result.cryptoReader = &cipher.StreamReader{
		S: stream,
		R: result.RepoFile,
	}

	result.tarReader = tar.NewReader(result.cryptoReader)
	return result, nil
}

// AddFile adds data from a file
func (r *Repository) AddFile(filePath string) error {
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

// ExtractFile extracts a file from the repository
func (r *Repository) ExtractFile() error {
	header, err := r.tarReader.Next()
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

// Seal completes writing the data and closes the repository
func (r *Repository) Seal() error {
	if err := r.tarWriter.Flush(); err != nil {
		log.Printf("Repository#Seal - Failed to flush the tar writer.")
	}

	if err := r.RepoFile.Close(); err != nil {
		log.Printf("Repository#Seal - Failed to close output file: %v", err)
	}

	return nil
}

// Close closes the repository
func (r *Repository) Close() error {
	if err := r.RepoFile.Close(); err != nil {
		log.Printf("Repository#Close - Failed to close repo file: %v", err)
		return err
	}

	return nil
}
