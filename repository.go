package repository

import (
	"archive/tar"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
	"log"
	"os"
)

// Repository is an encrypted bunch of stuff
type Repository struct {
	AesKey     []byte
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
	iv         []byte
	signature  []byte
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
	cryptoWriter *cipher.StreamWriter
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

func (r *WriteRepository) writeHeader(repoFile io.Writer) error {
	keyBytes := make([]byte, r.keylength()/2)
	copy(keyBytes[0:32], r.AesKey)
	copy(keyBytes[32:48], r.iv)

	var err error

	log.Printf("%d bytes", len(r.publicKey.N.Bytes()))
	encryptedHeader, err := rsa.EncryptPKCS1v15(rand.Reader, r.publicKey, keyBytes)
	if err != nil {
		log.Printf("Repository#writeHeader - Failed to encrypt header: %v", err)
		return err
	}

	_, err = repoFile.Write(encryptedHeader)
	if err != nil {
		log.Printf("Repository#writeHeader - Failed to write encrypted header: %v", err)
		return err
	}

	return nil
}

func (r *WriteRepository) writeSignature(repoFile io.Writer) error {
	key := make([]byte, len(r.AesKey)+len(r.iv))
	copy(key[0:len(r.AesKey)], r.AesKey)
	copy(key[len(r.AesKey):], r.iv)

	var err error
	hash := sha256.Sum256(key)
	r.signature, err = rsa.SignPKCS1v15(rand.Reader, r.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		log.Printf("Repository#writeHeader - Failed to sign header: %v", err)
		return err
	}

	_, err = repoFile.Write(r.signature)
	if err != nil {
		log.Printf("Repository#writeSignature - failed to write signature: %v", err)
		return err
	}

	return nil
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

// CreateRepository creates a new repository with the given filename
//
// AesKey contains the random AES encryption key
// RepoFile points to the open file
func CreateRepository(key *rsa.PublicKey, privateKey *rsa.PrivateKey, repoFile io.Writer) (*WriteRepository, error) {
	result := &WriteRepository{}
	result.publicKey = key
	result.privateKey = privateKey

	result.AesKey = make([]byte, 32)
	_, err := rand.Read(result.AesKey)
	if err != nil {
		log.Printf("Repository#CreateRepository - Unable to read random data while creating: %v", err)
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

	if err = result.writeHeader(repoFile); err != nil {
		log.Printf("Repository#CreateRepository - Unable to create header: %v", err)
		return nil, err
	}

	if err = result.writeSignature(repoFile); err != nil {
		log.Printf("Repository#CreateRepository - Unable to write signature: %v", err)
	}

	stream := cipher.NewCTR(block, result.iv)
	result.cryptoWriter = &cipher.StreamWriter{
		S: stream,
		W: repoFile,
	}

	result.tarWriter = tar.NewWriter(result.cryptoWriter)

	return result, nil
}

func (r *ReadRepository) readHeader(repoFile io.Reader) error {
	encryptedHeader := make([]byte, r.keylength())
	if _, err := repoFile.Read(encryptedHeader); err != nil {
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

func (r *ReadRepository) verifySignature(repoFile io.Reader) error {
	signature := make([]byte, r.keylength())
	if _, err := repoFile.Read(signature); err != nil {
		log.Printf("Repository#verifySignature - Unable to read signature block")
		return err
	}

	header := make([]byte, r.keylength())
	copy(header[0:32], r.AesKey)
	copy(header[32:], r.iv)

	sha := sha256.Sum256(header[0:48])
	err := rsa.VerifyPKCS1v15(r.publicKey, crypto.SHA256, sha[:], signature)
	if err != nil {
		log.Printf("Respository#readHeader - Failed to verify signature: %v", err)
		return err
	}

	r.signature = signature

	return nil
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

	if err = result.readHeader(repoFile); err != nil {
		log.Printf("Repository#OpenRepository - Failed to read the header for: %v", err)
		return nil, err
	}

	if err = result.verifySignature(repoFile); err != nil {
		log.Printf("Repository#OpenRepository - Failed to verify the signature: %v", err)
		return nil, err
	}

	block, err := aes.NewCipher(result.AesKey)
	if err != nil {
		log.Printf("Repository#OpenRepository - Failed to create new block cipher for: %v", err)
		return nil, err
	}

	stream := cipher.NewCTR(block, result.iv)
	result.cryptoReader = &cipher.StreamReader{
		S: stream,
		R: repoFile,
	}

	result.tarReader = tar.NewReader(result.cryptoReader)
	return result, nil
}
