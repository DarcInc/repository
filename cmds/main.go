package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

func writeKeyPairToFile(key *rsa.PrivateKey, filename string) error {
	privateKeyName := fmt.Sprintf("%s.key", filename)
	publicKeyName := fmt.Sprintf("%s-pub.key", filename)

	privateKeyData := x509.MarshalPKCS1PrivateKey(key)
	publicKeyData, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		log.Printf("Failed to marshal public key: %v", err)
		return err
	}

	err = ioutil.WriteFile(privateKeyName, privateKeyData, 0644)
	if err != nil {
		log.Printf("Failed to write private key: %s: %v", privateKeyName, err)
		return err
	}

	ioutil.WriteFile(publicKeyName, publicKeyData, 0644)
	if err != nil {
		log.Printf("Failed to write public key: %s: %v", publicKeyName, err)
		os.Remove(privateKeyName)
		return err
	}

	return nil
}

func readPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(fmt.Sprintf("%s.key", filename))
	if err != nil {
		log.Printf("Failed to read private key %s.key: %v", filename, err)
		return nil, err
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(data)
	if err != nil {
		log.Printf("Failed to parse private key: %v", err)
		return nil, err
	}

	return privateKey, nil
}

func readPublicKeyFromFile(filename string) (*rsa.PublicKey, error) {
	data, err := ioutil.ReadFile(fmt.Sprintf("%s-pub.key", filename))
	if err != nil {
		log.Printf("Failed to read public key %s-pub.key from file: %v", filename, err)
		return nil, err
	}

	publicKey, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		log.Printf("Failed to parse public key: %v", err)
		return nil, err
	}

	rsaPublicKey := publicKey.(*rsa.PublicKey)
	return rsaPublicKey, nil
}

func generateRandomAESKey() ([]byte, error) {
	aesKey := make([]byte, 32)
	bytesRead, err := rand.Read(aesKey)
	if err != nil {
		log.Printf("Failed to read random AES key: %v", err)
		return nil, nil
	}

	if bytesRead < 32 {
		log.Printf("Failed to read 32 bytes fo data")
		return nil, nil
	}

	return aesKey, nil
}

func startRepository(aesKey []byte, pubKey *rsa.PublicKey, filename string) (io.Writer, error) {
	iv := make([]byte, aes.BlockSize)
	bytesRead, err := rand.Read(iv)
	if err != nil {
		log.Printf("Failed to read initialization vector for the AES key: %v", err)
		return nil, err
	}
	if bytesRead < aes.BlockSize {
		log.Printf("Failed to read a sufficiently large IV")
		return nil, nil
	}

	header := make([]byte, len(aesKey)+aes.BlockSize)
	copy(header[0:len(aesKey)], aesKey)
	copy(header[len(aesKey):len(aesKey)+aes.BlockSize], iv)

	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Printf("Failed to open file %s: %v", filename, err)
		return nil, err
	}

	encryptedHeader, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, header)
	if err != nil {
		log.Printf("Failed to encrypt file header: %v", err)
		file.Close()
		return nil, err
	}

	bytesWritten, err := file.Write(encryptedHeader)
	if err != nil {
		log.Printf("Failed to write encrypted header: %v", err)
		file.Close()
		return nil, err
	}
	if bytesWritten < len(encryptedHeader) {
		log.Printf("Failed to write all %d bytes to header: %v", len(encryptedHeader), err)
		file.Close()
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		log.Printf("Failed to generate new AES Block Cipher: %v", err)
		file.Close()
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)
	writer := &cipher.StreamWriter{
		S: stream,
		W: file,
	}

	return writer, nil
}

func openRepository(key *rsa.PrivateKey, filename string) (io.Reader, error) {
	file, err := os.OpenFile(filename, os.O_RDONLY, 0600)
	if err != nil {
		log.Printf("Failed to open repository: %v", err)
		return nil, err
	}

	encryptedHeader := make([]byte, len(key.D.Bytes()))
	bytesRead, err := file.Read(encryptedHeader)
	if err != nil {
		log.Printf("Failed to read the repository headers: %v", err)
		return nil, err
	}

	if bytesRead < len(key.D.Bytes()) {
		log.Printf("Failed to read full header.  Only read %d bytes.", bytesRead)
		return nil, nil
	}

	header, err := rsa.DecryptPKCS1v15(rand.Reader, key, encryptedHeader)
	if err != nil {
		log.Printf("Failed to decrypt repository headers: %v", err)
		return nil, err
	}

	randomAesKey := header[0:32]
	iv := header[32:48]

	cipherBlock, err := aes.NewCipher(randomAesKey)
	if err != nil {
		log.Printf("Failed to create a new cipher block")
		return nil, err
	}
	stream := cipher.NewCTR(cipherBlock, iv)
	reader := &cipher.StreamReader{
		S: stream,
		R: file,
	}

	return reader, nil
}

func writeFileToRepository(repo io.Writer, filename string) error {
	infile, err := os.OpenFile(filename, os.O_RDONLY, 0600)
	if err != nil {
		log.Printf("Unable to open input file: %s: %v", filename, err)
		return err
	}

	defer infile.Close()

	_, err = io.Copy(repo, infile)
	if err != nil {
		log.Printf("Failed to write data to file: %v", err)
		return err
	}

	return nil
}

func readFileFromRepository(repo io.Reader) error {
	_, err := io.Copy(os.Stdout, repo)
	if err != nil {
		log.Printf("Failed to copy output to stdout: %v", err)
		return err
	}
	return nil
}

func temp() {
	publicKey, err := readPublicKeyFromFile("keyname")
	if err != nil {
		log.Fatalf("Failed to read public key from file: %v", err)
	}

	repo, err := CreateRepository("myrepo.repo", publicKey)
	if err != nil {
		log.Fatalf("Failed to create repository: %v", err)
	}

	if err = repo.AddFile("cluster.pdf"); err != nil {
		log.Fatalf("Failed to add file to repository: %v", err)
	}

	if err = repo.Seal(); err != nil {
		log.Fatalf("Failed to seal repo: %v", err)
	}
}

func main() {
	privateKey, err := readPrivateKeyFromFile("keyname")
	if err != nil {
		log.Fatalf("Failed to read private key from file: %v", err)
	}

	repo, err := OpenRepository("myrepo.repo", privateKey)
	if err != nil {
		log.Fatalf("Failed to open repository: %v", err)
	}

	if err = repo.ExtractFile(); err != nil {
		log.Fatalf("Failed to extract file: %v", err)
	}

	if err = repo.Close(); err != nil {
		log.Fatalf("Failed to close file: %v", err)
	}
}
