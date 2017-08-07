package repository

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
	"log"
)

// Label is a key and key signature to use to encrypt a tape.
type Label struct {
	AesKey    []byte
	iv        []byte
	signature []byte
}

func (l *Label) writeHeader(repoFile io.Writer, publicKey *rsa.PublicKey) error {
	keyBytes := make([]byte, publicKey.N.BitLen()/8-16)
	copy(keyBytes[0:32], l.AesKey)
	copy(keyBytes[32:48], l.iv)

	var err error

	encryptedHeader, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, keyBytes)
	if err != nil {
		return NewError(err, "Failed to encrypt AES key and IV")
	}

	_, err = repoFile.Write(encryptedHeader)
	if err != nil {
		return NewError(err, "Failed to write encrypted key into header")
	}

	return nil
}

func (l *Label) readHeader(repoFile io.Reader, encKey *rsa.PrivateKey) error {
	encryptedHeader := make([]byte, encKey.N.BitLen()/8)
	if _, err := repoFile.Read(encryptedHeader); err != nil {
		log.Printf("Repository#readHeader - Unable to read header out of file: %v", err)
		return err
	}

	header, err := rsa.DecryptPKCS1v15(rand.Reader, encKey, encryptedHeader)
	if err != nil {
		log.Printf("Repository#readHeader - Failed to decrypt header: %v", err)
		return err
	}

	l.AesKey = header[0:32]
	l.iv = header[32:48]

	return nil
}

func (l *Label) writeSignature(repoFile io.Writer, privateKey *rsa.PrivateKey) error {
	key := make([]byte, len(l.AesKey)+len(l.iv))
	copy(key[0:len(l.AesKey)], l.AesKey)
	copy(key[len(l.AesKey):], l.iv)

	var err error
	hash := sha256.Sum256(key)
	l.signature, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return NewError(err, "Failed to sign the label header")
	}

	_, err = repoFile.Write(l.signature)
	if err != nil {
		return NewError(err, "Failed to write signature to label")
	}

	return nil
}

func (l *Label) verifySignature(repoFile io.Reader, pubKey *rsa.PublicKey) error {
	signature := make([]byte, (pubKey.N.BitLen() / 8))
	if _, err := repoFile.Read(signature); err != nil {
		return NewError(err, "Unable to verify label signature")
	}

	header := make([]byte, pubKey.N.BitLen()/8)
	copy(header[0:32], l.AesKey)
	copy(header[32:], l.iv)

	sha := sha256.Sum256(header[0:48])
	err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, sha[:], signature)
	if err != nil {
		return NewError(err, "Failed to verify signature")
	}

	l.signature = signature

	return nil
}

// WriteLabel creates a new label for an encrypted tape.  It consists of the
// the header (the AES random key and initialization vector) and the
// signature of the header.
func (l *Label) WriteLabel(repoFile io.Writer, encKey *rsa.PublicKey, signKey *rsa.PrivateKey) error {
	if err := l.writeHeader(repoFile, encKey); err != nil {
		return NewError(err, "Error writing label header")
	}

	if err := l.writeSignature(repoFile, signKey); err != nil {
		return NewError(err, "Error writing label signature")
	}

	return nil
}

// ReadLabel reads a label in from the source reader, using the private key to
// decrypt the label and the public key to check the signature.  Returns an empty
// label and error if there is an error.
func ReadLabel(repoFile io.Reader, decrKey *rsa.PrivateKey, signKey *rsa.PublicKey) (Label, error) {
	result := Label{}

	if err := result.readHeader(repoFile, decrKey); err != nil {
		return result, NewError(err, "Unable to read label")
	}

	if err := result.verifySignature(repoFile, signKey); err != nil {
		return result, NewError(err, "Unable to verify signature")
	}

	return result, nil
}

// OpenReader opens a decrypting reader encapsulating the given stream.  The
// label's AES key and IV are used to set up the read stream.
func (l *Label) OpenReader(repoFile io.Reader) (io.Reader, error) {
	block, err := aes.NewCipher(l.AesKey)
	if err != nil {
		return nil, NewError(err, "Error creating read cypher")
	}

	stream := cipher.NewCTR(block, l.iv)
	cryptoReader := &cipher.StreamReader{
		S: stream,
		R: repoFile,
	}

	return cryptoReader, nil
}

// OpenWriter opens an encrypting writer, wrapping the original file writer.
func (l *Label) OpenWriter(repoFile io.Writer) (io.Writer, error) {
	block, err := aes.NewCipher(l.AesKey)
	if err != nil {
		return nil, NewError(err, "Unable to create a new cipher")
	}

	stream := cipher.NewCTR(block, l.iv)
	result := &cipher.StreamWriter{
		S: stream,
		W: repoFile,
	}

	return result, nil
}

// RandomLabel generates a new, random Label
func RandomLabel() (Label, error) {
	result := Label{}
	result.AesKey = make([]byte, 32)
	_, err := rand.Read(result.AesKey)
	if err != nil {
		return result, NewError(err, "Unable to read random data to generate random key")
	}

	result.iv = make([]byte, 16)
	_, err = rand.Read(result.iv)
	if err != nil {
		return result, NewError(err, "Unable to generate random initialization vector for cipher")
	}

	return result, nil
}
