package repository

import (
	"log"
	"path"
	"path/filepath"
	"runtime"

	"os"

	"crypto/rsa"
	"crypto/x509"
	"encoding/json"

	"github.com/darcinc/afero"
)

// HomeDir returns the user's home directory.
func HomeDir() string {
	homedir := os.Getenv("HOME")
	if runtime.GOOS == "windows" {
		homedir = os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
	}
	return homedir
}

// KeystoreDefaultDirectory returns the default directory for named keystores.
// By default the default directory is in the user's home directory and the
// .repkey "hidden director".  E.g. (/home/joeuser/.repkey on Unix.)
func KeystoreDefaultDirectory() string {

	return filepath.Join(HomeDir(), ".repkey")
}

// NamedKeystoreFile returns a named keystore file from the user's default
// keystore directory.
func NamedKeystoreFile(location string) string {
	if filepath.IsAbs(location) {
		return location
	}
	return filepath.Join(KeystoreDefaultDirectory(), location+".keys")
}

func keystoreExists(fs afero.Fs, location string) (bool, error) {
	var dir string
	var fullpath string

	if filepath.IsAbs(location) {
		dir = path.Dir(location)
		fullpath = location
	} else {
		dir = KeystoreDefaultDirectory()
		fullpath = NamedKeystoreFile(location)
	}

	ok, err := afero.DirExists(fs, dir)
	if err != nil {
		return false, err
	}

	if !ok {
		return false, nil
	}

	ok, err = afero.Exists(fs, fullpath)
	if err != nil {
		return false, err
	}

	return ok, nil
}

// Keystore is the collection of private and public keys.
type Keystore struct {
	PrivateKeys map[string][]byte
	PublicKeys  map[string][]byte
}

// CreateKeystore creates a new key store in the given file system.  If a keystore
// already exists, that is an error.  Returns the keystore or nil if there was
// an error.
func CreateKeystore(fs afero.Fs, name string) (*Keystore, error) {
	result := &Keystore{}
	result.PrivateKeys = make(map[string][]byte)
	result.PublicKeys = make(map[string][]byte)

	directory := filepath.Dir(name)
	_, err := fs.Stat(directory)
	if err != nil {
		err := fs.MkdirAll(directory, 0700)
		if err != nil {
			log.Fatalf("Failed to crete directory %s: %v", directory, err)
		}
	}

	file, err := fs.OpenFile(NamedKeystoreFile(name), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	err = result.Save(file)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// AddPrivateKey adds a private key to the key store with the given name.
func (k *Keystore) AddPrivateKey(name string, key *rsa.PrivateKey) {
	bytes := x509.MarshalPKCS1PrivateKey(key)
	k.PrivateKeys[name] = bytes
}

// FindPrivateKey finds a private key from the keystore with the given
// name.  If no key is found, it returns nil and false for the second
// return value.
func (k *Keystore) FindPrivateKey(name string) (*rsa.PrivateKey, bool) {
	bytes, ok := k.PrivateKeys[name]
	if !ok {
		return nil, ok
	}

	result, err := x509.ParsePKCS1PrivateKey(bytes)
	if err != nil {
		panic(err)
	}

	return result, ok
}

// FindPublicKey return the private or public key for a given nanem.  If
// no key is found nil is returned and false for the second return value.
func (k *Keystore) FindPublicKey(name string) (*rsa.PublicKey, bool) {
	bytes, ok := k.PrivateKeys[name]
	if !ok {
		bytes, ok = k.PublicKeys[name]
		if !ok {
			return nil, false
		}
		result, err := x509.ParsePKIXPublicKey(bytes)
		if err != nil {
			panic(err)
		}

		return result.(*rsa.PublicKey), ok
	}
	result, err := x509.ParsePKCS1PrivateKey(bytes)
	if err != nil {
		panic(err)
	}

	return &result.PublicKey, ok
}

// AddPublicKey to keystore with the given name.
func (k *Keystore) AddPublicKey(name string, key *rsa.PublicKey) {
	bytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		panic(err)
	}

	k.PublicKeys[name] = bytes
}

// RemoveKey removes a private key ad or public key with
// that name.
func (k *Keystore) RemoveKey(name string) {
	_, ok := k.PrivateKeys[name]
	if ok {
		delete(k.PrivateKeys, name)
	}

	_, ok = k.PublicKeys[name]
	if ok {
		delete(k.PublicKeys, name)
	}
}

// Save saves a keystore to a file.  Returns an erro if the
// keystore cannot be saved to the file.
func (k *Keystore) Save(file afero.File) error {
	encoder := json.NewEncoder(file)
	return encoder.Encode(k)
}

// OpenKeystore opnes a keystore from a file.  Returns a keystore
// or nil if there is an error.
func OpenKeystore(file afero.File) (*Keystore, error) {
	decoder := json.NewDecoder(file)
	keystore := &Keystore{
		PrivateKeys: make(map[string][]byte),
		PublicKeys:  make(map[string][]byte),
	}
	err := decoder.Decode(keystore)
	if err != nil {
		return nil, err
	}

	return keystore, nil
}

// KeystorePath returns the path to a keystore.  If the path is an
// absolute path, that is returned.  If the path is not an absolute
// path, then it is assumed to be a named keystore.
func KeystorePath(name string) string {
	if path.IsAbs(name) {
		return name
	}

	return NamedKeystoreFile(name)
}
