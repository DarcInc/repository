package repository

import (
	"path"
	"path/filepath"
	"runtime"

	"os"

	"crypto/rsa"
	"crypto/x509"
	"encoding/json"

	"github.com/darcinc/afero"
)

func KeystoreDefaultDirectory() string {
	homedir := os.Getenv("HOME")
	if runtime.GOOS == "windows" {
		homedir = os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
	}
	return filepath.Join(homedir, ".repkey")
}

func NamedKeystoreFile(location string) string {
	if filepath.IsAbs(location) {
		return location
	}
	return filepath.Join(KeystoreDefaultDirectory(), location+".sqlite")
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

// Keystore is the collection of keys
type Keystore struct {
	PrivateKeys map[string][]byte
	PublicKeys  map[string][]byte
}

// CreateKeystore creates a new keystore or fails if one exist
func CreateKeystore(fs afero.Fs, name string) (*Keystore, error) {
	result := &Keystore{}
	result.PrivateKeys = make(map[string][]byte)
	result.PublicKeys = make(map[string][]byte)

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

// AddPrivateKey adds a private key to the keystore
func (k *Keystore) AddPrivateKey(name string, key *rsa.PrivateKey) {
	bytes := x509.MarshalPKCS1PrivateKey(key)
	k.PrivateKeys[name] = bytes
}

// FindPrivateKey finds a private key from the keystore
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

// FindPublicKey is returned the public key for a given name
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

// AddPublicKey to keystore
func (k *Keystore) AddPublicKey(name string, key *rsa.PublicKey) {
	bytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		panic(err)
	}

	k.PublicKeys[name] = bytes
}

// Save saves a keystore to a file
func (k *Keystore) Save(file afero.File) error {
	encoder := json.NewEncoder(file)
	return encoder.Encode(k)
}

// OpenKeystore opens a keystore pointed to by a file
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

// KeystorePath returns the path to a keystore
func KeystorePath(name string) string {
	if path.IsAbs(name) {
		return name
	}

	return NamedKeystoreFile(name)
}
