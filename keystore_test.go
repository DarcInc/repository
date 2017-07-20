package repository

import (
	"path/filepath"
	"runtime"
	"testing"

	"os"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	"github.com/darcinc/afero"
)

func createTestFs() (afero.Fs, error) {
	appfs := afero.NewMemMapFs()
	userHome := os.Getenv("HOME")

	var err error
	if runtime.GOOS == "windows" {
		userHome, err = filepath.Abs(os.Getenv("HOMEPATH"))
		if err != nil {
			panic(err)
		}
	}

	filename := "keystore.sqlite"

	appfs.MkdirAll(filepath.Join(userHome, ".repkey"), 0700)
	file, err := appfs.Create(filepath.Join(userHome, ".repkey", filename))
	if err != nil {
		return nil, err
	}

	file.Close()
	return appfs, nil
}

func TestAbsolutePathKeystoreExists(t *testing.T) {
	appfs, err := createTestFs()
	if err != nil {
		t.Fatalf("TestAbsolutePathKeystoreExists - Failed to create test filesystem: %v", err)
	}
	homedir := os.Getenv("HOME")
	if runtime.GOOS == "windows" {
		homedir = os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
	}

	fullPath, err := filepath.Abs(filepath.Join(homedir, ".repkey", "keystore.sqlite"))
	if err != nil {
		t.Fatalf("TestAbsolutePathKeystoreExists - Error creating absolute path: %v", err)
	}
	ok, err := keystoreExists(appfs, fullPath)
	if err != nil {
		t.Fatalf("TestAbsolutePathKeystoreExists - Failed to check existence of keystore: %v", err)
	}

	if !ok {
		t.Errorf("TestAbsolutePathKeystoreExists - Expected keystore to exist")
	}
}

func TestNamedKeystoreExists(t *testing.T) {
	appfs, err := createTestFs()
	if err != nil {
		t.Fatalf("TestNamedKeystoreExists - Failed to create test filesystem: %v", err)
	}

	ok, err := keystoreExists(appfs, "keystore")
	if err != nil {
		t.Fatalf("TestNamedKeystoreExists - Failed to check existence of keystore: %v", err)
	}

	if !ok {
		t.Errorf("TestNamedKeystoreExists - Expected keystore to exist")
	}
}

func TestCreateNamedKeystore(t *testing.T) {
	appfs, err := createTestFs()
	if err != nil {
		t.Fatalf("TestCreateNamedKeystore - Failed to create test filesystem: %v", err)
	}

	keystore, err := CreateKeystore(appfs, "foo")
	if err != nil {
		t.Fatalf("TestCreateNamedKeystore - Failed to create keystore: %v", err)
	}
	if keystore == nil {
		t.Fatalf("TestCreateNamedKeystore - Keystore is nil")
	}

	ok, err := keystoreExists(appfs, "foo")
	if err != nil {
		t.Fatalf("TestCreateNamedKeystore - Failed to check the existence of keystore: %v", err)
	}

	if !ok {
		t.Error("TestCreateNamedKeystore - Expected keystore 'foo' to exist")
	}
}

func TestAddPublicPrivateKey(t *testing.T) {
	appfs, err := createTestFs()
	if err != nil {
		t.Fatalf("TestCreateNamedKeystore - Failed to create test filesystem: %v", err)
	}

	keystore, err := CreateKeystore(appfs, "foo")
	if err != nil {
		t.Fatalf("TestCreateNamedKeystore - Failed to create test filesystem: %v", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	keystore.AddPrivateKey("foo", privateKey)

	foundPrivateKey, ok := keystore.FindPrivateKey("foo")
	if !ok {
		t.Fatalf("TestCreateNamedKeystore - Failed to find the key just inserted")
	}

	bytes1 := x509.MarshalPKCS1PrivateKey(privateKey)
	bytes2 := x509.MarshalPKCS1PrivateKey(foundPrivateKey)

	for i := range bytes1 {
		if bytes1[i] != bytes2[i] {
			t.Fatalf("TestCreateNamedKeystore - Mismatch")
		}
	}

	foundPublicKey, ok := keystore.FindPublicKey("foo")
	if !ok {
		t.Fatalf("TestCreateNamedKeystore - Failed to find the public key for the key just inserted")
	}

	bytes1, err = x509.MarshalPKIXPublicKey(foundPublicKey)
	if err != nil {
		t.Fatalf("TestCreateNamedKeystore - Failed to marshal found public key: %v", err)
	}
	bytes2, err = x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("TestCreateNamedKeystore - Failed to marshal public key: %v", err)
	}

	for i := range bytes1 {
		if bytes1[i] != bytes2[i] {
			t.Fatalf("TestCreateNamedKeystore - Mismatch")
		}
	}
}

func TestAddPublicKey(t *testing.T) {
	appfs, err := createTestFs()
	if err != nil {
		t.Fatalf("TestAddPublicKey - Failed to create test filesystem: %v", err)
	}

	keystore, err := CreateKeystore(appfs, "foo")
	if err != nil {
		t.Fatalf("TestAddPublicKey - Failed to create test filesystem: %v", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("TestAddPublicKey - Failed to generate key")
	}

	keystore.AddPublicKey("foo", &privateKey.PublicKey)

	foundKey, ok := keystore.FindPublicKey("foo")
	if !ok {
		t.Fatalf("TestAddPublicKey - Failed to find the key just added")
	}

	bytes1, err := x509.MarshalPKIXPublicKey(foundKey)
	if err != nil {
		t.Fatalf("TestAddPublicKey - Failed to marshal found public key: %v", err)
	}
	bytes2, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("TestAddPublicKey - Failed to marshal public key: %v", err)
	}

	for i := range bytes1 {
		if bytes1[i] != bytes2[i] {
			t.Fatalf("TestAddPublicKey - Mismatch")
		}
	}
}

func TestSaveKeystore(t *testing.T) {
	appfs, err := createTestFs()
	if err != nil {
		t.Fatalf("TestSaveKeystore - Failed to create test filesystem: %v", err)
	}

	keystore, err := CreateKeystore(appfs, "foo")
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("TestSaveKeystore - Failed to generate key")
	}

	keystore.AddPrivateKey("bar", privateKey)
	fullPath := KeystorePath("foo")
	keyFile, err := appfs.OpenFile(fullPath, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("TestSaveKeystore - Failed to open save file: %v", err)
	}

	err = keystore.Save(keyFile)
	keyFile.Close()

	keyFile, err = appfs.OpenFile(fullPath, os.O_RDONLY, 0600)
	keystore, err = OpenKeystore(keyFile)
	defer keyFile.Close()

	privateKey, ok := keystore.FindPrivateKey("bar")
	if !ok {
		t.Fatal("TestSaveKeystore - Failed to find private key")
	}
}
