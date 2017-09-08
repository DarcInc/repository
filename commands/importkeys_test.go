package commands

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path"
	"testing"

	"github.com/darcinc/afero"
	"github.com/darcinc/repository"
)

const testPubkey = `-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAziXOEOxPp01Kq2gtASVI
MkRJxtnDKh9n3xZL+mJYkh5IVUN6+OhSy5QYPif5pjomCR3qDsK5utTDZosNxVYu
M7Gc00DNlS4y4JxaTJzyzwm9izIWataQpFvqc2ou8tzVmZzaJQ+5YopRLU/biCOV
kjgeyGwpgZ762t+qRk9YIX7KXYwAXiw9X5/9CTKtRiJRLSj5ArHfmfESPZekp5I1
qM0TPn2HE7rqvU6IWMN5v4Q07LXJb0+IWrZ2Sh6oo29dWgEtJ0KbTU5jyb/1297N
XxArvnCfn5lSMu7Oie+no9Dgbo/cQ+vVoygbFS8qaIg32dFwmltznVY73DZymh2g
3QIDAQAB
-----END RSA PUBLIC KEY-----`

func createTestKeyFile(fs afero.Fs) {
	pk, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}

	keybytes := x509.MarshalPKCS1PrivateKey(pk)
	file, err := fs.OpenFile(path.Join(repository.HomeDir(), "test.pem"), os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	file, err = fs.OpenFile(path.Join(repository.HomeDir(), "test3.pem"), os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	_, err = file.Write([]byte(testPubkey))
	if err != nil {
		panic(err)
	}

	err = pem.Encode(file, &pem.Block{Type: "PRIVATE KEY", Bytes: keybytes})
	if err != nil {
		panic(err)
	}

	keybytes, err = x509.MarshalPKIXPublicKey(&pk.PublicKey)
	if err != nil {
		panic(err)
	}
	file, err = fs.OpenFile(path.Join(repository.HomeDir(), "test2.pem"), os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	err = pem.Encode(file, &pem.Block{Type: "PUBLIC KEY", Bytes: keybytes})
	if err != nil {
		panic(err)
	}
}

func TestImportPrivateKey(t *testing.T) {
	fs := createFSWithKeystore(t)
	createTestKeyFile(fs)

	file, err := fs.Open(path.Join(repository.HomeDir(), "test.pem"))
	if err != nil {
		t.Fatalf("Unable to open test key file: %v", err)
	}
	defer file.Close()

	err = importKey(fs, "foo", "imported", file)
	if err != nil {
		t.Fatalf("Unable to import key: %v", err)
	}

	filename := repository.NamedKeystoreFile("foo")
	file, err = fs.Open(filename)
	if err != nil {
		t.Fatalf("Unale to open keystore file: %v", err)
	}
	defer file.Close()

	keystore, err := repository.OpenKeystore(file)
	if err != nil {
		t.Fatalf("Unable to read keystore file: %v", err)
	}

	_, ok := keystore.FindPrivateKey("imported")
	if !ok {
		t.Error("Failed to find testkey after import")
	}

}

func TestImportPublicKey(t *testing.T) {
	fs := createFSWithKeystore(t)
	createTestKeyFile(fs)

	file, err := fs.Open(path.Join(repository.HomeDir(), "test2.pem"))
	if err != nil {
		t.Fatalf("Unable to find public key test key: %v", err)
	}
	defer file.Close()

	err = importKey(fs, "foo", "imported2", file)
	if err != nil {
		t.Errorf("Failed to import public key: %v", err)
	}

	filename := repository.NamedKeystoreFile("foo")
	file, err = fs.Open(filename)
	if err != nil {
		t.Fatalf("Unale to open keystore file: %v", err)
	}
	defer file.Close()

	keystore, err := repository.OpenKeystore(file)
	if err != nil {
		t.Fatalf("Unable to read keystore file: %v", err)
	}

	_, ok := keystore.FindPublicKey("imported2")
	if !ok {
		t.Error("Failed to find imported2 after import")
	}
}

func TestImportSSHPublicKey(t *testing.T) {
	fs := createFSWithKeystore(t)
	createTestKeyFile(fs)

	file, err := fs.Open(path.Join(repository.HomeDir(), "test3.pem"))
	if err != nil {
		t.Fatalf("Unable to find public ssh key test key: %v", err)
	}
	defer file.Close()

	err = importKey(fs, "foo", "public-ssh", file)
	if err != nil {
		t.Errorf("Failed to import public key: %v", err)
	}

	filename := repository.NamedKeystoreFile("foo")
	file, err = fs.Open(filename)
	if err != nil {
		t.Fatalf("Unale to open keystore file: %v", err)
	}
	defer file.Close()

	keystore, err := repository.OpenKeystore(file)
	if err != nil {
		t.Fatalf("Unable to read keystore file: %v", err)
	}

	_, ok := keystore.FindPublicKey("public-ssh")
	if !ok {
		t.Error("Failed to find public-ssh after import")
	}
}
