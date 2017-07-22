package commands

import (
	"io"

	"crypto/x509"
	"encoding/pem"

	"github.com/darcinc/afero"
	"github.com/darcinc/repository"
)

// ExtractKeys extracts a key into PEM encoded formats
func ExtractKeys(fs afero.Fs, keyfile, name string, out io.Writer) {
	filename := repository.NamedKeystoreFile(keyfile)
	file, err := fs.Open(filename)
	if err != nil {
		panic(err)
	}

	keystore, err := repository.OpenKeystore(file)
	if err != nil {
		panic(err)
	}

	privkey, ok := keystore.FindPrivateKey(name)
	if ok {
		bytes := x509.MarshalPKCS1PrivateKey(privkey)
		err = pem.Encode(out, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: bytes})
		if err != nil {
			panic(err)
		}

		bytes, err = x509.MarshalPKIXPublicKey(privkey.Public())
		if err != nil {
			panic(err)
		}

		err = pem.Encode(out, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: bytes})
		if err != nil {
			panic(err)
		}

		return
	}

	pubkey, ok := keystore.FindPublicKey(name)
	if ok {
		bytes, err := x509.MarshalPKIXPublicKey(pubkey)
		if err != nil {
			panic(err)
		}

		err = pem.Encode(out, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: bytes})
		if err != nil {
			panic(err)
		}

		return
	}
}
