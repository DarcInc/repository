package commands

import (
	"crypto/rsa"
	"errors"

	"github.com/darcinc/afero"
	"github.com/darcinc/repository"
)

func readKeysFromKeystore(fs afero.Fs, keystoreName, privKeyName, pubKeyName string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	keystorePath := repository.KeystorePath(keystoreName)

	file, err := fs.Open(keystorePath)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	keystore, err := repository.OpenKeystore(file)
	if err != nil {
		return nil, nil, err
	}

	privateKey, ok := keystore.FindPrivateKey(privKeyName)
	if !ok {
		return nil, nil, errors.New("Private key not found error")
	}

	publicKey, ok := keystore.FindPublicKey(pubKeyName)
	if !ok {
		return nil, nil, errors.New("Public key not found error")
	}

	return privateKey, publicKey, nil
}
