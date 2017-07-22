package commands

import (
	"os"

	"github.com/darcinc/afero"
	"github.com/darcinc/repository"
)

func DeleteKeys(fs afero.Fs, keyfile, name string) {
	filename := repository.NamedKeystoreFile(keyfile)
	file, err := fs.Open(filename)
	if err != nil {
		panic(err)
	}

	keystore, err := repository.OpenKeystore(file)
	if err != nil {
		panic(err)
	}
	file.Close()

	keystore.RemoveKey(name)

	file, err = fs.OpenFile(filename, os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	keystore.Save(file)
}
