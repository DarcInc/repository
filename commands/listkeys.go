package commands

import (
	"fmt"
	"io"
	"os"

	"github.com/darcinc/afero"
	"github.com/darcinc/repository"
)

func listKeys(fs afero.Fs, keyfile string, out io.Writer) {
	filename := repository.NamedKeystoreFile(keyfile)
	_, err := fs.Stat(filename)
	if err != nil {
		fmt.Fprintf(out, "No such repository: %s", keyfile)
		return
	}

	file, err := fs.Open(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	keys, err := repository.OpenKeystore(file)
	if err != nil {
		panic(err)
	}

	fmt.Fprintf(out, "Private Keys:\n")
	for k := range keys.PrivateKeys {
		fmt.Fprintf(out, "  %s\n", k)
	}

	fmt.Fprintf(out, "Public Keys: \n")
	for k := range keys.PublicKeys {
		fmt.Fprintf(out, "  %s\n", k)
	}
}

// ListKeys prints all the key names
func ListKeys(fs afero.Fs, keyfile string) {
	listKeys(fs, keyfile, os.Stdout)
}
