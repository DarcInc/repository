package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/darcinc/afero"
	"github.com/darcinc/repository/commands"
)

func about() {
	flag.Usage()
}

func validateArguments(action, keyname, keyfile, pemfile string, cipherStrength int) bool {
	switch {
	case action == "about":
		about()
	case action == "import":
		if keyname == "" {
			fmt.Println("A key name for the imported key is required when importing a key.")
			return false
		}
		if pemfile == "" {
			fmt.Println("The pem file to import is required when importing a key.")
			return false
		}

	case action == "export":
		if keyname == "" {
			fmt.Println("The name of the key to export is required.")
			return false
		}
	case action == "create":
		if keyname == "" {
			fmt.Println("The name of the key is required when creating a new key")
			return false
		}
		if !(cipherStrength == 1024 || cipherStrength == 2048 || cipherStrength == 4096 || cipherStrength == 8192) {
			fmt.Println("Valid bits for cipher strength are 1024 (not recommended), 2048, 4096, or 8192")
			return false
		}
	}

	return true
}

func main() {
	var (
		action, keyName  string
		keyfile, pemfile string
		cipherStrength   int
	)
	flag.StringVar(&action, "action", "about", "What to do (create, list, export, import)")
	flag.StringVar(&keyName, "keyName", "", "The name of the key (required for create or import key)")
	flag.StringVar(&keyfile, "keyFile", "keys", "The name of the keystore, can be the name or an absolute path")
	flag.StringVar(&pemfile, "pemFile", "", "The pem encoded key file to import")
	flag.IntVar(&cipherStrength, "bits", 4096, "The number of bits for the RSA key")

	flag.Parse()

	if !validateArguments(action, keyName, keyfile, pemfile, cipherStrength) {
		log.Printf("Unable to continue, invalid or missing arguments")
		about()
		return
	}

	fs := afero.NewOsFs()

	switch action {
	case "create":
		commands.CreateKeys(fs, keyName, keyfile, cipherStrength)
	case "list":
		commands.ListKeys(fs, keyfile)
	case "import":
		commands.ImportKey(fs, keyfile, keyName, pemfile)
	case "export":
		commands.ExtractKeys(fs, keyfile, keyName, pemfile)
	case "about":
		about()
	}
}
