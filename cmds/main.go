package main

import (
	"flag"
	"log"

	"github.com/darcinc/repository/commands"
)

func about() {
	flag.Usage()
}

func main() {
	var (
		action, archive, files, publicKey, privateKey, keyName string
		keyfile                                                string
		cipherStrength                                         int
	)
	flag.StringVar(&action, "action", "about", "What to do (pack, list, unpack, create-keys, about)")
	flag.StringVar(&archive, "archive", "", "The name of the archive (required for pack, list, and unpack)")
	flag.StringVar(&files, "files", "", "Comma separated list of files (required for pack)")
	flag.StringVar(&publicKey, "publicKey", "", "Public key to use for encryption (required for pack)")
	flag.StringVar(&privateKey, "privateKey", "", "Private key to use for signing or decryption (required for pack and unpack)")
	flag.StringVar(&keyName, "keyName", "", "The name of the key (required for create key)")
	flag.StringVar(&keyfile, "keyFile", "keys", "The name of the keystore, can be the name or an absolute path")
	flag.IntVar(&cipherStrength, "bits", 4096, "The number of bits for the RSA key")

	flag.Parse()

	if !commands.ValidateArguments(action, archive, files, privateKey, publicKey, keyName) {
		log.Printf("Unable to continue")
		about()
		return
	}

	switch action {
	case "pack":
		commands.PackRepository(archive, files, publicKey, privateKey)
	case "list":
		commands.ListContents(archive)
	case "unpack":
		commands.UnpackRepository(archive, publicKey, privateKey)
	case "create-keys":
		commands.CreateKeys(keyName, keyfile, cipherStrength)
	case "about":
		about()
	}
}
