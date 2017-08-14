package main

import (
	"flag"
	"log"
	"os"

	"github.com/darcinc/afero"
	"github.com/darcinc/repository/commands"
)

func about() {
	flag.Usage()
}

// ValidateArguments checks to see that all arguments are correct.
func validateArguments(action, archive, files, keystore, publicKey, privateKey string) bool {
	result := true
	switch action {
	case "pack":
		if archive == "" {
			log.Printf("Packing an archive requires a path to an archive")
			return false
		}
		if files == "" {
			log.Printf("Packing an archive requires a list of files")
			result = false
		}
		if publicKey == "" {
			log.Printf("Packing an archive requires a key name")
			result = false
		}
		if privateKey == "" {
			log.Printf("Packing an archive requries a private key name")
			result = false
		}
	case "unpack":
		if archive == "" {
			log.Printf("When unpacking contents you must specify an archive")
			result = false
		}
		if privateKey == "" {
			log.Printf("When unpacking contents you must specify a key name")
			result = false
		}
		if publicKey == "" {
			log.Printf("When unpacking contetns you must specify a public key")
			result = false
		}
	case "list":
		if archive == "" {
			log.Printf("When listing contents you must specify an archive")
			result = false
		}
		if privateKey == "" {
			log.Printf("When listing contents you must specify a key name")
			result = false
		}
		if publicKey == "" {
			log.Printf("When listing contetns you must specify a public key")
			result = false
		}
	}
	return result
}

func main() {
	var (
		action, archive string
		files, keystore string
		privkey, pubkey string
	)
	flag.StringVar(&action, "action", "about", "What to do (pack, unpack, list)")
	flag.StringVar(&archive, "archive", "", "The name of the archive (required for pack, unpack, and list)")
	flag.StringVar(&files, "files", "", "The comma separated list of files to pack (required for pack)")
	flag.StringVar(&privkey, "privkey", "", "The name of the private key to use (rquired for pack, unpack, and list)")
	flag.StringVar(&pubkey, "pubkey", "", "The name of the public key to use (required for pack, unpack, and list")
	flag.StringVar(&keystore, "keystore", "keys", "The name of the keystore containing the keys")
	flag.Parse()

	if !validateArguments(action, archive, files, pubkey, keystore, privkey) {
		log.Printf("Unable to continue, invalid or missing arguments")
		about()
		return
	}

	fs := afero.NewOsFs()

	switch action {
	case "pack":
		commands.PackRepository(fs, archive, files, keystore, pubkey, privkey)
	case "unpack":
		commands.UnpackRepository(fs, archive, keystore, privkey, pubkey)
	case "list":
		commands.ListContents(fs, archive, keystore, pubkey, privkey, os.Stdout)
	case "about":
		flag.Usage()
	}
}
