package main

import (
	"flag"
	"log"
	"os"
	"strings"

	"github.com/darcinc/afero"
	"github.com/darcinc/repository/commands"
)

var (
	action, archive string
	files, keystore string
	privkey, pubkey string
	directory       string
)

func about() {
	flag.Usage()
}

type arguments map[string]string

func packArguments() arguments {
	result := make(arguments)

	vals := []string{action, archive, files, keystore, privkey, pubkey, directory}
	keys := []string{"action", "archive", "files", "keystore", "privkey", "pubkey", "directory"}

	for i := range vals {
		result[keys[i]] = vals[i]
	}

	return result
}

func (a arguments) Action() string {
	return a["action"]
}

func (a arguments) Archive() string {
	return a["archive"]
}

func (a arguments) Files() string {
	return a["files"]
}

func (a arguments) FilesList() []string {
	return strings.Split(a["files"], ",")
}

func (a arguments) Keystore() string {
	return a["keystore"]
}

func (a arguments) PrivKey() string {
	return a["privkey"]
}

func (a arguments) PubKey() string {
	return a["pubkey"]
}

func (a arguments) Directory() string {
	return a["directory"]
}

// ValidateArguments checks to see that all arguments are correct.
func validateArguments() bool {
	args := packArguments()

	result := true
	switch action {
	case "pack":
		if args.Archive() == "" {
			log.Printf("Packing an archive requires a path to an archive")
			return false
		}
		if args.Files() == "" && args.Directory() == "" {
			log.Printf("Packing an archive requires a list of files or a directory")
			result = false
		}
		if args.PubKey() == "" {
			log.Printf("Packing an archive requires a key name")
			result = false
		}
		if args.PrivKey() == "" {
			log.Printf("Packing an archive requries a private key name")
			result = false
		}
	case "unpack":
		if args.Archive() == "" {
			log.Printf("When unpacking contents you must specify an archive")
			result = false
		}
		if args.PrivKey() == "" {
			log.Printf("When unpacking contents you must specify a key name")
			result = false
		}
		if args.PubKey() == "" {
			log.Printf("When unpacking contetns you must specify a public key")
			result = false
		}
	case "list":
		if args.Archive() == "" {
			log.Printf("When listing contents you must specify an archive")
			result = false
		}
		if args.PrivKey() == "" {
			log.Printf("When listing contents you must specify a key name")
			result = false
		}
		if args.PubKey() == "" {
			log.Printf("When listing contetns you must specify a public key")
			result = false
		}
	}
	return result
}

func main() {
	flag.StringVar(&action, "action", "about", "What to do (pack, unpack, list)")
	flag.StringVar(&archive, "archive", "", "The name of the archive (required for pack, unpack, and list)")
	flag.StringVar(&files, "files", "", "The comma separated list of files to pack (required for pack)")
	flag.StringVar(&privkey, "privkey", "", "The name of the private key to use (rquired for pack, unpack, and list)")
	flag.StringVar(&pubkey, "pubkey", "", "The name of the public key to use (required for pack, unpack, and list")
	flag.StringVar(&keystore, "keystore", "keys", "The name of the keystore containing the keys")
	flag.StringVar(&directory, "dir", "", "The optional directory containing the files to pack")
	flag.Parse()

	if !validateArguments() {
		log.Printf("Unable to continue, invalid or missing arguments")
		about()
		return
	}

	fs := afero.NewOsFs()

	switch action {
	case "pack":
		commands.PackRepository(fs, packArguments())
	case "unpack":
		commands.UnpackRepository(fs, archive, keystore, privkey, pubkey)
	case "list":
		commands.ListContents(fs, archive, keystore, pubkey, privkey, os.Stdout)
	case "about":
		flag.Usage()
	}
}
