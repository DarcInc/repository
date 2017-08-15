package main

import "testing"

func TestPackArguments(t *testing.T) {
	action = "pack"
	archive = "myarchive"
	files = "foo,bar"
	keystore = "keystore"
	pubkey = "pubkey"
	privkey = "privkey"
	directory = "directory"

	args := packArguments()
	if args.Action() != action {
		t.Errorf("Expected %s but got %s", action, args.Action())
	}

	if args.Archive() != archive {
		t.Errorf("Expected %s but got %s", archive, args.Archive())
	}

	if args.Files() != files {
		t.Errorf("Expected %s but got %s", files, args.Files())
	}

	allfiles := args.FilesList()
	if allfiles[0] != "foo" || allfiles[1] != "bar" {
		t.Errorf("Got %s %s instead of foo bar", allfiles[0], allfiles[1])
	}

	if args.Keystore() != keystore {
		t.Errorf("Expected %s but got %s", keystore, args.Keystore())
	}

	if args.PubKey() != pubkey {
		t.Errorf("Expected %s but got %s", pubkey, args.PubKey())
	}

	if args.PrivKey() != privkey {
		t.Errorf("Expected %s but got %s", privkey, args.PrivKey())
	}

	if args.Directory() != directory {
		t.Errorf("Expected %s but got %s", directory, args.Directory())
	}
}

func TestValidatePack(t *testing.T) {
	action = "pack"
	archive = "myarchive"
	files = "foo,bar"
	keystore = "keystore"
	pubkey = "pubkey"
	privkey = "privkey"
	directory = ""

	if !validateArguments() {
		t.Error("Should have validated a valid call to pack an archive")
	}

	directory = "foo"
	files = ""
	if !validateArguments() {
		t.Error("Should have validated a valid call to pack an archive")
	}

	files = "foo,bar"
	archive = ""
	if validateArguments() {
		t.Error("Should not have validated a call to pack without an archive path")
	}

	archive = "myarchive"
	files = ""
	directory = ""
	if validateArguments() {
		t.Error("Should not have validated a call to pack without files or directory")
	}

	files = "foo,bar"
	pubkey = ""
	if validateArguments() {
		t.Error("Should not have validated a call to pack without a public key")
	}

	pubkey = "pubkey"
	privkey = ""
	if validateArguments() {
		t.Error("Should not have validated a call to pack without a private key")
	}
}

func TestValidateUnpack(t *testing.T) {
	action = "unpack"
	archive = "myarchive"
	keystore = ""
	files = ""
	pubkey = "pubkey"
	privkey = "privkey"

	if !validateArguments() {
		t.Error("Should have validated a valid call to unpack an archive")
	}

	archive = ""
	if validateArguments() {
		t.Error("Should not validate a call to unpack without an archive")
	}

	archive = "myarchive"
	pubkey = ""
	if validateArguments() {
		t.Error("Should not validate a call to unpack without a public key")
	}

	pubkey = "pubkey"
	privkey = ""
	if validateArguments() {
		t.Error("Should not validate a call to unpack without a private key")
	}
}

func TestValidateList(t *testing.T) {
	action = "list"
	archive = "myarchive"
	keystore = ""
	files = ""
	pubkey = "pubkey"
	privkey = "privkey"

	if !validateArguments() {
		t.Error("Should have validated a valid call to list an archive")
	}

	archive = ""
	if validateArguments() {
		t.Error("Should not validate a call to list without an archive")
	}

	archive = "myarchive"
	pubkey = ""
	if validateArguments() {
		t.Error("Should not validate a call to list without a public key")
	}

	pubkey = "pubkey"
	privkey = ""
	if validateArguments() {
		t.Error("Should not validate a call to list without a private key")
	}
}
