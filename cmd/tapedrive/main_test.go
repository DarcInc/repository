package main

import "testing"

func TestValidatePack(t *testing.T) {
	if !validateArguments("pack", "myarchive", "foo,bar", "keystore", "pubkey", "privkey") {
		t.Error("Should have validated a valid call to pack an archive")
	}

	if validateArguments("pack", "", "foo,bar", "keystore", "pubkey", "privkey") {
		t.Error("Should not have validated a call to pack without an archive path")
	}

	if validateArguments("pack", "archive", "", "keystore", "pubkey", "privkey") {
		t.Error("Should not have validated a call to pack without files")
	}

	if validateArguments("pack", "archive", "foo,bar", "keystore", "", "privkey") {
		t.Error("Should not have validated a call to pack without a public key")
	}

	if validateArguments("pack", "archive", "foo,bar", "keystore", "pubkey", "") {
		t.Error("Should not have validated a call to pack without a private key")
	}
}

func TestValidateUnpack(t *testing.T) {
	if !validateArguments("unpack", "myarchive", "", "", "pubkey", "privkey") {
		t.Error("Should have validated a valid call to unpack an archive")
	}

	if validateArguments("unpack", "", "", "", "pubkey", "privkey") {
		t.Error("Should not validate a call to unpack without an archive")
	}

	if validateArguments("unpack", "archive", "", "", "", "privkey") {
		t.Error("Should not validate a call to unpack without a public key")
	}

	if validateArguments("unpack", "archive", "", "", "pubkey", "") {
		t.Error("Should not validate a call to unpack without a private key")
	}
}

func TestValidateList(t *testing.T) {
	if !validateArguments("list", "myarchive", "", "", "pubkey", "privkey") {
		t.Error("Should have validated a valid call to list an archive")
	}

	if validateArguments("list", "", "", "", "pubkey", "privkey") {
		t.Error("Should not validate a call to list without an archive")
	}

	if validateArguments("list", "myarchive", "", "", "", "privkey") {
		t.Error("Should not validate a call to list without a public key")
	}

	if validateArguments("list", "myarchive", "", "", "pubkey", "") {
		t.Error("Should not validate a call to list without a private key")
	}
}
