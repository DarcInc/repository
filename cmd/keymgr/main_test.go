package main

import "testing"

func TestValidateAbout(t *testing.T) {
	if !validateArguments("about", "", "", "", 0) {
		t.Error("Failed to return true for about validation")
	}
}

func TestValidateCreate(t *testing.T) {
	if !validateArguments("create", "mykey", "foo", "", 2048) {
		t.Error("Failed to return true for valid create validation")
	}

	if validateArguments("create", "", "foo", "", 2048) {
		t.Error("Returned true when validating create without keyname")
	}
}

func TestValidateImport(t *testing.T) {
	if !validateArguments("import", "mykey", "foo", "import.pem", 0) {
		t.Error("Returned false with valid import validate")
	}

	if validateArguments("import", "", "foo", "import.pem", 0) {
		t.Error("Returned true with invalid import validate")
	}

	if validateArguments("import", "mykey", "foo", "", 0) {
		t.Error("Returned true with invalid import validate")
	}
}

func TestValidateExport(t *testing.T) {
	if !validateArguments("export", "mykey", "foo", "export.pem", 0) {
		t.Error("Returned false with valid export validate")
	}

	if validateArguments("export", "", "foo", "export.pem", 0) {
		t.Error("Returned true with invalid export validate")
	}
}

func TestValidateList(t *testing.T) {
	if !validateArguments("list", "", "", "", 0) {
		t.Error("Returned false with valid list validate")
	}
}

func TestValidCipherStrength(t *testing.T) {
	validStrengths := []int{1024, 2048, 4096, 8192}
	for _, v := range validStrengths {
		if !validateArguments("create", "mykey", "", "", v) {
			t.Errorf("Failed to validate valid cipher strength of %d", v)
		}
	}

	invalidStrengths := []int{-100, 0, 9000000000}
	for _, v := range invalidStrengths {
		if validateArguments("create", "mykey", "", "", v) {
			t.Errorf("Validated invalid key strength")
		}
	}
}
