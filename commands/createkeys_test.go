package commands

import (
	"os"
	"testing"
)

func TestCreateKeys(t *testing.T) {
	CreateKeys("DeleteKey", 2048)

	_, err := os.Stat("DeleteKey.key")
	if err != nil {
		t.Errorf("Error statting the private key file: %v", err)
	}

	_, err = os.Stat("DeleteKey-pub.key")
	if err != nil {
		t.Errorf("Error statting the public file: %v", err)
	}

	if err = os.Remove("DeleteKey.key"); err != nil {
		t.Errorf("Failed to remove the private key file: %v", err)
	}

	if err = os.Remove("DeleteKey-pub.key"); err != nil {
		t.Errorf("Failed to remove the public key file: %v", err)
	}
}
