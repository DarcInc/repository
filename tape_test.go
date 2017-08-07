package repository

import (
	"bytes"
	"log"
	"testing"
)

func TestCreateTape(t *testing.T) {
	buffer := new(bytes.Buffer)
	_, err := NewTapeWriter(Key{PublicKey: &testKey.PublicKey, PrivateKey: testKey}, buffer)
	if err != nil {
		log.Fatalf("Unable to write out repository: %v", err)
	}

	reader := bytes.NewReader(buffer.Bytes())
	_, err = OpenTape(testKey, &testKey.PublicKey, reader)
	if err != nil {
		log.Fatalf("Failed to open repository: %v", err)
	}
}
