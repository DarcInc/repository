package repository

import (
	"bytes"
	"crypto/rsa"
	"log"
	"testing"
)

func TestWriteHeader(t *testing.T) {

	for _, k := range keys {
		func(pk *rsa.PrivateKey) {
			l := Label{AesKey: testAes, iv: testIv}
			buffer := new(bytes.Buffer)

			err := l.writeHeader(buffer, &pk.PublicKey)
			if err != nil {
				t.Fatalf("Unable to write bytes: %v", err)
			}

			if len(buffer.Bytes()) != pk.N.BitLen()/8 {
				t.Errorf("Expected %d bytes but got %d", pk.N.BitLen()/8, len(buffer.Bytes()))
			}
		}(k)
	}

}

func TestReadHeader(t *testing.T) {

	for _, k := range keys {
		func(pk *rsa.PrivateKey) {
			l := Label{AesKey: testAes, iv: testIv}
			buffer := new(bytes.Buffer)

			err := l.writeHeader(buffer, &pk.PublicKey)
			if err != nil {
				t.Fatalf("Unable to write bytes: %v", err)
			}

			l2 := Label{}
			l2.readHeader(bytes.NewBuffer(buffer.Bytes()), pk)

			for i := range l2.AesKey {
				if l2.AesKey[i] != l.AesKey[i] {
					log.Fatalf("Mismatched AES keys in TestReadHeader")
				}
			}
		}(k)
	}
}

func TestSignAndVerify(t *testing.T) {
	for _, k := range keys {
		func(pk *rsa.PrivateKey) {
			l := Label{AesKey: testAes, iv: testIv}
			buffer := new(bytes.Buffer)

			err := l.writeSignature(buffer, pk)
			if err != nil {
				t.Fatalf("Unable to write signature: %v", err)
			}

			err = l.verifySignature(bytes.NewBuffer(buffer.Bytes()), &pk.PublicKey)
			if err != nil {
				t.Fatalf("Failed to verify signature: %v", err)
			}
		}(k)
	}
}

func TestReadWriteLabel(t *testing.T) {
	for _, k := range keys {
		func(pk *rsa.PrivateKey) {
			l := Label{AesKey: testAes, iv: testIv}
			buffer := new(bytes.Buffer)

			err := l.WriteLabel(buffer, &pk.PublicKey, pk)
			if err != nil {
				t.Fatalf("Failed to write label: %v", err)
			}

			l2, err := ReadLabel(bytes.NewBuffer(buffer.Bytes()), pk, &pk.PublicKey)
			if err != nil {
				t.Fatalf("Failed to read label: %v", err)
			}

			if string(l.AesKey) != string(l2.AesKey) {
				t.Errorf("Key mismatch: expected %s but got %s", string(l.AesKey), string(l2.AesKey))
			}
		}(k)
	}
}

func TestOpenWriter(t *testing.T) {
	for _, k := range keys {
		func(pk *rsa.PrivateKey) {
			l := Label{AesKey: testAes, iv: testIv}
			buffer := new(bytes.Buffer)
			wr, err := l.OpenWriter(buffer)
			if err != nil {
				t.Fatalf("Failed to open writer: %v", err)
			}

			wr.Write([]byte("Hello World"))

			if string(buffer.Bytes()) == "Hello World" {
				t.Fatalf("Didn't encrypt the data")
			}

			rd, err := l.OpenReader(bytes.NewBuffer(buffer.Bytes()))
			if err != nil {
				t.Fatalf("Error opening new reader from label: %v", err)
			}

			temp := make([]byte, len(buffer.Bytes()))
			rd.Read(temp)
			if string(temp) != "Hello World" {
				t.Errorf("Failed to decrypt data: expected 'Hello World' but got %s", string(temp))
			}
		}(k)
	}
}
