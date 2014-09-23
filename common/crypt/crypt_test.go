package crypt

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"io/ioutil"
	"testing"
)

var crypt, signer *rsa.PrivateKey

const (
	cryptFile  = "testdata/crypt.key"
	signerFile = "testdata/signer.key"
)

var (
	cryptSHA256 = []byte{
		0xbe, 0x2b, 0x07, 0x17, 0x52, 0xe2, 0x3f, 0x06,
		0x69, 0xda, 0x7b, 0x75, 0x5d, 0x2b, 0xc4, 0x7d,
		0x75, 0x34, 0xe2, 0x24, 0xd3, 0xab, 0x3a, 0xe0,
		0x12, 0x04, 0xe3, 0x75, 0xd9, 0xb2, 0x54, 0x86,
	}

	signerSHA256 = []byte{
		0xdd, 0xc9, 0x76, 0xc7, 0x8f, 0x0e, 0x01, 0x43,
		0x9c, 0xc6, 0x2a, 0x67, 0xdb, 0xfd, 0x57, 0x0c,
		0xf2, 0xe4, 0xf9, 0x10, 0x42, 0xec, 0x53, 0x79,
		0xb7, 0x20, 0xef, 0x56, 0x6b, 0x00, 0xe6, 0x2e,
	}
)

func checkError(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestLoadKeys(t *testing.T) {
	in, err := ioutil.ReadFile(cryptFile)
	checkError(t, err)

	crypt, err = x509.ParsePKCS1PrivateKey(in)
	checkError(t, err)
	digest := sha256.Sum256(in)
	if !bytes.Equal(digest[:], cryptSHA256) {
		t.Fatal("crypt: invalid digest for encryption key")
	}

	in, err = ioutil.ReadFile(signerFile)
	checkError(t, err)

	signer, err = x509.ParsePKCS1PrivateKey(in)
	checkError(t, err)
	digest = sha256.Sum256(in)
	if !bytes.Equal(digest[:], signerSHA256) {
		t.Fatal("crypt: invalid digest for signature key")
	}
}

var testCiphertext []byte
var testMessage = []byte("Do not go gently into that good night\nRage, rage against the dying of the light.")

func TestEncryptNoSign(t *testing.T) {
	var err error
	testCiphertext, err = Encrypt(testMessage, &crypt.PublicKey, nil)
	checkError(t, err)
}

func TestDecryptNoSign(t *testing.T) {
	msg, signed, err := Decrypt(testCiphertext, crypt, nil)
	checkError(t, err)

	if signed {
		t.Fatal("crypt: message was marked as signed, but it wasn't signed")
	}

	if !bytes.Equal(msg, testMessage) {
		t.Fatal("crypt: decrypted message doesn't match the original message")
	}
}

func TestEncryptSign(t *testing.T) {
	var err error
	testCiphertext, err = Encrypt(testMessage, &crypt.PublicKey, signer)
	checkError(t, err)
}

func TestDecryptSign(t *testing.T) {
	msg, signed, err := Decrypt(testCiphertext, crypt, &signer.PublicKey)
	checkError(t, err)

	if !signed {
		t.Fatal("crypt: message should be marked as signed, but isn't")
	}

	if !bytes.Equal(msg, testMessage) {
		t.Fatal("crypt: decrypted message doesn't match the original message")
	}
}
