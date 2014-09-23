package crypt

import (
	"crypto"
	"io"

	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"

	"code.google.com/p/go.crypto/nacl/box"
)

const symKeyLen = 32

type signed struct {
	Message   []byte
	Signature []byte
}

// NonceSize contains the size, in bytes, of a NaCl nonce.
const nonceSize = 24

// NewNonce generates a new random nonce for use with NaCl. This is a
// 192-bit random number. In this set of utilities, only one nonce is
// ever actually used with a key in most cases.
func newNonce() *[nonceSize]byte {
	var nonce [nonceSize]byte
	p := RandBytes(nonceSize)
	if p == nil {
		return nil
	}
	copy(nonce[:], p)
	return &nonce
}

// RandBytes is a wrapper for retrieving a buffer of the requested
// size, filled with random data. On failure, it returns nil.
func RandBytes(size int) []byte {
	p := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, p)
	if err != nil {
		p = nil
	}
	return p
}

func Encrypt(message []byte, peer []byte, signer *rsa.PrivateKey) ([]byte, error) {
	if peer == nil {
		return nil, errors.New("crypt: no public key provided")
	}

	var pub [32]byte
	copy(pub[:], peer)

	var signed signed
	var err error

	signed.Message = message
	if signer != nil {
		digest := sha256.Sum256(message)
		signed.Signature, err = rsa.SignPSS(rand.Reader, signer, crypto.SHA256, digest[:], nil)
		if err != nil {
			return nil, err
		}
	}

	sm, err := asn1.Marshal(signed)
	if err != nil {
		return nil, err
	}

	epub, epriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	out := epub[:]
	nonce := newNonce()
	out = append(out, nonce[:]...)
	out = box.Seal(out, sm, nonce, &pub, epriv)
	return out, nil
}

const msgStart = 32 + nonceSize
const overhead = 32 + nonceSize + box.Overhead

func Decrypt(ciphertext []byte, priv []byte, signer *rsa.PublicKey) ([]byte, bool, error) {
	var signedMessage bool

	if priv == nil {
		return nil, false, errors.New("crypt: no private key provided")
	}

	if len(ciphertext) < (32 + nonceSize + box.Overhead) {
		return nil, false, errors.New("crypt: invalid box size")
	}

	var pub [32]byte
	copy(pub[:], ciphertext[:32])

	var nonce [nonceSize]byte
	copy(nonce[:], ciphertext[32:])

	var decrypt [32]byte
	copy(decrypt[:], priv)

	out, ok := box.Open(nil, ciphertext[msgStart:], &nonce, &pub, &decrypt)
	if !ok {
		return nil, false, errors.New("crypt: decryption failure")
	}

	var signed signed
	_, err := asn1.Unmarshal(out, &signed)
	if err != nil {
		return nil, false, err
	}

	if len(signed.Signature) != 0 {
		digest := sha256.Sum256(signed.Message)
		err = rsa.VerifyPSS(signer, crypto.SHA256, digest[:], signed.Signature, nil)
		if err != nil {
			return nil, false, err
		}
		signedMessage = true
	}
	return signed.Message, signedMessage, nil
}
