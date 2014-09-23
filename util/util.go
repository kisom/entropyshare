package util

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
)

func ParseCertificate(path string) *x509.Certificate {
	in, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("%v", err)
	}

	if p, _ := pem.Decode(in); p != nil {
		if p.Type != "CERTIFICATE" {
			log.Fatalf("invalid certificate (type is %s)",
				p.Type)
		}
		in = p.Bytes
	}
	cert, err := x509.ParseCertificate(in)
	if err != nil {
		log.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}

func ParsePrivateKey(path string) *rsa.PrivateKey {
	in, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("%v", err)
	}

	if p, _ := pem.Decode(in); p != nil {
		if p.Type != "PRIVATE KEY" && p.Type != "RSA PRIVATE KEY" {
			log.Fatalf("invalid private key (type is %s)",
				p.Type)
		}
		in = p.Bytes
	}
	priv, err := x509.ParsePKCS1PrivateKey(in)
	if err != nil {
		log.Fatalf("failed to parse certificate: %v", err)
	}
	return priv
}

func ParsePublicKey(path string) *rsa.PublicKey {
	in, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("%v", err)
	}

	if p, _ := pem.Decode(in); p != nil {
		if p.Type != "PUBLIC KEY" && p.Type != "RSA PUBLIC KEY" {
			log.Fatalf("invalid public key (type is %s)",
				p.Type)
		}
		in = p.Bytes
	}
	pub, err := x509.ParsePKIXPublicKey(in)
	if err != nil {
		log.Fatalf("failed to parse certificate: %v", err)
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub
	default:
		log.Fatalf("only RSA public keys are supported")
		return nil
	}
}
