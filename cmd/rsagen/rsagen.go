package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"

	"github.com/kisom/entropyshare/util"
)

func main() {
	armour := flag.Bool("a", false, "armour key")
	keyFile := flag.String("key", "", "key file to dump public key from")
	outFile := flag.String("o", "signer", "output file base name")
	keySize := flag.Int("s", 2048, "RSA key size")
	flag.Parse()

	if *keyFile != "" {
		priv := util.ParsePrivateKey(*keyFile)
		dumpPublic(priv, *outFile, *armour)
		return
	}

	if *outFile == "" {
		log.Fatal("no output base filename specified")
	}

	priv, err := rsa.GenerateKey(rand.Reader, *keySize)
	if err != nil {
		log.Fatalf("%v", err)
	}

	dumpPrivate(priv, *outFile, *armour)
	dumpPublic(priv, *outFile, *armour)
}

func dumpPrivate(priv *rsa.PrivateKey, baseName string, armour bool) {
	out := x509.MarshalPKCS1PrivateKey(priv)
	if armour {
		p := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: out,
		}
		out = pem.EncodeToMemory(p)
	}

	err := ioutil.WriteFile(baseName+".key", out, 0600)
	if err != nil {
		log.Fatalf("%v", err)
	}
	log.Printf("wrote private key to %s.key", baseName)
}

func dumpPublic(priv *rsa.PrivateKey, baseName string, armour bool) {
	out, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		log.Fatalf("%v", err)
	}

	if armour {
		p := &pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: out,
		}
		out = pem.EncodeToMemory(p)
	}

	err = ioutil.WriteFile(baseName+".pub", out, 0644)
	if err != nil {
		log.Fatalf("%v", err)
	}
	log.Printf("wrote public key to %s.pub", baseName)
}
