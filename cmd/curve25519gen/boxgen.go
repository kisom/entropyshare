package main

import (
	"crypto/rand"

	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"

	"code.google.com/p/go.crypto/nacl/box"
)

func main() {
	armour := flag.Bool("a", false, "armour key")
	outFile := flag.String("o", "signer", "output file base name")
	flag.Parse()

	if *outFile == "" {
		log.Fatal("no output base filename specified")
	}

	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("%v", err)
	}

	dumpPrivate(priv, *outFile, *armour)
	dumpPublic(pub, *outFile, *armour)
}

func dumpPrivate(priv *[32]byte, baseName string, armour bool) {
	out := priv[:]
	if armour {
		p := &pem.Block{
			Type:  "CURVE25519 PRIVATE KEY",
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

func dumpPublic(pub *[32]byte, baseName string, armour bool) {
	out := pub[:]
	if armour {
		p := &pem.Block{
			Type:  "CURVE25519 PUBLIC KEY",
			Bytes: out,
		}
		out = pem.EncodeToMemory(p)
	}

	err := ioutil.WriteFile(baseName+".pub", out, 0644)
	if err != nil {
		log.Fatalf("%v", err)
	}
	log.Printf("wrote public key to %s.pub", baseName)
}
