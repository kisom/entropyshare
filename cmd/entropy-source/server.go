package main

import (
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"

	"github.com/kisom/entropyshare/cmd/entropy-source/source"
	"github.com/kisom/entropyshare/prng"
)

var signer *rsa.PrivateKey

var config struct {
	targets string
	signer  string
}

func main() {
	flag.StringVar(&config.signer, "k", "signer.key", "signature key")
	seedFile := flag.String("s", "source.seed", "PRNG seed file")
	flag.StringVar(&config.targets, "t", "targets.json", "test targets")
	flag.Parse()

	in, err := ioutil.ReadFile(config.signer)
	if err != nil {
		log.Fatalf("%v", err)
	}
	signer, err := x509.ParsePKCS1PrivateKey(in)
	if err != nil {
		log.Fatalf("%v", err)
	}

	prng.Start(*seedFile)

	defer prng.StoreSeed()
	source.Start(signer, config.targets)
}
