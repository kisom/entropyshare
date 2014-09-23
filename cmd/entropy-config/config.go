package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

var config struct {
	Address string
	Signer  []byte
	Counter int64
	Private []byte
	Drift   int64
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}
}

func main() {
	flag.StringVar(&config.Address, "a", ":9437", "listener address")
	keyFile := flag.String("k", "decrypt.key", "key file for decryption")
	signerFile := flag.String("s", "signer.pub", "signer's public key")
	flag.Int64Var(&config.Drift, "d", 120, "clock drift value")
	flag.Parse()

	in, err := ioutil.ReadFile(*keyFile)
	checkError(err)

	if len(in) != 32 {
		fmt.Fprintf(os.Stderr, "[!] bad Curve25519 private key.\n")
	}
	config.Private = in

	in, err = ioutil.ReadFile(*signerFile)
	checkError(err)

	pub, err := x509.ParsePKIXPublicKey(in)
	checkError(err)

	if _, ok := pub.(*rsa.PublicKey); !ok {
		fmt.Fprintf(os.Stderr, "[!] signer isn't a valid DER-encoded PKIX RSA public key")
		os.Exit(1)
	}

	config.Signer = in

	buf := &bytes.Buffer{}
	out, err := json.Marshal(config)
	checkError(err)

	err = json.Indent(buf, out, "", "\t")
	checkError(err)

	fmt.Printf("%s\n", buf.Bytes())
}
