package main

import (
	"bytes"

	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

var target struct {
	Address string
	Public  []byte
	Counter int64
	Next    int64 `json:",omitempty"`
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}
}
func main() {
	flag.StringVar(&target.Address, "a", "", "address of sink")
	flag.Int64Var(&target.Counter, "c", 0, "initial packet counter")
	flag.Int64Var(&target.Next, "t", 0, "initial update timestamp")
	keyFile := flag.String("k", "decrypt.pub", "sink's decryption public key")
	flag.Parse()

	if target.Address == "" {
		fmt.Fprintf(os.Stderr, "[!] no address provided.\n")
		os.Exit(1)
	}

	in, err := ioutil.ReadFile(*keyFile)
	checkError(err)

	if len(in) != 32 {
		fmt.Fprintf(os.Stderr, "[!] invalid Curve25519 public key.\n")
	}

	target.Public = in
	buf := &bytes.Buffer{}
	out, err := json.Marshal(target)
	checkError(err)

	err = json.Indent(buf, out, "", "\t")
	checkError(err)

	fmt.Printf("%s\n", buf.Bytes())

}
