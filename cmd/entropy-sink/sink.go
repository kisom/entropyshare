package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"

	"github.com/kisom/entropyshare/common"
)

var config struct {
	Address string
	Signer  []byte
	Counter int64
	Private []byte
	Drift   int64
}

var state struct {
	Signer  *rsa.PublicKey
	Counter int64
	PRNG    io.WriteCloser
}

func loadState(filespec string) error {
	in, err := ioutil.ReadFile(filespec)
	if err != nil {
		return err
	}

	err = json.Unmarshal(in, &config)
	if err != nil {
		return err
	}

	state.Counter = config.Counter
	signer, err := x509.ParsePKIXPublicKey(config.Signer)
	if err != nil {
		return err
	}

	var ok bool
	state.Signer, ok = signer.(*rsa.PublicKey)
	if !ok {
		return errors.New("invalid public key")
	}
	return nil
}

func writeState(filespec string) error {
	config.Counter = state.Counter
	out, err := json.Marshal(config)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filespec, out, 0644)
}

func receive(conn net.Conn) {
	defer conn.Close()

	log.Println("new packet from", conn.RemoteAddr())
	var b [2]byte
	_, err := conn.Read(b[:])
	if err != nil {
		log.Printf("%s %v", conn.RemoteAddr(), err)
		return
	}

	l := binary.BigEndian.Uint16(b[:])
	packet := make([]byte, int(l))
	_, err = io.ReadFull(conn, packet)
	if err != nil {
		log.Printf("%s %v", conn.RemoteAddr(), err)
		return
	}

	state.Counter, err = common.ParseAndWritePacket(packet, config.Private,
		state.Signer, config.Drift, state.Counter, state.PRNG)
	if err != nil {
		log.Printf("%s %v", conn.RemoteAddr(), err)
		return
	}

	log.Println("successfully wrote packet")
}

func server(filespec string) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", config.Address)
	if err != nil {
		log.Fatalf("%v", err)
	}

	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		log.Fatalf("%v", err)
	}

	log.Println("listening on", config.Address)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("%v", err)
		}

		receive(conn)
		err = writeState(filespec)
		if err != nil {
			log.Printf("%v", err)
		}
	}
}

func main() {
	cfgFile := flag.String("f", "config.json", "configuration file")
	flag.Parse()

	err := loadState(*cfgFile)
	if err != nil {
		log.Fatalf("%v", err)
	}

	state.PRNG, err = os.OpenFile("/dev/random", os.O_WRONLY, 0)
	if err != nil {
		log.Fatalf("%v", err)
	}
	server(*cfgFile)
}
