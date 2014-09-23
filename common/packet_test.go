package common

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"code.google.com/p/go.crypto/nacl/box"
	"github.com/kisom/entropyshare/common/crypt"
)

const signerFile = "testdata/signer.key"

var (
	testPriv, testPub []byte
	signer            *rsa.PrivateKey
)

var testSizes bool

func init() {
	flag.BoolVar(&testSizes, "sizes", false, "print encoded packet sizes")
	flag.Parse()
}

func checkError(t *testing.T, err error) {
	if err != nil {
		panic(err.Error())
		t.Fatalf("%v", err)
	}
}

func TestLoadKeys(t *testing.T) {
	in, err := ioutil.ReadFile(signerFile)
	checkError(t, err)

	signer, err = x509.ParsePKCS1PrivateKey(in)
	checkError(t, err)

	pub, priv, err := box.GenerateKey(rand.Reader)
	checkError(t, err)

	testPriv = make([]byte, 32)
	testPub = make([]byte, 32)
	copy(testPriv, priv[:])
	copy(testPub, pub[:])
}

var testPacket []byte

func TestSerialiseWire(t *testing.T) {
	var err error
	p := &Packet{}
	testPacket, err = SerialiseWire(p, testPub, signer)
	checkError(t, err)
}

func TestParsePacket(t *testing.T) {
	_, err := ParsePacket(testPacket, testPriv, &signer.PublicKey)
	checkError(t, err)
}

var testRawPacket *Packet
var senderCounter, receiverCounter int64

func TestNewPacket(t *testing.T) {
	var err error
	senderCounter, testRawPacket, err = NewPacket(30, rand.Reader)
	checkError(t, err)

	if senderCounter != 31 {
		t.Fatalf("Counter: expected 31, have %d", senderCounter)
	}

	testPacket, err = SerialiseWire(testRawPacket, testPub, signer)
	checkError(t, err)
}

func TestUnsignedPacket(t *testing.T) {
	out, err := SerialiseWire(testRawPacket, testPub, nil)
	checkError(t, err)

	_, err = ParsePacket(out, testPriv, nil)
	if err != ErrUnsignedPacket {
		t.Fatal("unsigned packet should be rejected")
	}
}

func TestParseAndWritePacket(t *testing.T) {
	var buf = &bytes.Buffer{}
	var err error

	drift := time.Now().Unix() - testRawPacket.Timestamp + 1
	receiverCounter, err = ParseAndWritePacket(testPacket, testPriv, &signer.PublicKey, drift, 0, buf)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Make sure that counter regression is caught.
	receiverCounter, err = ParseAndWritePacket(testPacket, testPriv, &signer.PublicKey, drift, receiverCounter, buf)
	if err != ErrCounter {
		t.Fatal("counter regression should be rejected")
	}
}

func TestTimestamping(t *testing.T) {
	var err error
	var buf = &bytes.Buffer{}

	// Delay to push the clock drift check.
	<-time.After(2 * time.Second)
	// Ensure clock drift is caught.
	var drift int64 = 1
	_, err = ParseAndWritePacket(testPacket, testPriv, &signer.PublicKey, drift, receiverCounter-1, buf)
	if err != ErrTimestamp {
		t.Fatal("packet should be outside acceptable clock drift")
	}

	_, p, err := NewPacket(0, rand.Reader)
	checkError(t, err)

	p.Timestamp = time.Now().Unix() + drift + 1
	out, err := SerialiseWire(p, testPub, signer)
	checkError(t, err)

	_, err = ParseAndWritePacket(out, testPriv, &signer.PublicKey, drift, 0, buf)
	if err != ErrTimestamp {
		t.Fatalf("packet should be outside acceptable clock drift", err)
	}

	p.Timestamp = time.Now().Unix() - drift - 1
	out, err = SerialiseWire(p, testPub, signer)
	checkError(t, err)

	_, err = ParseAndWritePacket(out, testPriv, &signer.PublicKey, drift, 0, buf)
	if err != ErrTimestamp {
		t.Fatalf("packet should be outside acceptable clock drift", err)
	}

}

func TestCounterProgression(t *testing.T) {
	var err error
	var buf = &bytes.Buffer{}

	senderCounter, testRawPacket, err = NewPacket(senderCounter, rand.Reader)
	checkError(t, err)

	testPacket, err = SerialiseWire(testRawPacket, testPub, signer)
	checkError(t, err)

	drift := time.Now().Unix() - testRawPacket.Timestamp + 1
	receiverCounter, err = ParseAndWritePacket(testPacket, testPriv, &signer.PublicKey, drift, receiverCounter, buf)
	checkError(t, err)
}

func TestCounterPreserved(t *testing.T) {
	r := &bytes.Buffer{}

	counter, packet, err := NewPacket(senderCounter, r)
	if err == nil {
		fmt.Println(hex.Dump(packet.Chunk[:]))
		t.Fatal("expected call to NewPacket to fail")
	}

	if counter != senderCounter {
		t.Fatal("counter should not have been incremented on error")
	}

	if packet != nil {
		t.Fatal("no packet should have been returned")
	}
}

func TestCryptFails(t *testing.T) {
	_, err := SerialiseWire(testRawPacket, nil, nil)
	if err == nil {
		t.Fatal("serialisation should fail without a public key")
	}

	_, err = ParsePacket(testPacket, nil, nil)
	if err == nil {
		t.Fatal("parsing should fail without a private key")
	}

	_, err = ParseAndWritePacket(testPacket, nil, nil, 0, 0, nil)
	if err == nil {
		t.Fatal("parsing should fail without a private key")
	}
}

func TestPacketSizes(t *testing.T) {
	asnPacket := packet{
		testRawPacket.Timestamp,
		testRawPacket.Counter,
		testRawPacket.Chunk[:],
	}
	packet, err := asn1.Marshal(asnPacket)
	checkError(t, err)

	jpacket, err := json.Marshal(asnPacket)
	checkError(t, err)

	jout, err := crypt.Encrypt(jpacket, testPub, signer)
	checkError(t, err)

	buf := &bytes.Buffer{}
	enc := gob.NewEncoder(buf)
	err = enc.Encode(asnPacket)
	checkError(t, err)
	gpacket := buf.Bytes()

	gout, err := crypt.Encrypt(gpacket, testPub, signer)
	checkError(t, err)

	fmt.Println("              ASN.1 packet length:", len(packet))
	fmt.Println("               JSON packet length:", len(jpacket))
	fmt.Println("                Gob packet length:", len(gpacket))
	fmt.Println("Signed and encrypted ASN.1 length:", len(testPacket))
	fmt.Println(" Signed and encrypted JSON length:", len(jout))
	fmt.Println("  Signed and encrypted gob length:", len(gout))
}
