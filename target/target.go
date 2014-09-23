package target

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"log"
	"net"

	"github.com/kisom/entropyshare/common"
	"github.com/kisom/entropyshare/prng"
)

type Target struct {
	Address string
	Public  []byte
	Counter int64
	Next    int64
}

func (t *Target) Send(signer *rsa.PrivateKey) (err error) {
	var packet *common.Packet
	t.Counter, packet, err = common.NewPacket(t.Counter, prng.PRNG)
	if err != nil {
		return
	}

	out, err := common.SerialiseWire(packet, t.Public, signer)
	if err != nil {
		return
	}

	log.Printf("sending %d byte packet", len(out))
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(out)))

	conn, err := net.Dial("tcp", t.Address)
	if err != nil {
		return
	}

	if _, err = conn.Write(header[:]); err != nil {
		return
	}

	if _, err = conn.Write(out); err != nil {
		return
	}

	conn.Close()
	return nil
}

func Load(fileName string) []*Target {
	var targets = []*Target{}
	in, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Fatalf("%v", err)
	}

	err = json.Unmarshal(in, &targets)
	if err != nil {
		log.Fatalf("%v", err)
	}

	return targets
}

func Store(fileName string, targets []*Target) (err error) {
	out, err := json.Marshal(targets)
	if err != nil {
		return
	}

	buf := &bytes.Buffer{}
	err = json.Indent(buf, out, "", "\t")
	if err != nil {
		return
	}
	return ioutil.WriteFile(fileName, buf.Bytes(), 0644)
}
