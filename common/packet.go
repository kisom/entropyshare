package common

import (
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"io"
	"time"

	"github.com/kisom/entropyshare/common/crypt"
)

const ChunkSize = 1024

// Packet combine a timestamp and a random chunk of data.
type Packet struct {
	Timestamp int64
	Counter   int64
	Chunk     [ChunkSize]byte
}

type packet struct {
	Timestamp int64
	Counter   int64
	Chunk     []byte
}

func NewPacket(counter int64, r io.Reader) (int64, *Packet, error) {
	var p Packet
	_, err := io.ReadFull(r, p.Chunk[:])
	if err != nil {
		return counter, nil, err
	}

	counter++
	p.Timestamp = time.Now().Unix()
	p.Counter = counter
	return counter, &p, nil
}

// SerialiseWire packs and encrypts a packet for transmission on the wire.
func SerialiseWire(p *Packet, peer []byte, signer *rsa.PrivateKey) ([]byte, error) {
	packet := packet{
		Timestamp: p.Timestamp,
		Counter:   p.Counter,
		Chunk:     p.Chunk[:],
	}
	out, err := asn1.Marshal(packet)
	if err != nil {
		return nil, err
	}

	return crypt.Encrypt(out, peer, signer)
}

var (
	ErrUnsignedPacket = errors.New("packet was not signed")
	ErrBadChunk       = errors.New("bad packet chunk length")
)

// ParsePacket decrypts and unpacks a packet from the wire.
func ParsePacket(in []byte, priv []byte, signer *rsa.PublicKey) (*Packet, error) {
	msg, signed, err := crypt.Decrypt(in, priv, signer)
	if err != nil {
		return nil, err
	} else if !signed {
		return nil, ErrUnsignedPacket
	}

	var packet packet
	_, err = asn1.Unmarshal(msg, &packet)
	if err != nil {
		return nil, err
	}

	if len(packet.Chunk) != ChunkSize {
		return nil, ErrBadChunk
	}
	p := &Packet{
		Timestamp: packet.Timestamp,
		Counter:   packet.Counter,
	}
	copy(p.Chunk[:], packet.Chunk)
	return p, nil
}

var (
	ErrTimestamp = errors.New("invalid packet timestamp")
	ErrCounter   = errors.New("counter has regressed")
)

// ParseAndWritePacket decrypts and unpacks a packet from the wire,
// verifies the timestamp is within an acceptable drift range and
// that the counter hasn't decremented, and then writes the entropy
// to the PRNG. It returns the new counter. On error, the current
// counter value is returned instead of a new value.
func ParseAndWritePacket(in []byte, priv []byte, signer *rsa.PublicKey, drift, counter int64, w io.Writer) (int64, error) {
	p, err := ParsePacket(in, priv, signer)
	if err != nil {
		return counter, err
	}

	if w == nil {
		return counter, errors.New("invalid writer")
	}

	now := time.Now().Unix()

	if (now + drift) < p.Timestamp {
		return counter, ErrTimestamp
	}

	if (now - drift) > p.Timestamp {
		return counter, ErrTimestamp
	}

	if p.Counter <= counter {
		return counter, ErrCounter
	}

	_, err = w.Write(p.Chunk[:])
	return p.Counter, err
}
