package prng

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"log"
	"os"
	"time"

	"github.com/gokyle/gofortuna/fortuna"
	"github.com/gokyle/tpm"
)

var config struct {
	prng           *fortuna.Fortuna
	tpmCtx         *tpm.TPMContext
	tpmSource      *fortuna.SourceWriter
	devRandSource  *fortuna.SourceWriter
	connTimeSource *fortuna.SourceWriter
	shutdownChan   chan interface{}
	seedFile       string
	entropyChan    chan int64
}

var PRNG = config.prng

// The Fortuna PRNG requires identifiers for each source. These are
// represented as single bytes.
const (
	SourceTPM byte = iota + 1
	SourceDevRand
	SourceConnTime
)

// readLimit is the number of bytes in a chunk copied over.
const readLimit int64 = 4096

// copyFromPRNG is a modification of the io.Copy function. In this
// case, none of the interfaces is a WriterTo or ReaderFrom; it's
// also important that the amount of random data that has been written
// out be regularly added to the PRNG tally so that it the PRNG may
// be stirred as required.
func copyFromPRNG(dst io.Writer) (written int64, err error) {
	buf := make([]byte, readLimit)
	for {
		nr, er := config.prng.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er == io.EOF {
			break
		}
		if er != nil {
			err = er
			break
		}
		config.entropyChan <- int64(nr)
	}
	return written, err
}

// Initialise the PRNG, TPM, and add initial entropy from host and TPM.
func Start(seedFile string) {
	if seedFile == "" {
		log.Fatal("no seed file specified")
	}
	config.seedFile = seedFile
	config.shutdownChan = make(chan interface{}, 0)
	config.entropyChan = make(chan int64, 4)
	log.Println("initialising PRNG and TPM")
	if _, err := os.Stat(config.seedFile); err == nil {
		log.Printf("seed file found; loading PRNG state from %s",
			config.seedFile)
		config.prng, err = fortuna.FromSeed(config.seedFile)
		if err != nil {
			log.Fatalf("%v", err)
		}
	} else {
		log.Println("no seed file found, initialising new PRNG")
		config.prng = fortuna.New()
	}
	config.tpmSource = fortuna.NewSourceWriter(config.prng, SourceTPM)
	config.devRandSource = fortuna.NewSourceWriter(config.prng, SourceDevRand)
	config.connTimeSource = fortuna.NewSourceWriter(config.prng, SourceConnTime)
	var err error

	config.tpmCtx, err = tpm.NewTPMContext()
	if err != nil {
		log.Fatalf("%v", err)
	}
	err = refillPRNG()
	if err != nil {
		log.Fatalf("%v", err)
	}

	err = config.prng.WriteSeed(config.seedFile)
	if err != nil {
		log.Fatalf("%v", err)
	}

	go logAutoUpdate()
	go entropyCheck()
}

// refillPRNG reloads the PRNG with entropy. It reads 1024 bytes from
// crypto/rand.Reader and 1024 bytes from the TPM. Finally, the nanosecond
// component of the current timestamp is written to the PRNG.
func refillPRNG() (err error) {
	log.Println("refilling pool (1/2)")
	// First fill of pool: each pool receives 16 bytes of entropy
	// from crypto/rand.Reader, and 16 bytes of entropy from the TPM.
	var event1 = make([]byte, 16)
	for i := 0; i < fortuna.PoolSize; i++ {
		_, err = io.ReadFull(rand.Reader, event1)
		if err != nil {
			log.Fatalf("%v", err)
		}
		_, err = config.devRandSource.Write(event1)
		if err != nil {
			log.Fatalf("%v", err)
		}
		var event2 []byte
		event2, err = config.tpmCtx.Random(16)
		if err != nil {
			log.Fatalf("%v", err)
		}
		_, err = config.tpmSource.Write(event2)
		if err != nil {
			log.Fatalf("%v", err)
		}
	}
	log.Println("refilling pool (2/2)")
	// Second fill: swap order of writes (TPM, then rand).
	for i := 0; i < fortuna.PoolSize; i++ {
		var event2 []byte
		event2, err = config.tpmCtx.Random(16)
		if err != nil {
			log.Fatalf("%v", err)
		}
		_, err = config.tpmSource.Write(event2)
		if err != nil {
			log.Fatalf("%v", err)
		}
		_, err = io.ReadFull(rand.Reader, event1)
		if err != nil {
			log.Fatalf("%v", err)
		}
		_, err = config.devRandSource.Write(event1)
		if err != nil {
			log.Fatalf("%v", err)
		}
	}
	writeTimestamp()
	return nil
}

// writeTimestamp takes the nanosecond component of the current
// timestamp, packs it as a 32-bit unsigned integer, and adds the
// SHA-256 digest of that to the PRNG state.
func writeTimestamp() {
	ns := uint32(time.Now().Nanosecond())
	var ts = make([]byte, 8)
	binary.BigEndian.PutUint32(ts, ns)
	sum := sha256.Sum256(ts)
	config.connTimeSource.Write(sum[:])
}

// Shutdown closes down the TPM interface and writes out a seed file.
func shutdown() {
	log.Println("shutting down")
	close(config.shutdownChan)
	close(config.entropyChan)
	err := config.tpmCtx.Destroy()
	if err != nil {
		log.Fatalf("TPM failed to shutdown: %v", err)
	}
	err = config.prng.WriteSeed(config.seedFile)
	if err != nil {
		log.Printf("failed to write seed file: %v", err)
	}
}

// logAutoUpdate runs the PRNG autoupdate functions. These write
// out the seed file every ten minutes and refill the PRNG after
// six hours.
func logAutoUpdate() {
	var fsErr = make(chan error, 4)
	config.prng.AutoUpdate(config.seedFile, config.shutdownChan, fsErr)
	go func() {
		for {
			err := <-fsErr
			log.Println("autoupdate error: %v", err)
		}
	}()
	go func() {
		for {
			select {
			case <-time.After(6 * time.Hour):
				refillPRNG()
			case _, ok := <-config.shutdownChan:
				if !ok {
					break
				}
			}
		}
		log.Println("autofill shutting down")
	}()
}

// entropyCheck keeps track of the amount of random data written
// out; after 2**32-1 bytes, it will stir the PRNG using rand.Reader
// and the TPM.
func entropyCheck() {
	var entropy int64
	var printCheck int64
	const regen int64 = 4294967295 // 2^32-1 bytes
	for {
		n, ok := <-config.entropyChan
		if !ok {
			break
		}
		entropy += n
		printCheck += n
		// 2 ** 32 bits
		if printCheck >= 536870912 {
			log.Printf("%d total bytes read from PRNG",
				entropy)
			printCheck = 0
		}
		if entropy >= regen {
			log.Println("stirring PRNG")
			refillPRNG()
			entropy = 0
		}
	}
}

func StoreSeed() {
	if config.seedFile == "" {
		log.Fatal("PRNG has not been started")
	}
	config.prng.WriteSeed(config.seedFile)
}
