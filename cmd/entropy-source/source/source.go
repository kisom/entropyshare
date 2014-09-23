package source

import (
	"crypto/rsa"
	"log"
	"time"

	"github.com/kisom/entropyshare/prng"
	"github.com/kisom/entropyshare/target"
)

// Start begins the source scanner. This function will continually
// load the target list, and deliver entropy packets as appropriate.
func Start(signer *rsa.PrivateKey, targetFile string) {
	defer prng.StoreSeed()

	var delay = 6 * time.Hour
	var targetUpdate bool

	for {
		log.Println("scanning targets")
		now := time.Now().Unix()

		targets := target.Load(targetFile)
		for i, t := range targets {
			updated := targetCheck(t, signer, now)
			if updated {
				targets[i].Next = now + int64(delay.Seconds())
				targetUpdate = true
			}
		}

		if targetUpdate {
			err := target.Store(targetFile, targets)
			if err != nil {
				log.Printf("%v", err)
			}
			targetUpdate = false
		}
		<-time.After(1 * time.Minute)
	}
}

func targetCheck(t *target.Target, signer *rsa.PrivateKey, now int64) bool {
	if t.Next < now {
		err := t.Send(signer)
		if err != nil {
			log.Printf("failed to send to %s: %v",
				t.Address, err)
			return false
		} else {
			log.Printf("send packet to %s", t.Address)
			return true
		}
	}
	return false
}
