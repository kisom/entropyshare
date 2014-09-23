## entropyshare
### entropy distribution infrastructure

`entropyshare` is a system designed to provide additional, high-quality
entropy to virtual servers via a [Beaglebone Black](http://elinux.org/Beagleboard:BeagleBoneBlack)
on a residential connection (in fact, currently, this runs over a
hotspot).

In `entropyshare`, **sources** generate **packets** of entropy,
sending them to **sinks**.

Packets are defined as

```
packet ::= SEQUENCE {
       timestamp INTEGER        -- int64
       counter   INTEGER        -- int64
       chunk     OCTET STRING   -- [1024]byte
}
```

ASN.1 was selected because it was in the Go standard library, and it
results in a packet that is significantly smaller than either JSON-encoded
or gob-encoded packets (the only other serialisation formats that really
made sense in the standard library encoders). Running the `common` package
test code with the `-sizes` flag will print the sizes of packets:

```
              ASN.1 packet length: 1041
               JSON packet length: 1416
                Gob packet length: 1099
Signed and encrypted ASN.1 length: 1381
 Signed and encrypted JSON length: 1756
  Signed and encrypted gob length: 1439
```

Having a small packet size may not seem like a big deal, but the BBB
runs on a hotspot connection whose connection speed is often measured
in hundreds of bytes per second.

When a source needs to send a new packet to a sink, it generates a fresh
packet, signs it with it's signature RSA private key, and encrypts it
to the sink's Curve25519 public key. The sink will decrypt the packet,
verify the signature, check the packet's timestamp to ensure it is within
an acceptable drift range, and ensure the counter hasn't regressed.

### Building

This system requires a working
[Go installation](http://golang.org/doc/install).

```
$ go get github.com/kisom/entropyshare/...
```

This will install six binaries in `$GOPATH/bin`:

* `entropy-config`
* `entropy-sink`
* `entropy-source`
* `entropy-target`
* `rsagen`
* `curve25519gen`

### Running a source

A source node takes two parameters on startup:

* the signature key (see the rsagen section)
* a JSON file containing an array of sinks, which looks like

```
[
    {
        "Address": "vps.example.net",
        "Counter": 13,
        "Next": 1411351662,
        "Public": "MI...AB"
    }
]
```

The "Public" field has been truncated for clarity, but each sink entry
has four fields, only two of which are required for a new entry:

* `Address` contains the host:port address for the sink; this is
  required.
* `Public` contains the sink's public encryption key; this is
  required. This should be the base64-encoded public key.
* `Counter` is the packet counter for the sink; if not provided, it
  will be filled in with an initial value of 0.
* `Next` contains the time that the sink should be sent a new packet,
  stored as a Unix timestamp.

The targets file is re-read on each run, and written once the run is
complete to update the counter and timestamp values.

The `entropy-target` command can be used to generate a new target
entry.

### Running a sink

A sink takes a JSON configuration file in the form:

```
{
    "Address": ":4141",
    "Counter": 14,
    "Drift": 120,
    "Private": "MI...AB",
    "Signer": "MI...AB"
}
```

The fields are:

* `Address` is the address the server should listen on.
* `Counter` is a 64-bit integer storing the current counter value;
  only packets with a higher counter number than this will be
  accepted. When the counter rolls over, the counter will have to be
  manually reset (and the encryption key should be rotated, as
  well). If this isn't provided initially, it will be set to 0.
* `Drift` stores the allowed range for the timestamp's drift, in
  seconds. If not provided, this is set to 0, which will require the
  clocks of the source and sink to be kept in precise sync.
* `Private`: the base64-encoded Curve25519 private key for decryption
  used to decrypt incoming packets.
* `Signer`: the signer's base64-encoded PKIX public key to verify the
  signatures on incoming packets.

The `entropy-config` command can be used to generate a new
configuration file.

### rsagen

The `rsagen` utility is used to generate RSA keypairs. For example, to
generate the signature keys:

```
rsagen -s 4096
```

### curve25519gen

The `curve25519` utility is used to generate Curve25519 keypairs.

### Planned improvements:

* Set up client auth TLS and an HTTP API
* Use TPM for signing packets

