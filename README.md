# Offline SLH-DSA Signing Device

An Arduino Nano ESP32 that reads `message.txt` from a microSD card, signs it
with a post-quantum SLH-DSA key held on the device, and writes
`message.txt.sig` back to the card.

---

## Desktop CLI (`cli/`)

A desktop prototype of the signing logic, using the `SLH-DSA-SHA2-128f`
parameter set. Run all commands from the `cli/` directory.

### Generate a keypair

```bash
cargo run -- keygen <secret-key-path>
```

Writes the raw secret key to `<secret-key-path>` and prints the public
(verifying) key as hex to stdout.

### Sign a message

```bash
cargo run -- sign <secret-key-path> <message> <signature-path>
```

Reads the secret key from `<secret-key-path>`, writes the raw signature over
`<message>` to `<signature-path>`, and prints the hex-encoded signature to
stdout.

### Verify a signature

```bash
cargo run -- verify <public-key-hex> <message> <signature-path>
```

Reads the raw signature from `<signature-path>` and verifies it over
`<message>` against the hex-encoded public key.

### Run tests

```bash
cargo test
```