# OrIsyVra-P768/K384/C384/T256-R18 Specification

Status: `0.2.0-alpha.1`

## Parameters

| Parameter | Value |
|---|---:|
| State | 768 bits (`12 × u64`) |
| Collision Rail | 384 bits |
| Wave Rail | 384 bits |
| Master key | 384 bits |
| Capacity | 384 bits |
| Native tag | 256 bits |
| Full rounds | 18 |
| Byte order | little-endian |

## Core permutation

Each round performs constant injection, three scheduled collision updates, wave propagation, bidirectional cross-rail injection, word rotations, and rail-local word permutations. The exact normative operations and constants are defined in `crates/orisyvra-core/src/permutation.rs` and `constants.rs`.

## Keyed primitive

`prf_parts(K, domain, parts, output_length)` uses the P768 state as a keyed sponge. Each part is length-prefixed before absorption. Domain identifiers separate key derivation, header binding, Record-SIV, stream generation, and manifest authentication.

## Protected key capsule

The internal key capsule contains one random 384-bit master key protected by Argon2id and XChaCha20-Poly1305.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | `OYVKEY1\0` |
| 8 | 2 | version |
| 10 | 4 | Argon2 memory KiB |
| 14 | 4 | Argon2 iterations |
| 18 | 4 | Argon2 parallelism |
| 22 | 16 | salt |
| 38 | 24 | XChaCha20 nonce |
| 62 | 2 | wrapped-key length |
| 64 | 64 | encrypted master key + tag |

The GUI normally stores this capsule inside one visual-key PNG rather than exposing a separate key file.

## Visual-key PNG

A digital visual key is a valid PNG containing:

1. a human-readable card design and key fingerprint;
2. a private ancillary PNG chunk named `orKY` containing version, protected key capsule, and SHA-256 integrity digest;
3. a QR representation of the same protected key capsule for print/camera recovery.

The application reads the `orKY` chunk first. QR decoding is a fallback for scanned, photographed, or re-rendered cards whose private PNG chunk is no longer present.

The visual-key fingerprint is the first eight bytes of SHA-256 over the protected key capsule, displayed as hexadecimal groups. It is an identifier, not an authentication tag.

A printable PDF contains the QR fallback and fingerprint but cannot carry the digital PNG chunk.

## File header

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | `OYVFILE1` |
| 8 | 2 | version |
| 10 | 1 | mode: `0` Native, `1` Guarded |
| 11 | 1 | flags |
| 12 | 4 | chunk size |
| 16 | 32 | salt |
| 48 | 32 | file ID |

Accepted chunk sizes are 4 KiB through 16 MiB. The default is 1 MiB.

## Native data record

```text
kind                 1 byte = 0x01
record index         8 bytes
plaintext length     4 bytes
body length          4 bytes
body                 variable
```

For each record:

```text
context = header_binding || record_index || plaintext_length
SIV = MAC(K_siv, context, plaintext)
stream = PRF(K_stream, context, SIV, plaintext_length)
ciphertext = plaintext XOR stream
body = SIV || ciphertext
```

The SIV is recalculated after decryption and compared in constant time.

## Guarded Mode

Guarded Mode encrypts each complete Native body with XChaCha20-Poly1305. Guard keys are derived independently from the 384-bit master key with HKDF-SHA-384. Nonces are derived with HMAC-SHA-256 from the file ID, record type, and record index.

## Manifest

The final manifest authenticates total plaintext length, record count, and the SHA-384 transcript of the header plus all data records. Decryption persists the output file only after successful manifest verification.

## Session unlock

The desktop application derives and unwraps the master key once after the user supplies the visual-key passphrase. The unwrapped `MasterKey` remains only in process memory until the user presses Lock or the application exits. The passphrase itself is cleared after the unlock task finishes.

## Recovery visual key

A recovery visual key wraps the same master key under an independent recovery passphrase and stores the resulting protected capsule in a separate PNG or printable PDF.
