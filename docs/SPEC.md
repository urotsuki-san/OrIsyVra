# OrIsyVra-P768/K384/C384/T256-R18 Specification

Status: `0.2.0-alpha.1`

The construction name describes parameter sizes. Native Research Mode has no claimed concrete security level.

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

Each round performs constant injection, three scheduled collision updates, wave propagation, bidirectional cross-rail injection, word rotations, and rail-local word permutations. The normative operations and constants are defined in `crates/orisyvra-core/src/permutation.rs` and `constants.rs`.

State, key, capacity, tag, and round-count sizes are not security claims. Concrete usage bounds and external cryptanalysis remain open work.

## Keyed primitive

`prf_parts(K, domain, parts, output_length)` uses the P768 state as a keyed sponge. Each part is length-prefixed before absorption. Domain identifiers separate key derivation, header binding, Record-SIV, stream generation, manifest authentication, and other internal purposes.

## Master key

Each Visual Key contains an operating-system-CSPRNG-generated 384-bit master key. Human credentials protect the key capsule; they do not determine the master key.

## Protected key capsule

The key capsule protects the 384-bit master key with Argon2id and XChaCha20-Poly1305.

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

The desktop application normally stores this capsule inside the Visual Key PNG.

## Windows four-digit PIN cards

Windows PIN cards use the same protected-capsule format with a device-bound Argon2id credential.

1. Generate a random 256-bit device secret with the operating-system CSPRNG.
2. Protect it for the current Windows user with DPAPI.
3. Build the Argon2id credential from a fixed domain string, the device secret, and four ASCII decimal PIN digits.
4. Store the DPAPI-protected device secret under the current user's OrIsyVra application data.
5. Store the non-secret PIN-card policy marker in the PNG.

A copied PNG does not contain the DPAPI device secret. The scheme is bound to the Windows user/account trust boundary and does not provide hardware-backed non-exportability.

## Visual Key PNG

A current Visual Key PNG contains:

1. the rendered card image and key fingerprint;
2. a deterministic, non-secret Key Sigil for visual identification;
3. private ancillary chunk `orKY` containing the protected key capsule and integrity metadata;
4. for Windows PIN cards, private marker chunk `orPn` describing the unlock policy.

The displayed key fingerprint is derived from SHA-256 over the protected key capsule. It is an identifier, not an authentication tag.

Older passphrase-protected Visual Key formats remain accepted for compatibility.

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

The final manifest authenticates total plaintext length, record count, and the SHA-384 transcript of the header plus all data records. Decrypted output is persisted only after successful manifest verification.

## Session unlock

The desktop application unwraps the selected master key once after credential verification. `MasterKey` remains in process memory until **Lock** or application exit. Human-entered PIN and passphrase buffers are cleared after use where practical.

## Recovery keys

- A second PIN card can wrap the same master key under another Windows binding and PIN.
- A passphrase recovery key can wrap the same master key independently of Windows DPAPI.
- A copied PIN PNG does not replace the DPAPI binding required for device-bound unlock.

## Security status

Native Research Mode is experimental. The parameter name must not be interpreted as a claim of 384-bit, 256-bit, 192-bit, or another concrete security strength.

Current validation includes known-answer tests, container-integrity tests, fuzzing infrastructure, and reduced-round exploratory analysis. Stronger trail modelling and independent cryptanalysis are still required before a concrete security claim can be made.
