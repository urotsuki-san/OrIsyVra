# Threat Model

## Protected assets

- plaintext files;
- the 384-bit master key;
- visual-key material;
- encrypted-record integrity and ordering.

## Attacker capabilities

The attacker may read, copy, modify, truncate, reorder, or replace encrypted files and visual keys. A stolen visual key may be subjected to offline passphrase guessing because it contains an Argon2id-protected key capsule.

The attacker may also attempt to replace one visual key with another. Users can compare the displayed key fingerprint when identity matters.

## Assumptions

- the operating-system CSPRNG is available;
- the endpoint is not already compromised during encryption or decryption;
- the visual key, its backups, and recovery material are stored appropriately;
- the passphrase has adequate entropy;
- external cryptographic dependencies behave as specified.

## Desktop session

The desktop application unwraps the selected visual key once and retains the master key in process memory until Lock or application exit. The passphrase is cleared after the unlock operation. This does not protect against malware, process-memory inspection with sufficient privilege, or an already compromised user session.

The application remembers only the selected key path. It does not persist the passphrase or unwrapped master key.

## Modes

**Guarded Mode** is the default and wraps each Native record in XChaCha20-Poly1305.

**Native Research Mode** exposes the experimental OrIsyVra construction for cryptanalysis and research data. It requires explicit acknowledgement in the GUI and CLI.

## Visual-key formats

The digital PNG contains the protected key capsule in a private ancillary PNG chunk. The visible QR encodes the same protected capsule for print/camera recovery. Loss of the private PNG chunk does not disclose the master key, but it can remove the fast digital-key path and leave only optical recovery.

## Out of scope

- malware controlling the host OS;
- denial of service or file deletion;
- hardware fault injection;
- physical power or electromagnetic side channels;
- recovery after loss of all visual keys and recovery material;
- hidden-volume deniability;
- mountable encrypted-volume guarantees before P2 is implemented and tested.
