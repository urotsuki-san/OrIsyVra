# Windows four-digit PIN cards

OrIsyVra supports device-bound four-digit PIN cards on Windows. A card consists of a Visual Key PNG plus a local Windows binding.

## Credential construction

A four-digit PIN has 10,000 possible values, so it is not used as the only secret protecting the master key.

For each Windows PIN card, OrIsyVra generates a random 256-bit device secret and protects it with Windows DPAPI for the current user. The Argon2id credential is built from:

```text
OrIsyVra domain string
        +
256-bit device secret
        +
four ASCII PIN digits
```

The 384-bit master key is generated independently with the operating-system CSPRNG.

## Storage

### Visual Key PNG

The PNG contains:

- the rendered card image;
- a non-secret key fingerprint;
- a non-secret Key Sigil used for visual identification;
- the protected key capsule in private PNG chunk `orKY`;
- the PIN-card policy marker in private PNG chunk `orPn`.

### Windows user profile

The DPAPI-protected 256-bit device secret is stored separately and indexed by the card fingerprint.

### Not stored as plaintext

- the 384-bit master key;
- the four-digit PIN;
- the unwrapped device secret.

## Copying a card

Copies of the same PNG use the same binding on the Windows account where the card was registered.

On another Windows account or device, the PNG does not include the required device secret. OrIsyVra reports the missing binding instead of treating the PIN as a normal passphrase.

## Card identifiers

The key fingerprint and Key Sigil identify a card visually. They are non-secret values and are not authentication factors.

## Recovery

The Windows binding is required to unlock a PIN card. Loss of the Windows profile or its DPAPI data can therefore make the card unusable even when the PNG and PIN are still available.

For data that must survive device loss, create a separate passphrase recovery key while the master key is unlocked. A second PIN card wrapping the same master key can also be created on the current Windows account.

Device migration using recovery material is planned but not yet implemented.

## Security boundary

The PIN-card scheme relies on the current Windows user account and DPAPI. It does not provide hardware-backed non-exportability. Malware or an attacker with sufficient access to the same user session may be able to use DPAPI-protected material or read an already-unlocked master key.

See [`THREAT_MODEL.md`](THREAT_MODEL.md) for the full threat model.
