# Threat Model

## Protected assets

- plaintext files and mounted-volume plaintext;
- the random 384-bit master key;
- Visual Key material and Windows PIN-card bindings;
- encrypted-record integrity and ordering;
- authenticated volume metadata and logical block placement.

## Attacker capabilities

An attacker may read, copy, modify, truncate, reorder, or replace encrypted files, encrypted-volume backing files, and Visual Key PNGs.

A stolen passphrase-protected Visual Key permits offline passphrase guessing against its Argon2id-protected key capsule.

For a Windows PIN card, the attacker may possess the PNG and know or guess its four-digit PIN. The model assumes the attacker does not also have the DPAPI-unwrapped device secret unless the Windows account or active session is compromised.

The displayed key fingerprint and Key Sigil are identifiers only. Replacing one Visual Key with another is within the attacker model.

## Assumptions

- the operating-system CSPRNG is available;
- external cryptographic dependencies behave as specified;
- Windows DPAPI protects the PIN-card device secret within the current-user trust boundary;
- the endpoint is not already compromised while secrets are unlocked;
- recovery material is stored separately and protected appropriately;
- passphrase recovery keys use adequate passphrase entropy.

## Windows PIN-card boundary

A Windows PIN card requires:

1. the protected key capsule inside the PNG;
2. a random 256-bit device secret protected with Windows DPAPI;
3. the four-digit PIN.

The device secret supplies cryptographic entropy that the PIN alone cannot provide. Copying the PNG to another Windows account does not copy the DPAPI binding.

The binding is software and account based. It is not equivalent to a hardware-backed non-exportable key. Malware or an attacker with sufficient access to the same Windows user context may be able to use the protected device secret or inspect an already-unlocked master key.

Loss of the Windows profile or DPAPI binding can make a PIN card unusable. A separate recovery key is required when recovery from device loss matters.

## Passphrase-protected keys

Passphrase-protected Visual Keys wrap the random master key with an Argon2id-derived key and XChaCha20-Poly1305. Their offline-guessing resistance is bounded by passphrase entropy and KDF cost.

## Desktop session

The desktop application unwraps the selected Visual Key once and keeps the master key in process memory until **Lock** or application exit. PIN and passphrase buffers are cleared after use where practical.

This does not protect against malware, privileged process-memory inspection, UI capture, or an already compromised user session.

The application may remember the selected key path. Raw master keys and PINs are not persisted by the application.

## Modes

**Guarded Mode** is the default and protects each Native record with an independent XChaCha20-Poly1305 layer.

**Native Research Mode** exposes the OrIsyVra Native construction directly for analysis. It requires explicit acknowledgement in the GUI and CLI.

`P768/K384/C384/T256-R18` describes construction parameters, not a concrete security level. Native Research Mode currently has no claimed security strength.

## Visual Key format

Current Visual Key PNG files store the protected key capsule in private ancillary chunk `orKY`. Windows PIN cards also contain the non-secret `orPn` policy marker. The displayed fingerprint and Key Sigil are non-secret identifiers.

Older passphrase-protected key files remain supported.

## Encrypted volumes

The Windows volume layer authenticates logical blocks, block locations, generations, and alternating superblock state. The mounted disk also depends on WinSpd, the Windows storage stack, and the selected Windows filesystem.

Windows integration registration does not change the trust assumptions of DPAPI, Task Scheduler, WinSpd, NTFS/exFAT, or the Windows kernel.

## Out of scope

- malware already controlling the host OS or user session;
- kernel/root/administrator attackers while secrets are unlocked;
- denial of service or file deletion;
- hardware fault injection;
- power and electromagnetic side channels;
- recovery after loss of all device bindings and recovery keys;
- hidden-volume deniability;
- concrete Native security claims before external cryptanalysis;
- resistance to PIN guessing after disclosure of the DPAPI-unwrapped device secret.
