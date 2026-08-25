# Roadmap

## Implemented

- [x] P768/K384 collision-wave core
- [x] fixed known-answer tests
- [x] Guarded and Native streaming modes
- [x] Argon2id-protected key capsules
- [x] one-file Visual Key PNG
- [x] private PNG key chunk
- [x] Key Sigil visual identifier
- [x] passphrase recovery Visual Keys
- [x] Windows device-bound four-digit PIN cards
- [x] DPAPI-protected random PIN-card device secret
- [x] session key unlock in the desktop application
- [x] Guarded / Native selector
- [x] file and folder batch processing
- [x] Windows, Linux, and macOS GUI builds
- [x] reduced-round analysis commands
- [x] authenticated temporary output
- [x] Windows executable and installer build

## P2 — Mountable encrypted volumes

### P2A — Authenticated sparse volume core

- [x] authenticated random-access volume core
- [x] sparse 64-bit logical capacity
- [x] volume-specific guarded key derivation
- [x] authenticated A/B superblocks
- [x] generation and block-location binding
- [x] uncommitted-tail crash recovery
- [x] wrong-key, tamper, relocation, range, reopen, and sparse-capacity tests

### P2B — Windows block adapter

- [x] 4 KiB sector-to-encrypted-block adapter
- [x] authenticated partial-block read/modify/write
- [x] explicit flush semantics
- [ ] bounded write cache
- [ ] authenticated sparse deallocation / UNMAP records
- [ ] randomized sector stress harness

### P2C — Windows virtual disk

- [x] WinSpd runtime integration
- [x] `.orisyvra-volume` virtual SCSI disk
- [x] read-only mount option
- [x] attach/eject lifecycle and crash recovery
- [x] NTFS/exFAT first-use formatting flow
- [x] preferred drive-letter assignment
- [ ] Explorer / Office / browser / archive compatibility matrix on real machines
- [ ] sleep/resume and Windows Update endurance tests

### P2D — GUI and Windows auto-mount

- [x] create/connect/disconnect GUI
- [x] pending connection resumes after key unlock
- [x] automatic Windows mount-task registration
- [x] custom logical capacity
- [x] registered-volume list without plaintext secrets
- [x] connect at Windows sign-in
- [x] prompt-once startup unlock grouped by Visual Key
- [x] four-digit PIN support in the volume GUI
- [x] optional DPAPI auto-unlock
- [x] manual key lock
- [x] WinSpd runtime detection
- [x] Windows installer and Defender validation path
- [x] temporary manual-mount credential expiry
- [ ] idle-time automatic lock
- [ ] guided WinSpd installation

### P2E — Other platforms

- [ ] Linux mount/block strategy
- [ ] macOS mount strategy after Windows behavior stabilizes

See [`VOLUME.md`](VOLUME.md) and [`WINDOWS_AUTOMOUNT.md`](WINDOWS_AUTOMOUNT.md).

## Key management UX

- [x] four-digit PIN input on Windows
- [x] PIN combined with a DPAPI-bound random device secret
- [x] copied PIN PNG rejected when its Windows binding is unavailable
- [x] Key Sigil visual identifier
- [ ] guided device migration using an authorized recovery key
- [ ] optional Windows Hello / TPM-backed enhancement

## Documentation and branding

- [x] README hero artwork
- [x] OrIsyVra character identity and asset constraints
- [x] construction parameters separated from security claims
- [x] Windows PIN-card and encrypted-drive documentation

## Research and hardening

- [ ] deterministic container vectors
- [ ] long-running parser and Visual Key fuzzing
- [ ] per-output-bit differential-bias analysis
- [ ] SAT, SMT, and MILP trail models
- [ ] rotational / invariant-subspace / integral analysis
- [ ] concrete per-key usage bounds
- [ ] external cryptanalysis
- [ ] signed and reproducible installers
- [ ] broader Windows encrypted-drive endurance testing

Native Research Mode has no claimed concrete security strength.
