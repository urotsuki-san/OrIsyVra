# Roadmap

## Implemented

- [x] P768/K384 collision–wave core
- [x] fixed known-answer tests
- [x] Guarded and Native streaming modes
- [x] Argon2id-protected key capsules
- [x] one-file visual-key PNG
- [x] standards-compliant private PNG key chunk
- [x] QR fallback for print/camera recovery
- [x] separate-passphrase recovery visual keys
- [x] session-only key unlock in the desktop application
- [x] Guarded / Native selector in the desktop application
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
- [ ] randomized sector stress test harness

### P2C — Windows virtual disk

- [x] WinSpd runtime integration
- [x] expose `.orisyvra-volume` as a virtual SCSI disk
- [x] read-only mount option
- [x] attach/eject and authenticated crash-recovery lifecycle
- [x] NTFS/exFAT first-use formatting flow
- [x] preferred drive-letter assignment
- [ ] broad Explorer / Office / browser / archive compatibility matrix on real machines
- [ ] sleep/resume and Windows-update endurance matrix

### P2D — GUI and Windows auto-mount

- [x] dedicated create/open/mount/eject GUI
- [x] custom logical-capacity selection
- [x] registered-volume list without plaintext secrets
- [x] **Mount automatically when I sign in to Windows**
- [x] prompt-once startup unlock grouped by visual key
- [x] optional Windows-account-bound DPAPI auto-unlock
- [x] manual key lock
- [x] WinSpd runtime detection
- [x] Windows installer integration and Defender validation
- [x] temporary manual-mount credential expiry
- [ ] idle-time automatic lock
- [ ] one-click guided WinSpd installation flow

### P2E — Other platforms

- [ ] Linux mount/block strategy
- [ ] macOS mount strategy after the Windows format and recovery behavior stabilize

See [`VOLUME.md`](VOLUME.md) and [`WINDOWS_AUTOMOUNT.md`](WINDOWS_AUTOMOUNT.md).

## Branding / README

- [x] Hestia-style OrIsyVra hero-art direction
- [x] final OrIsyVra sister-character artwork with padlock hair ornament
- [x] `docs/assets/readme/orisyvra-showcase-hero-v1.png`
- [x] README hero integration

See [`MASCOT.md`](MASCOT.md).

## Research and hardening

- [ ] deterministic container vectors
- [ ] long-running parser and visual-key fuzzing
- [ ] SAT, SMT, and MILP trail models
- [ ] concrete per-key usage bounds
- [ ] external cryptanalysis
- [ ] signed and reproducible installers
- [ ] print, scan, crop, and damage tests for visual keys
