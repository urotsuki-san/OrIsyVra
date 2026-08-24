# Mountable Encrypted Volume

Status: **P2A implemented · Windows WinSpd alpha mount/GUI/auto-mount implemented · interoperability hardening ongoing**

OrIsyVra supports an experimental VeraCrypt-style encrypted container that can be exposed as a normal Windows drive while unlocked.

## Current implementation boundary

The current Windows alpha consists of three layers:

- [`crates/orisyvra-volume`](../crates/orisyvra-volume): authenticated sparse encrypted block container;
- [`crates/orisyvra-volume/src/bin/orisyvra-volume-mount.rs`](../crates/orisyvra-volume/src/bin/orisyvra-volume-mount.rs): WinSpd virtual-disk host;
- [`crates/orisyvra-volume-gui`](../crates/orisyvra-volume-gui): create/register/mount/unmount and Windows sign-in auto-mount GUI.

Implemented now:

- 64-bit logical capacity and sparse physical growth;
- configurable authenticated internal block size;
- XChaCha20-Poly1305 protection for random-access volume blocks;
- volume-unique key derivation from the 384-bit OrIsyVra master key;
- block-index and generation binding in nonce/AAD construction;
- authenticated alternating A/B superblocks;
- monotonically increasing generations and clean/dirty state;
- authenticated reopen and index reconstruction;
- truncation of an uncommitted crash tail;
- 4 KiB Windows logical-sector adapter;
- authenticated partial-block read/modify/write;
- explicit WinSpd flush handling;
- virtual SCSI-disk attach/detach;
- read-only attachment;
- initial MBR partition creation for new volumes;
- preferred drive-letter restoration where Windows permits it;
- dedicated Windows encrypted-volume GUI;
- per-user registered-volume metadata;
- prompt-once Windows sign-in auto-mount grouped by visual key;
- optional current-Windows-user DPAPI auto-unlock;
- five-minute expiry for temporary manual-mount credentials;
- tests for wrong-key rejection, record relocation/tampering, out-of-range access, reopen, and sparse 100 GiB behavior;
- Windows CI validation of the workspace, volume GUI, mount host, and Inno Setup installer.

Still open before this should be treated as a mature storage product:

- authenticated sparse deallocation / UNMAP semantics;
- bounded write cache and dedicated randomized sector stress harness;
- broad real-machine Explorer/Office/browser/archive compatibility testing;
- sleep/resume, Windows Update and long-duration endurance testing;
- idle-time automatic lock;
- one-click guided WinSpd installation;
- Linux/macOS mount adapters.

## Windows user experience

The implemented Windows-alpha workflow is:

1. Start **OrIsyVra Encrypted Volumes**.
2. Choose one visual-key PNG and unlock it once.
3. Choose a logical capacity and preferred drive letter, for example `O:`.
4. Create `vault.orisyvra-volume`.
5. OrIsyVra creates the initial Windows partition table and attaches the encrypted block device through WinSpd.
6. On first use only, format the new partition as NTFS or exFAT using Windows.
7. Use Explorer and ordinary applications normally.
8. Use **Unmount** to request a clean flush/detach before moving or removing the backing file.

The backing container remains sparse. A logical 100 GiB volume does not immediately consume 100 GiB on the host filesystem; physical usage grows as authenticated blocks are written.

## Windows architecture: virtual block device

OrIsyVra uses **WinSpd** rather than implementing a Windows filesystem itself. The encrypted container is block-oriented, so WinSpd lets Windows apply its own NTFS/exFAT filesystem semantics on top of OrIsyVra's authenticated sectors.

```text
Explorer / applications
        │
        ▼
Windows NTFS / exFAT
        │
        ▼
Windows storage stack
        │
        ▼
WinSpd virtual SCSI disk
        │
        ▼
OrIsyVra 4 KiB sector adapter
        │
        ▼
Authenticated sparse volume blocks
        │
        ▼
vault.orisyvra-volume
```

Windows remains responsible for directory layout, timestamps, filesystem locking and ordinary application semantics. OrIsyVra is responsible for key lifecycle, encrypted block translation, authenticated persistence, crash recovery and mount policy.

WinFsp remains a possible future option for directory-style mounts, but it is not the primary Windows path.

## Sector adapter

WinSpd exposes 4 KiB logical sectors while the encrypted container uses larger authenticated blocks (64 KiB by default).

Implemented behavior:

- map 4 KiB sectors into encrypted blocks;
- zero-fill unread/unallocated logical sectors;
- authenticated read-modify-write for partial internal-block updates;
- reject I/O beyond configured logical capacity;
- flush the encrypted volume before acknowledging WinSpd flush requests.

Not yet implemented:

- bounded write coalescing/cache;
- authenticated deallocation records and Windows UNMAP/TRIM support.

UNMAP remains disabled until authenticated deletion semantics are explicit and tested.

## First-use formatting

A newly created OrIsyVra volume contains an initial Windows partition table but no NTFS/exFAT filesystem yet.

The current alpha keeps this destructive step explicit. The GUI explains that the partition must be formatted once and provides access to Windows Disk Management. It does not silently format an existing disk or hide destructive shell operations.

Future UX may add a guided documented formatting flow after broader device-identification testing.

## Windows sign-in auto-mount

See [`WINDOWS_AUTOMOUNT.md`](WINDOWS_AUTOMOUNT.md) for implementation and security details.

Each registered volume can enable:

> **Mount automatically when I sign in to Windows**

Two implemented policies are available:

1. **Prompt once at sign-in — recommended.** The per-user startup GUI groups registered volumes by visual-key path. Unlocking that visual key once prepares and starts each configured volume using it.
2. **Windows auto-unlock — optional.** OrIsyVra creates a dedicated mount credential and stores only its random unlock secret through current-user Windows DPAPI. The visual-key passphrase and raw OrIsyVra master key are not persisted.

Manual mount credentials that are not configured for persistent automatic unlock expire after five minutes. Stale protected secrets and their temporary credential capsules are rejected and removed instead of being reused at a later Windows sign-in.

Pre-login/system-volume mounting is not implemented.

## Container layout

Current P2A layout:

```text
+----------------------------------+
| Public bootstrap header          |
| format/version/capacity/ID/salt  |
+----------------------------------+
| Authenticated superblock A       |
+----------------------------------+
| Authenticated superblock B       |
+----------------------------------+
| Reserved bootstrap area          |
+----------------------------------+
| Append-only authenticated blocks |
| ...                              |
+----------------------------------+
```

The public bootstrap exposes only the information required to locate and authenticate the encrypted volume structure. Once Windows filesystem sectors are written through the encrypted block layer, NTFS/exFAT metadata is ciphertext in the backing `.orisyvra-volume` file.

## Block protection

Mounted volumes use the guarded volume construction. Native Research protection is not the default mounted-volume profile.

Random-access storage cannot safely reuse the streaming `.orisyvra` file-record format unchanged. The volume core therefore uses independent volume-specific key derivation, authenticated block records, generation-bound nonces, block-location binding and authenticated superblocks.

## Delivery phases

### P2A — Authenticated sparse volume core ✅

- [x] create and inspect sparse containers;
- [x] authenticated random-access block read/write;
- [x] volume-specific guarded key derivation;
- [x] A/B authenticated superblocks;
- [x] generation and block-location binding;
- [x] uncommitted-tail crash recovery;
- [x] wrong-key, tamper, relocation, range, reopen, and sparse-capacity tests.

### P2B — Windows block adapter

- [x] 4 KiB sector-to-encrypted-block translation;
- [x] authenticated read-modify-write for partial blocks;
- [x] explicit flush semantics;
- [ ] bounded write cache;
- [ ] authenticated sparse deallocation / UNMAP semantics;
- [ ] deterministic randomized block-device stress tests.

### P2C — Windows virtual disk

- [x] WinSpd runtime integration;
- [x] virtual SCSI-disk lifecycle;
- [x] read-only mount option;
- [x] attach/eject and authenticated crash-recovery lifecycle;
- [x] preferred drive-letter assignment;
- [x] guided NTFS/exFAT first-use formatting step;
- [ ] broad Explorer/Office/browser/archive compatibility matrix;
- [ ] sleep/resume and Windows-update endurance matrix.

### P2D — GUI and automatic mounting

- [x] dedicated create/mount/unmount GUI;
- [x] custom logical-capacity selection;
- [x] registered-volume list without plaintext secrets;
- [x] preferred drive-letter configuration;
- [x] **Mount automatically when I sign in to Windows**;
- [x] prompt-once startup unlock;
- [x] optional Windows-account-bound DPAPI auto-unlock;
- [x] manual lock;
- [x] runtime detection;
- [x] Windows installer integration and Defender validation;
- [x] temporary manual-mount credential expiry;
- [ ] idle-time automatic lock;
- [ ] one-click guided WinSpd installation.

### P2E — Other platforms

- [ ] Linux block/FUSE strategy after Windows behavior stabilizes;
- [ ] macOS mount strategy after the Windows recovery model stabilizes.

## Release / hardening gate

The Windows alpha is build-validated, but a drive letter appearing is not sufficient evidence for production readiness. Further hardening includes:

- repeated randomized sector and filesystem-operation tests;
- multi-gigabyte sequential and random I/O tests;
- host disk-full and logical-volume-full behavior;
- metadata/data corruption tests;
- forced termination during writes;
- sleep/resume, sign-out and Windows Update tests;
- antivirus interaction tests on real machines;
- verification that backing-container blocks do not expose filesystem plaintext;
- documented backup/recovery behavior across WinSpd versions.

## Dependency and license boundary

WinSpd is an external Windows storage runtime. OrIsyVra detects it but does not silently download or install it. File/folder encryption continues to work without WinSpd. Redistribution/linking choices must continue to be reviewed against the WinSpd licensing terms before any future bundled-runtime distribution.
