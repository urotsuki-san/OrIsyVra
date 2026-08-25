# Mountable Encrypted Volume

Status: **Windows alpha**

OrIsyVra can expose an authenticated `.orisyvra-volume` container as a Windows block device through WinSpd.

## Components

- [`crates/orisyvra-volume`](../crates/orisyvra-volume): authenticated sparse block container;
- [`crates/orisyvra-volume/src/bin/orisyvra-volume-mount.rs`](../crates/orisyvra-volume/src/bin/orisyvra-volume-mount.rs): WinSpd virtual-disk host;
- [`crates/orisyvra-volume-gui`](../crates/orisyvra-volume-gui): volume creation, registration, connection, disconnection, and sign-in configuration.

## Architecture

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

Windows provides filesystem semantics. OrIsyVra handles key access, sector translation, authenticated block storage, recovery state, and mount policy.

## Container layout

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

The bootstrap contains the fields needed to locate and authenticate the volume structure. Windows filesystem sectors are encrypted before they are written to the backing file.

## Block protection

Volume keys are derived independently from the OrIsyVra master key. Each block record binds:

- logical block index;
- per-block generation;
- volume identity and key-derivation context;
- authenticated ciphertext and metadata.

The volume maintains two authenticated superblocks. Commits alternate between them so that a previously authenticated state remains available if a later update is interrupted.

On open, the log is reconstructed from the newest valid authenticated superblock. Bytes after its committed end are discarded.

## Windows sector adapter

WinSpd exposes 4 KiB logical sectors. The encrypted container uses larger authenticated blocks, 64 KiB by default.

The adapter:

- maps sector ranges to internal blocks;
- returns zeroes for unallocated logical regions;
- performs authenticated read-modify-write for partial-block updates;
- rejects requests beyond the configured logical capacity;
- flushes the encrypted volume before acknowledging WinSpd flush requests.

Windows I/O touching several internal blocks is committed as one authenticated block transaction.

UNMAP/TRIM is currently disabled. Authenticated sparse deallocation semantics are not yet implemented.

## Sparse allocation

Logical capacity is independent from current backing-file size. A 100 GiB logical volume grows as encrypted block records are written.

The backing file is append-oriented and may require compaction or deallocation work in future versions.

## Exclusive access

On Windows, writable volume files are opened without file sharing. This prevents another local process or SMB client from opening the same backing file for concurrent writes when the server honors Windows share modes.

The registered mount path also uses a per-entry Windows mutex to prevent duplicate mount-host instances for the same entry.

## Drive letters

A registered volume may specify a preferred drive letter. After attachment, the mount host identifies the new Windows volume and attempts to move it to the preferred letter.

If Windows initially assigns another letter, the host removes that old mount point after the preferred assignment is verified. An occupied preferred letter is not replaced.

## First-use formatting

New containers include an initial MBR partition entry but no filesystem. The partition must be formatted once as NTFS or exFAT using Windows.

Formatting is not performed automatically because it is destructive and requires positive identification of the target disk.

## Mount and dismount

For a registered volume:

1. unlock the associated Visual Key if required;
2. start the registered mount host;
3. open and authenticate the backing volume;
4. attach the WinSpd disk;
5. assign the preferred drive letter where possible;
6. write mounted-state metadata.

**Safely disconnect** requests Windows dismount first, then synchronizes the encrypted volume and shuts down the WinSpd storage unit. A clean flag is written only after the safe path completes.

Unexpected process termination leaves the volume dirty. Recovery on the next open uses the authenticated superblocks and committed log boundary.

## Automatic connection

Per-user sign-in behavior and DPAPI-protected mount credentials are described in [`WINDOWS_AUTOMOUNT.md`](WINDOWS_AUTOMOUNT.md).

Pre-login and system-volume mounting are not implemented.

## Current limitations

- no authenticated UNMAP/TRIM records;
- no bounded write cache;
- no dedicated randomized block-device stress harness;
- limited real-machine application and filesystem compatibility coverage;
- sleep/resume and Windows Update endurance testing is incomplete;
- no Linux or macOS mount adapter;
- WinSpd installation remains external.

See [`ROADMAP.md`](ROADMAP.md) for planned work.

## Runtime dependency

WinSpd is required only for the Windows mounted-volume feature. File and folder encryption works without it.

OrIsyVra currently detects an installed WinSpd runtime but does not bundle or automatically install it.
