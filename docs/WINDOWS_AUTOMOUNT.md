# Windows Automatic Volume Mounting

Status: **implemented as a Windows alpha feature; broad real-machine hardening remains**

OrIsyVra can restore registered encrypted volumes after a Windows user signs in. The current implementation is per-user and runs after sign-in; pre-login/system-volume mounting is outside this alpha.

## User-facing behavior

Each registered encrypted volume can enable:

> **Mount automatically when I sign in to Windows**

OrIsyVra stores non-secret registration metadata including:

- `.orisyvra-volume` path;
- visual-key path;
- preferred drive letter;
- read/write or read-only preference;
- auto-mount flag;
- selected unlock policy;
- Windows mount-task registration state.

The visual-key passphrase and raw 384-bit master key are not persisted.

## Implemented unlock policies

### 1. Prompt once at sign-in — recommended

When auto-mount is enabled without full automatic unlock:

1. Windows starts `orisyvra-volume-gui.exe --startup-automount` through the current user's Run entry.
2. The GUI loads registered auto-mount entries and groups them by visual-key path.
3. The user unlocks each required visual key once.
4. The master key remains only in the GUI process memory.
5. OrIsyVra creates a short-lived dedicated mount credential for each target volume and starts its already-registered elevated Windows mount task.
6. The WinSpd host attaches the volume and attempts to restore its preferred drive letter.
7. Temporary manual/startup credentials are one-shot and rejected after five minutes.

A single visual-key passphrase therefore starts every configured prompt-once volume that uses that key; the user is not prompted once per volume.

### 2. Windows auto-unlock — optional convenience mode

Full automatic mode is explicit opt-in and requires auto-mount to remain enabled.

When enabled, OrIsyVra:

1. starts from an already-unlocked visual-key master key;
2. generates a random dedicated mount password;
3. exports a separate protected mount credential carrying the same master key;
4. protects only that random mount password with current-user Windows DPAPI;
5. stores the DPAPI blob separately from the non-secret registration file.

The original visual-key passphrase is never stored. The raw OrIsyVra master key is not written as plaintext. Removing the DPAPI blob or dedicated credential does not rewrite or damage the encrypted volume; the visual-key PNG remains the durable recovery credential.

Security trade-off: malware running with sufficient access as the same logged-in Windows user may be able to invoke DPAPI or read data after the volume is mounted. Full automatic mode therefore provides less protection than prompt-once mode.

If `auto_mount` is disabled, `auto_unlock` is also disabled and persistent mount material is removed. Temporary non-auto-unlock secrets are accepted for at most five minutes; expired material is rejected and removed together with its temporary credential capsule.

## Startup and mount lifecycle

```text
Windows user signs in
        │
        ├─ fully automatic entries → elevated registered mount task
        │                            reads DPAPI-protected mount credential
        │
        └─ prompt-once entries → OrIsyVra Encrypted Volumes startup GUI
                                  │
                                  ├─ unlock visual key once
                                  └─ start registered mount tasks
                                                │
                                                ▼
                                     open .orisyvra-volume
                                                │
                                                ▼
                                     WinSpd virtual SCSI disk
                                                │
                                                ▼
                                     Windows NTFS / exFAT
                                                │
                                                ▼
                                         preferred O:\
```

The mount host marks the encrypted container dirty before exposing it. On normal **Unmount** it receives a stop request, flushes storage, marks the authenticated volume clean, detaches the WinSpd disk and removes its mounted-state marker.

If the process is terminated before clean detach, the volume core uses authenticated A/B superblocks and committed-log recovery on the next open.

## Configuration storage

Current per-user root:

```text
%APPDATA%\OrIsyVra\automount\
```

It contains separate areas for:

```text
entries\       non-secret registration metadata
credentials\   dedicated mount key capsules
secrets\       DPAPI-protected random mount passwords
state\         mounted/stop coordination files
```

Registration files contain paths, preferences and policy flags. Sensitive unlock material is never embedded into the registration text.

## Windows startup/task registration

Two Windows mechanisms are used for different purposes:

- **HKCU Run entry** — starts the Encrypted Volumes GUI in `--startup-automount` mode when prompt-once volumes exist.
- **Task Scheduler** — each registered volume receives an elevated on-logon mount task for the WinSpd host. The GUI can also trigger that task manually after preparing a short-lived credential.

Registering/removing an elevated mount task requires Windows approval through UAC. Normal file/folder encryption does not require WinSpd or these tasks.

The installer itself does not silently enable an encrypted volume for auto-mount; the option is configured per volume in the GUI.

## Drive-letter policy

A registered preferred letter is remembered. After a new WinSpd volume appears, the host compares Windows volume GUIDs before/after attachment and attempts to assign the preferred letter using Windows `mountvol`.

If the preferred letter is already occupied, OrIsyVra does not steal it. Windows' existing assignment is kept and a diagnostic is emitted. Broad conflict UX is still being hardened.

## Failure behavior

The intended fail-safe behavior is:

- **visual key missing/wrong** → authentication fails; no volume reformat/rewrite;
- **temporary credential older than five minutes** → reject and delete temporary secret/credential;
- **auto-unlock configured while auto-mount is disabled** → reject/remove the stale protected material;
- **DPAPI blob unavailable/corrupt** → automatic task cannot unlock the volume; durable visual-key recovery remains available;
- **WinSpd runtime missing** → the Encrypted Volumes GUI reports runtime/host status; ordinary file/folder encryption remains usable;
- **volume authentication/corruption failure** → do not expose unauthenticated blocks as a valid disk;
- **drive letter occupied** → do not evict the existing Windows volume;
- **mounted-state marker refers to a dead process** → GUI removes the stale marker after checking the PID.

## Runtime dependency

The Windows virtual-disk layer uses external WinSpd. OrIsyVra currently:

- dynamically probes the WinSpd runtime;
- keeps it optional from file/folder encryption;
- does not silently download/install it;
- includes a GUI recheck/status path;
- bundles the OrIsyVra mount host in the Windows installer.

A one-click guided WinSpd installation flow is still open work.

## Validation status

Current CI verifies on Windows x64:

- `cargo test --workspace --all-features`;
- `cargo build --release --workspace`;
- presence of the file GUI, encrypted-volume GUI, CLI, analysis tool and mount host;
- Inno Setup installer creation;
- the normal release Defender/package validation path.

This does **not** replace real-machine interoperability testing. Remaining hardening includes multiple Windows/WinSpd versions, occupied drive letters, sleep/resume, sign-out/shutdown, force-kill during writes, Windows Update/reboot, disk-full conditions, large sequential/random I/O and broad application compatibility.
