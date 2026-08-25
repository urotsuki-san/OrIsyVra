# Windows Automatic Volume Mounting

Status: **Windows alpha**

Automatic volume mounting is per-user and starts after Windows sign-in. Pre-login and system-volume mounting are not implemented.

## Connection policies

Each registered volume can use one of two sign-in policies.

### Prompt on sign-in

1. Windows starts `orisyvra-volume-gui.exe --startup-automount` through the current user's Run entry.
2. The GUI groups registered volumes by Visual Key path.
3. The user unlocks each required Visual Key once.
4. OrIsyVra creates short-lived mount credentials for the matching volumes.
5. The registered elevated mount tasks are started.

Windows PIN cards require the PNG, PIN, and the DPAPI-protected device binding described in [`PIN_CARDS.md`](PIN_CARDS.md).

Temporary credentials are one-shot and expire after five minutes.

### Fully automatic

Fully automatic mounting stores a dedicated random mount password protected with current-user Windows DPAPI.

When enabled, OrIsyVra:

1. creates a separate mount credential containing the same master key;
2. generates a random password for that credential;
3. protects the password with Windows DPAPI;
4. stores the DPAPI blob separately from registration metadata.

The original Visual Key PIN or passphrase is not stored. The raw master key is not stored as plaintext.

Disabling automatic connection also disables automatic unlock and removes persistent mount material for that entry.

## Startup flow

```text
Windows user signs in
        │
        ├─ fully automatic entry
        │      │
        │      └─ DPAPI-protected mount credential
        │                    │
        │                    ▼
        │             registered mount task
        │
        └─ prompt entry
               │
               └─ Encrypted Drives GUI
                      │
                      └─ unlock Visual Key
                              │
                              ▼
                       registered mount task
                              │
                              ▼
                       WinSpd virtual disk
                              │
                              ▼
                       Windows filesystem
```

The mount host authenticates the backing volume before exposing it through WinSpd.

## Configuration storage

Per-user mount state is stored under:

```text
%APPDATA%\OrIsyVra\automount\
```

Current subdirectories:

```text
entries\       registration metadata
credentials\   dedicated mount key capsules
secrets\       DPAPI-protected mount passwords
state\         mount and stop coordination files
```

Windows PIN-card bindings are stored separately under:

```text
%APPDATA%\OrIsyVra\pin-cards\
```

PIN-card binding files contain DPAPI-protected random device secrets. They do not contain the PIN or plaintext master key.

## Windows registration

Two Windows mechanisms are used:

- **HKCU Run** starts the Encrypted Drives GUI when prompt-based sign-in entries exist;
- **Task Scheduler** provides an elevated mount-host task for each registered volume.

The WinSpd mount host requires elevation. Task registration can therefore request UAC approval.

Normal file and folder encryption does not use these mechanisms.

## Mounted-state tracking

A mounted-state file records the mount-host PID and volume path. The GUI checks the PID before treating an entry as mounted and removes stale state files when the process is no longer present.

A separate stop marker requests clean disconnection.

## Drive-letter assignment

A preferred drive letter is stored with the registration entry.

After WinSpd attachment, the mount host compares Windows volume state before and after attachment to identify the new volume. It then:

1. checks whether the preferred letter is free;
2. assigns that letter to the new volume;
3. verifies the assignment;
4. removes any temporary Windows-assigned letter.

An occupied preferred letter is left unchanged.

## Clean disconnection

On **Safely disconnect**, the mount host:

1. requests Windows to dismount and remove the active drive-letter mount point;
2. synchronizes the encrypted backing volume;
3. shuts down the WinSpd storage unit;
4. marks the authenticated volume clean;
5. removes state and stop markers.

If clean disconnection does not complete, the volume remains dirty and is recovered from its authenticated committed state on the next open.

## Failure handling

| Condition | Result |
|---|---|
| PIN-card binding missing | unlock is rejected |
| wrong PIN or passphrase | authentication fails |
| temporary credential expired | credential and temporary secret are removed |
| DPAPI blob missing or corrupt | automatic unlock fails |
| WinSpd runtime unavailable | mount fails; file encryption remains available |
| backing-volume authentication fails | virtual disk is not exposed |
| preferred drive letter occupied | Windows assignment is retained |
| duplicate mount request | per-entry mutex prevents a second host instance |
| backing file already open for write | exclusive file open fails |

## Security boundary

Fully automatic mounting moves the unlock boundary to the current Windows user account. A process with sufficient access to that account may be able to invoke DPAPI or access data after the volume is mounted.

Prompt-based mounting retains a user credential step at sign-in but still depends on the security of the active Windows session.

See [`THREAT_MODEL.md`](THREAT_MODEL.md).

## Validation

The release workflow builds and tests the Windows GUI, mount host, CLI, analysis tool, and installer. Real-machine testing across WinSpd versions, sleep/resume, shutdown, disk-full conditions, large random I/O, and application compatibility remains ongoing.
