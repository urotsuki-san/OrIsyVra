#![forbid(unsafe_code)]

//! File encryption, key capsules, and visual keys.

use std::path::Path;

mod container;
mod error;
mod fileops;
mod keycard;
mod keyfile;

pub use container::{inspect_file, EncryptOptions, FileInfo, Mode};
pub use error::{Error, Result};
pub use fileops::{decrypt_file, encrypt_file};
pub use keycard::{
    create_keycard, decode_keycard_image, export_keycard, export_recovery_keycard,
    export_recovery_keycard_from_master, import_keycard, key_source_info, unlock_key_source,
    KeyCardInfo,
};
pub use keyfile::{create_keyfile, unlock_keyfile, KeyfileParams, MasterKey};

/// Re-wrap an already-unlocked master key into a binary key capsule.
///
/// This is used by the Windows encrypted-volume integration to create a dedicated
/// mount credential without persisting the user's visual-key passphrase or a raw
/// master key. The caller should protect the independent `mount_passphrase` with
/// an OS credential facility such as Windows DPAPI.
pub fn export_recovery_keyfile_from_master(
    master: &MasterKey,
    mount_passphrase: &[u8],
    params: KeyfileParams,
    output: &Path,
    overwrite: bool,
) -> Result<()> {
    let bytes = keyfile::encode_keyfile_bytes(master, mount_passphrase, params)?;
    keyfile::write_keyfile_bytes(output, &bytes, overwrite)
}
