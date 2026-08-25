#![forbid(unsafe_code)]

//! Windows device-bound four-digit PIN visual keys.
//!
//! The PIN is deliberately not treated as cryptographic entropy. A random
//! 256-bit device secret is protected with Windows DPAPI and combined with the
//! four-digit PIN before it is passed to OrIsyVra's existing Argon2id key
//! capsule. A copied PNG therefore cannot be brute-forced from the PIN alone on
//! another Windows account or device.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use orisyvra::{
    create_keycard, export_recovery_keycard_from_master, key_source_info, unlock_key_source,
    KeyCardInfo, KeyfileParams, MasterKey,
};
use orisyvra_windows::{protect_current_user, unprotect_current_user};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

const DEVICE_SECRET_SIZE: usize = 32;
const BINDING_MAGIC: &[u8; 8] = b"OYVPIN1\0";
const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
const PIN_CHUNK_TYPE: &[u8; 4] = b"orPn";
const PIN_CHUNK_DATA: &[u8; 12] = b"OYVPIN1\0\x01\0\0\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinCardState {
    /// This is a legacy/passphrase visual key, not a device-bound PIN card.
    NotPinCard,
    /// The PNG is a PIN card and the current Windows user has its DPAPI binding.
    Ready,
    /// The PNG is a PIN card but the device binding is absent on this machine.
    BindingMissing,
}

pub fn pin_is_valid(pin: &str) -> bool {
    pin.len() == 4 && pin.bytes().all(|value| value.is_ascii_digit())
}

fn validate_pin(pin: &str) -> Result<(), String> {
    if pin_is_valid(pin) {
        Ok(())
    } else {
        Err("PIN must contain exactly four digits".to_owned())
    }
}

fn binding_root() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        let base = std::env::var_os("APPDATA")
            .ok_or_else(|| "APPDATA is unavailable for PIN-card storage".to_owned())?;
        Ok(PathBuf::from(base).join("OrIsyVra").join("pin-cards"))
    }
    #[cfg(not(windows))]
    {
        Err("device-bound PIN cards are currently available on Windows only".to_owned())
    }
}

fn validate_card_id(card_id: &str) -> Result<(), String> {
    if card_id.len() == 16 && card_id.bytes().all(|value| value.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("invalid visual-key fingerprint".to_owned())
    }
}

fn binding_path(card_id: &str) -> Result<PathBuf, String> {
    validate_card_id(card_id)?;
    Ok(binding_root()?.join(format!("{}.dpapi", card_id.to_ascii_uppercase())))
}

fn credential(device_secret: &[u8; DEVICE_SECRET_SIZE], pin: &str) -> Zeroizing<Vec<u8>> {
    let mut value = Vec::with_capacity(64);
    value.extend_from_slice(b"OrIsyVra/device-pin/v1\0");
    value.extend_from_slice(device_secret);
    value.extend_from_slice(pin.as_bytes());
    Zeroizing::new(value)
}

fn store_binding(card_id: &str, device_secret: &[u8; DEVICE_SECRET_SIZE]) -> Result<(), String> {
    let path = binding_path(card_id)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let mut plaintext = Vec::with_capacity(BINDING_MAGIC.len() + DEVICE_SECRET_SIZE);
    plaintext.extend_from_slice(BINDING_MAGIC);
    plaintext.extend_from_slice(device_secret);
    let protected = protect_current_user(&plaintext).map_err(|error| error.to_string());
    plaintext.zeroize();
    let protected = protected?;
    write_atomic(&protected, &path, true)
}

fn load_binding(card_id: &str) -> Result<[u8; DEVICE_SECRET_SIZE], String> {
    let path = binding_path(card_id)?;
    let mut protected = fs::read(&path).map_err(|_| {
        "this PIN card is not registered to the current Windows account".to_owned()
    })?;
    let mut plaintext = unprotect_current_user(&protected).map_err(|error| error.to_string())?;
    protected.zeroize();
    if plaintext.len() != BINDING_MAGIC.len() + DEVICE_SECRET_SIZE
        || &plaintext[..BINDING_MAGIC.len()] != BINDING_MAGIC
    {
        plaintext.zeroize();
        return Err("invalid PIN-card device binding".to_owned());
    }
    let mut secret = [0_u8; DEVICE_SECRET_SIZE];
    secret.copy_from_slice(&plaintext[BINDING_MAGIC.len()..]);
    plaintext.zeroize();
    Ok(secret)
}

fn write_atomic(bytes: &[u8], output: &Path, overwrite: bool) -> Result<(), String> {
    if output.exists() && !overwrite {
        return Err(format!("output already exists: {}", output.display()));
    }
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let mut temporary = tempfile_path(parent)?;
    temporary
        .1
        .write_all(bytes)
        .map_err(|error| error.to_string())?;
    temporary
        .1
        .sync_all()
        .map_err(|error| error.to_string())?;
    drop(temporary.1);
    if output.exists() && overwrite {
        fs::remove_file(output).map_err(|error| error.to_string())?;
    }
    fs::rename(&temporary.0, output).map_err(|error| {
        let _ = fs::remove_file(&temporary.0);
        error.to_string()
    })
}

fn tempfile_path(parent: &Path) -> Result<(PathBuf, fs::File), String> {
    for attempt in 0..128_u64 {
        let value = OsRng.next_u64() ^ attempt;
        let path = parent.join(format!(".orisyvra-pin-{value:016x}.tmp"));
        match fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.to_string()),
        }
    }
    Err("could not create temporary PIN-card file".to_owned())
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320_u32 & mask);
        }
    }
    !crc
}

fn marker_present(png: &[u8]) -> bool {
    if !png.starts_with(PNG_SIGNATURE) {
        return false;
    }
    let mut cursor = PNG_SIGNATURE.len();
    while cursor + 12 <= png.len() {
        let Ok(length_bytes) = png[cursor..cursor + 4].try_into() else {
            return false;
        };
        let length = u32::from_be_bytes(length_bytes) as usize;
        let Some(data_end) = cursor.checked_add(8 + length) else {
            return false;
        };
        let Some(end) = data_end.checked_add(4) else {
            return false;
        };
        if end > png.len() {
            return false;
        }
        let chunk_type = &png[cursor + 4..cursor + 8];
        if chunk_type == PIN_CHUNK_TYPE {
            let data = &png[cursor + 8..data_end];
            if data != PIN_CHUNK_DATA {
                return false;
            }
            let mut crc_input = Vec::with_capacity(4 + data.len());
            crc_input.extend_from_slice(PIN_CHUNK_TYPE);
            crc_input.extend_from_slice(data);
            let stored = u32::from_be_bytes(png[data_end..end].try_into().unwrap_or([0; 4]));
            return stored == crc32(&crc_input);
        }
        cursor = end;
        if chunk_type == b"IEND" {
            break;
        }
    }
    false
}

fn add_pin_marker(png: &[u8]) -> Result<Vec<u8>, String> {
    if marker_present(png) {
        return Ok(png.to_vec());
    }
    if !png.starts_with(PNG_SIGNATURE) {
        return Err("PIN visual key is not a PNG".to_owned());
    }
    let mut crc_input = Vec::with_capacity(4 + PIN_CHUNK_DATA.len());
    crc_input.extend_from_slice(PIN_CHUNK_TYPE);
    crc_input.extend_from_slice(PIN_CHUNK_DATA);
    let marker_crc = crc32(&crc_input);

    let mut output = Vec::with_capacity(png.len() + PIN_CHUNK_DATA.len() + 12);
    output.extend_from_slice(PNG_SIGNATURE);
    let mut cursor = PNG_SIGNATURE.len();
    let mut inserted = false;
    while cursor + 12 <= png.len() {
        let length = u32::from_be_bytes(
            png[cursor..cursor + 4]
                .try_into()
                .map_err(|_| "invalid PNG chunk length")?,
        ) as usize;
        let end = cursor
            .checked_add(12 + length)
            .ok_or_else(|| "invalid PNG chunk length".to_owned())?;
        if end > png.len() {
            return Err("truncated PNG".to_owned());
        }
        let chunk_type = &png[cursor + 4..cursor + 8];
        if chunk_type == b"IEND" && !inserted {
            output.extend_from_slice(&(PIN_CHUNK_DATA.len() as u32).to_be_bytes());
            output.extend_from_slice(PIN_CHUNK_TYPE);
            output.extend_from_slice(PIN_CHUNK_DATA);
            output.extend_from_slice(&marker_crc.to_be_bytes());
            inserted = true;
        }
        output.extend_from_slice(&png[cursor..end]);
        cursor = end;
        if chunk_type == b"IEND" {
            break;
        }
    }
    if !inserted {
        return Err("PNG IEND chunk was not found".to_owned());
    }
    Ok(output)
}

fn mark_pin_card(path: &Path) -> Result<(), String> {
    let original = fs::read(path).map_err(|error| error.to_string())?;
    let marked = add_pin_marker(&original)?;
    write_atomic(&marked, path, true)
}

pub fn pin_card_state(source: &Path) -> Result<PinCardState, String> {
    let bytes = fs::read(source).map_err(|error| error.to_string())?;
    if !marker_present(&bytes) {
        return Ok(PinCardState::NotPinCard);
    }
    let info = key_source_info(source).map_err(|error| error.to_string())?;
    match binding_path(&info.card_id) {
        Ok(path) if path.is_file() => Ok(PinCardState::Ready),
        _ => Ok(PinCardState::BindingMissing),
    }
}

pub fn create_pin_card(
    output: &Path,
    pin: &str,
    params: KeyfileParams,
    overwrite: bool,
) -> Result<KeyCardInfo, String> {
    validate_pin(pin)?;
    if !cfg!(windows) {
        return Err("device-bound PIN cards are currently available on Windows only".to_owned());
    }
    let mut device_secret = [0_u8; DEVICE_SECRET_SIZE];
    OsRng.fill_bytes(&mut device_secret);
    let password = credential(&device_secret, pin);
    let result = (|| {
        create_keycard(output, password.as_slice(), params, overwrite)
            .map_err(|error| error.to_string())?;
        mark_pin_card(output)?;
        let info = key_source_info(output).map_err(|error| error.to_string())?;
        store_binding(&info.card_id, &device_secret)?;
        Ok(info)
    })();
    device_secret.zeroize();
    if result.is_err() {
        let _ = fs::remove_file(output);
    }
    result
}

pub fn create_pin_card_from_master(
    master: &MasterKey,
    output: &Path,
    pin: &str,
    params: KeyfileParams,
    overwrite: bool,
) -> Result<KeyCardInfo, String> {
    validate_pin(pin)?;
    if !cfg!(windows) {
        return Err("device-bound PIN cards are currently available on Windows only".to_owned());
    }
    let mut device_secret = [0_u8; DEVICE_SECRET_SIZE];
    OsRng.fill_bytes(&mut device_secret);
    let password = credential(&device_secret, pin);
    let result = (|| {
        export_recovery_keycard_from_master(master, password.as_slice(), params, output, overwrite)
            .map_err(|error| error.to_string())?;
        mark_pin_card(output)?;
        let info = key_source_info(output).map_err(|error| error.to_string())?;
        store_binding(&info.card_id, &device_secret)?;
        Ok(info)
    })();
    device_secret.zeroize();
    if result.is_err() {
        let _ = fs::remove_file(output);
    }
    result
}

pub fn unlock_pin_card(source: &Path, pin: &str) -> Result<MasterKey, String> {
    validate_pin(pin)?;
    if pin_card_state(source)? == PinCardState::BindingMissing {
        return Err(
            "this PIN card belongs to another Windows account or its device binding is missing"
                .to_owned(),
        );
    }
    if pin_card_state(source)? != PinCardState::Ready {
        return Err("the selected visual key is not a device-bound PIN card".to_owned());
    }
    let info = key_source_info(source).map_err(|error| error.to_string())?;
    let mut device_secret = load_binding(&info.card_id)?;
    let password = credential(&device_secret, pin);
    let result = unlock_key_source(source, password.as_slice()).map_err(|error| error.to_string());
    device_secret.zeroize();
    result
}

pub fn copy_pin_card(source: &Path, output: &Path, overwrite: bool) -> Result<KeyCardInfo, String> {
    if pin_card_state(source)? == PinCardState::NotPinCard {
        return Err("the selected key is not a PIN card".to_owned());
    }
    let bytes = fs::read(source).map_err(|error| error.to_string())?;
    write_atomic(&bytes, output, overwrite)?;
    key_source_info(output).map_err(|error| error.to_string())
}

pub fn remove_pin_binding(source: &Path) -> Result<(), String> {
    let info = key_source_info(source).map_err(|error| error.to_string())?;
    let path = binding_path(&info.card_id)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{marker_present, pin_is_valid, PIN_CHUNK_DATA, PIN_CHUNK_TYPE};

    #[test]
    fn pin_validation_is_strictly_four_ascii_digits() {
        assert!(pin_is_valid("0000"));
        assert!(pin_is_valid("9182"));
        assert!(!pin_is_valid("123"));
        assert!(!pin_is_valid("12345"));
        assert!(!pin_is_valid("１２３４"));
        assert!(!pin_is_valid("12a4"));
    }

    #[test]
    fn marker_parser_rejects_non_png() {
        assert!(!marker_present(b"not a png"));
        assert_eq!(PIN_CHUNK_TYPE.len(), 4);
        assert_eq!(PIN_CHUNK_DATA.len(), 12);
    }
}
