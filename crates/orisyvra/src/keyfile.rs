use std::fs;
use std::io::Write;
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};

pub(crate) const KEY_MAGIC: &[u8; 8] = b"OYVKEY1\0";
const KEY_VERSION: u16 = 1;
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 24;
const MASTER_KEY_SIZE: usize = orisyvra_core::KEY_SIZE;
const WRAPPED_KEY_SIZE: usize = MASTER_KEY_SIZE + 16;
const HEADER_SIZE: usize = 64;
pub(crate) const KEYFILE_SIZE: usize = HEADER_SIZE + WRAPPED_KEY_SIZE;

#[derive(Clone, Copy, Debug)]
pub struct KeyfileParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KeyfileParams {
    fn default() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; MASTER_KEY_SIZE]);

impl MasterKey {
    pub fn as_bytes(&self) -> &[u8; MASTER_KEY_SIZE] {
        &self.0
    }
}

fn validate_password(password: &[u8]) -> Result<()> {
    if password.len() < 12 {
        return Err(Error::InvalidInput(
            "passphrase must contain at least 12 bytes".into(),
        ));
    }
    Ok(())
}

fn validate_params(params: KeyfileParams) -> Result<()> {
    if params.memory_kib < 8 * 1024 || params.memory_kib > 1024 * 1024 {
        return Err(Error::InvalidInput(
            "Argon2 memory must be between 8192 KiB and 1048576 KiB".into(),
        ));
    }
    if params.iterations == 0 || params.iterations > 32 {
        return Err(Error::InvalidInput(
            "Argon2 iterations must be between 1 and 32".into(),
        ));
    }
    if params.parallelism == 0 || params.parallelism > 16 {
        return Err(Error::InvalidInput(
            "Argon2 parallelism must be between 1 and 16".into(),
        ));
    }
    Ok(())
}

fn derive_wrapping_key(
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    params: KeyfileParams,
) -> Result<[u8; 32]> {
    validate_params(params)?;
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|_| Error::Crypto("invalid Argon2id parameters"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut wrapping_key = [0_u8; 32];
    argon2
        .hash_password_into(password, salt, &mut wrapping_key)
        .map_err(|_| Error::Crypto("Argon2id key derivation failed"))?;
    Ok(wrapping_key)
}

fn encode_header(
    params: KeyfileParams,
    salt: &[u8; SALT_SIZE],
    nonce: &[u8; NONCE_SIZE],
) -> [u8; HEADER_SIZE] {
    let mut header = [0_u8; HEADER_SIZE];
    header[..8].copy_from_slice(KEY_MAGIC);
    header[8..10].copy_from_slice(&KEY_VERSION.to_le_bytes());
    header[10..14].copy_from_slice(&params.memory_kib.to_le_bytes());
    header[14..18].copy_from_slice(&params.iterations.to_le_bytes());
    header[18..22].copy_from_slice(&params.parallelism.to_le_bytes());
    header[22..38].copy_from_slice(salt);
    header[38..62].copy_from_slice(nonce);
    header[62..64].copy_from_slice(&(WRAPPED_KEY_SIZE as u16).to_le_bytes());
    header
}

fn decode_header(
    bytes: &[u8; HEADER_SIZE],
) -> Result<(KeyfileParams, [u8; SALT_SIZE], [u8; NONCE_SIZE])> {
    if &bytes[..8] != KEY_MAGIC {
        return Err(Error::InvalidFormat("not an OrIsyVra key capsule"));
    }
    let version = u16::from_le_bytes(bytes[8..10].try_into().expect("fixed header"));
    if version != KEY_VERSION {
        return Err(Error::InvalidFormat("unsupported key capsule version"));
    }
    let params = KeyfileParams {
        memory_kib: u32::from_le_bytes(bytes[10..14].try_into().expect("fixed header")),
        iterations: u32::from_le_bytes(bytes[14..18].try_into().expect("fixed header")),
        parallelism: u32::from_le_bytes(bytes[18..22].try_into().expect("fixed header")),
    };
    validate_params(params)?;
    let mut salt = [0_u8; SALT_SIZE];
    salt.copy_from_slice(&bytes[22..38]);
    let mut nonce = [0_u8; NONCE_SIZE];
    nonce.copy_from_slice(&bytes[38..62]);
    let wrapped_size = u16::from_le_bytes(bytes[62..64].try_into().expect("fixed header"));
    if wrapped_size as usize != WRAPPED_KEY_SIZE {
        return Err(Error::InvalidFormat("unexpected wrapped-key length"));
    }
    Ok((params, salt, nonce))
}

pub(crate) fn validate_keyfile_bytes(bytes: &[u8]) -> Result<()> {
    if bytes.len() != KEYFILE_SIZE {
        return Err(Error::InvalidFormat("unexpected key capsule size"));
    }
    let header: [u8; HEADER_SIZE] = bytes[..HEADER_SIZE]
        .try_into()
        .map_err(|_| Error::InvalidFormat("truncated key capsule header"))?;
    decode_header(&header)?;
    Ok(())
}

pub(crate) fn encode_keyfile_bytes(
    master_key: &MasterKey,
    password: &[u8],
    params: KeyfileParams,
) -> Result<Vec<u8>> {
    validate_password(password)?;
    validate_params(params)?;
    let mut salt = [0_u8; SALT_SIZE];
    let mut nonce = [0_u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let header = encode_header(params, &salt, &nonce);
    let wrapping_key = Zeroizing::new(derive_wrapping_key(password, &salt, params)?);
    let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
        .map_err(|_| Error::Crypto("invalid wrapping key"))?;
    let wrapped = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: master_key.as_bytes(),
                aad: &header,
            },
        )
        .map_err(|_| Error::Crypto("key capsule encryption failed"))?;
    if wrapped.len() != WRAPPED_KEY_SIZE {
        return Err(Error::Crypto("unexpected key capsule size"));
    }
    let mut output = Vec::with_capacity(KEYFILE_SIZE);
    output.extend_from_slice(&header);
    output.extend_from_slice(&wrapped);
    Ok(output)
}

pub(crate) fn write_keyfile_bytes(path: &Path, bytes: &[u8], overwrite: bool) -> Result<()> {
    validate_keyfile_bytes(bytes)?;
    if path.exists() && !overwrite {
        return Err(Error::OutputExists(path.display().to_string()));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file_mut().sync_all()?;
    if path.exists() && overwrite {
        fs::remove_file(path)?;
    }
    temporary
        .persist(path)
        .map_err(|error| Error::Io(error.error))?;
    Ok(())
}

pub(crate) fn unlock_keyfile_bytes(bytes: &[u8], password: &[u8]) -> Result<MasterKey> {
    validate_keyfile_bytes(bytes)?;
    let header: [u8; HEADER_SIZE] = bytes[..HEADER_SIZE]
        .try_into()
        .map_err(|_| Error::InvalidFormat("truncated key capsule header"))?;
    let (params, salt, nonce) = decode_header(&header)?;
    let wrapping_key = Zeroizing::new(derive_wrapping_key(password, &salt, params)?);
    let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
        .map_err(|_| Error::Crypto("invalid wrapping key"))?;
    let mut plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &bytes[HEADER_SIZE..],
                aad: &header,
            },
        )
        .map_err(|_| Error::AuthenticationFailed)?;
    if plaintext.len() != MASTER_KEY_SIZE {
        plaintext.zeroize();
        return Err(Error::InvalidFormat("unexpected master-key size"));
    }
    let mut key = [0_u8; MASTER_KEY_SIZE];
    key.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(MasterKey(key))
}

pub fn create_keyfile(
    path: &Path,
    password: &[u8],
    params: KeyfileParams,
    overwrite: bool,
) -> Result<()> {
    validate_password(password)?;
    validate_params(params)?;
    let mut master_key = MasterKey([0_u8; MASTER_KEY_SIZE]);
    OsRng.fill_bytes(&mut master_key.0);
    let bytes = encode_keyfile_bytes(&master_key, password, params)?;
    write_keyfile_bytes(path, &bytes, overwrite)
}

pub fn unlock_keyfile(path: &Path, password: &[u8]) -> Result<MasterKey> {
    unlock_keyfile_bytes(&fs::read(path)?, password)
}

#[cfg(test)]
mod tests {
    use super::{
        create_keyfile, encode_keyfile_bytes, unlock_keyfile, unlock_keyfile_bytes, KeyfileParams,
    };

    #[test]
    fn keyfile_round_trip_and_wrong_password_rejection() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("test.orisyvra-key");
        let params = KeyfileParams {
            memory_kib: 8 * 1024,
            iterations: 1,
            parallelism: 1,
        };
        create_keyfile(&path, b"correct horse battery staple", params, false)
            .expect("create keyfile");
        let first = unlock_keyfile(&path, b"correct horse battery staple").expect("unlock keyfile");
        let second =
            unlock_keyfile(&path, b"correct horse battery staple").expect("unlock keyfile again");
        assert_eq!(first.as_bytes(), second.as_bytes());
        assert!(unlock_keyfile(&path, b"definitely the wrong password").is_err());
        let rewrapped = encode_keyfile_bytes(&first, b"different recovery passphrase", params)
            .expect("rewrap key");
        let recovered = unlock_keyfile_bytes(&rewrapped, b"different recovery passphrase")
            .expect("unlock rewrapped key");
        assert_eq!(first.as_bytes(), recovered.as_bytes());
    }
}
