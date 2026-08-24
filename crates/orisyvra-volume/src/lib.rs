#![forbid(unsafe_code)]

//! Authenticated random-access encrypted volume core for the future mountable-drive feature.
//!
//! This crate deliberately stops below the filesystem/mount layer. It provides a sparse,
//! append-only authenticated block log, two alternating authenticated superblocks, crash-safe
//! commit ordering, and keyed random access by logical block number.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use orisyvra::MasterKey;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Sha256, Sha384};
use zeroize::{Zeroize, ZeroizeOnDrop};

const VOLUME_MAGIC: &[u8; 8] = b"OYVVOL1\0";
const VOLUME_VERSION: u16 = 1;
const BOOTSTRAP_SIZE: usize = 256;
const SUPER_SLOT_SIZE: usize = 512;
const SUPER_A_OFFSET: u64 = BOOTSTRAP_SIZE as u64;
const SUPER_B_OFFSET: u64 = SUPER_A_OFFSET + SUPER_SLOT_SIZE as u64;
const LOG_START: u64 = 4096;
const SUPER_PLAINTEXT_SIZE: usize = 64;
const SUPER_MAGIC: &[u8; 8] = b"OYVSB1\0\0";
const RECORD_MAGIC: &[u8; 4] = b"OYVB";
const RECORD_HEADER_SIZE: usize = 32;
const AEAD_TAG_SIZE: usize = 16;
const MIN_BLOCK_SIZE: u32 = 4096;
const MAX_BLOCK_SIZE: u32 = 16 * 1024 * 1024;
const DEFAULT_BLOCK_SIZE: u32 = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum VolumeError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid volume format: {0}")]
    InvalidFormat(&'static str),
    #[error("invalid volume input: {0}")]
    InvalidInput(String),
    #[error("volume authentication failed")]
    AuthenticationFailed,
    #[error("volume data is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("logical block is outside the configured capacity")]
    BlockOutOfRange,
}

pub type Result<T> = std::result::Result<T, VolumeError>;

#[derive(Clone, Copy, Debug)]
pub struct VolumeOptions {
    pub logical_capacity: u64,
    pub block_size: u32,
}

impl VolumeOptions {
    pub fn new(logical_capacity: u64) -> Self {
        Self {
            logical_capacity,
            block_size: DEFAULT_BLOCK_SIZE,
        }
    }
}

#[derive(Clone, Debug)]
pub struct VolumeInfo {
    pub version: u16,
    pub logical_capacity: u64,
    pub block_size: u32,
    pub volume_id: [u8; 32],
    pub generation: u64,
    pub clean: bool,
    pub record_count: u64,
    pub allocated_blocks: usize,
}

#[derive(Clone)]
struct Bootstrap {
    version: u16,
    logical_capacity: u64,
    block_size: u32,
    volume_id: [u8; 32],
    salt: [u8; 32],
}

impl Bootstrap {
    fn new(options: VolumeOptions) -> Result<Self> {
        validate_options(options)?;
        let mut volume_id = [0_u8; 32];
        let mut salt = [0_u8; 32];
        OsRng.fill_bytes(&mut volume_id);
        OsRng.fill_bytes(&mut salt);
        Ok(Self {
            version: VOLUME_VERSION,
            logical_capacity: options.logical_capacity,
            block_size: options.block_size,
            volume_id,
            salt,
        })
    }

    fn encode(&self) -> [u8; BOOTSTRAP_SIZE] {
        let mut bytes = [0_u8; BOOTSTRAP_SIZE];
        bytes[..8].copy_from_slice(VOLUME_MAGIC);
        bytes[8..10].copy_from_slice(&self.version.to_le_bytes());
        bytes[10..14].copy_from_slice(&self.block_size.to_le_bytes());
        bytes[14..22].copy_from_slice(&self.logical_capacity.to_le_bytes());
        bytes[22..54].copy_from_slice(&self.volume_id);
        bytes[54..86].copy_from_slice(&self.salt);
        bytes[86..94].copy_from_slice(&LOG_START.to_le_bytes());
        bytes
    }

    fn decode(bytes: &[u8; BOOTSTRAP_SIZE]) -> Result<Self> {
        if &bytes[..8] != VOLUME_MAGIC {
            return Err(VolumeError::InvalidFormat("not an OrIsyVra volume"));
        }
        let version = u16::from_le_bytes(bytes[8..10].try_into().expect("fixed field"));
        if version != VOLUME_VERSION {
            return Err(VolumeError::InvalidFormat("unsupported volume version"));
        }
        let block_size = u32::from_le_bytes(bytes[10..14].try_into().expect("fixed field"));
        let logical_capacity = u64::from_le_bytes(bytes[14..22].try_into().expect("fixed field"));
        let log_start = u64::from_le_bytes(bytes[86..94].try_into().expect("fixed field"));
        if log_start != LOG_START {
            return Err(VolumeError::InvalidFormat("unexpected volume log offset"));
        }
        validate_options(VolumeOptions {
            logical_capacity,
            block_size,
        })?;
        let mut volume_id = [0_u8; 32];
        volume_id.copy_from_slice(&bytes[22..54]);
        let mut salt = [0_u8; 32];
        salt.copy_from_slice(&bytes[54..86]);
        Ok(Self {
            version,
            logical_capacity,
            block_size,
            volume_id,
            salt,
        })
    }

    fn block_count(&self) -> u64 {
        let block = self.block_size as u64;
        self.logical_capacity / block + u64::from(self.logical_capacity % block != 0)
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct VolumeKeys {
    key: [u8; 32],
    nonce_key: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
struct SuperState {
    generation: u64,
    committed_end: u64,
    record_count: u64,
    clean: bool,
}

impl SuperState {
    fn encode(self) -> [u8; SUPER_PLAINTEXT_SIZE] {
        let mut bytes = [0_u8; SUPER_PLAINTEXT_SIZE];
        bytes[..8].copy_from_slice(SUPER_MAGIC);
        bytes[8..16].copy_from_slice(&self.generation.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.committed_end.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.record_count.to_le_bytes());
        bytes[32] = u8::from(self.clean);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SUPER_PLAINTEXT_SIZE || &bytes[..8] != SUPER_MAGIC {
            return Err(VolumeError::Corrupt("invalid superblock payload"));
        }
        let generation = u64::from_le_bytes(bytes[8..16].try_into().expect("fixed field"));
        let committed_end = u64::from_le_bytes(bytes[16..24].try_into().expect("fixed field"));
        let record_count = u64::from_le_bytes(bytes[24..32].try_into().expect("fixed field"));
        let clean = match bytes[32] {
            0 => false,
            1 => true,
            _ => return Err(VolumeError::Corrupt("invalid superblock clean flag")),
        };
        if committed_end < LOG_START {
            return Err(VolumeError::Corrupt(
                "superblock points before the data log",
            ));
        }
        Ok(Self {
            generation,
            committed_end,
            record_count,
            clean,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct RecordHeader {
    block_index: u64,
    generation: u64,
    plaintext_len: u32,
    ciphertext_len: u32,
}

impl RecordHeader {
    fn encode(self) -> [u8; RECORD_HEADER_SIZE] {
        let mut bytes = [0_u8; RECORD_HEADER_SIZE];
        bytes[..4].copy_from_slice(RECORD_MAGIC);
        bytes[4..12].copy_from_slice(&self.block_index.to_le_bytes());
        bytes[12..20].copy_from_slice(&self.generation.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.plaintext_len.to_le_bytes());
        bytes[24..28].copy_from_slice(&self.ciphertext_len.to_le_bytes());
        bytes
    }

    fn decode(bytes: &[u8; RECORD_HEADER_SIZE]) -> Result<Self> {
        if &bytes[..4] != RECORD_MAGIC {
            return Err(VolumeError::Corrupt("invalid block-record magic"));
        }
        if bytes[28..32] != [0, 0, 0, 0] {
            return Err(VolumeError::Corrupt("unsupported block-record flags"));
        }
        let block_index = u64::from_le_bytes(bytes[4..12].try_into().expect("fixed field"));
        let generation = u64::from_le_bytes(bytes[12..20].try_into().expect("fixed field"));
        let plaintext_len = u32::from_le_bytes(bytes[20..24].try_into().expect("fixed field"));
        let ciphertext_len = u32::from_le_bytes(bytes[24..28].try_into().expect("fixed field"));
        if ciphertext_len as usize != plaintext_len as usize + AEAD_TAG_SIZE {
            return Err(VolumeError::Corrupt("invalid encrypted block length"));
        }
        Ok(Self {
            block_index,
            generation,
            plaintext_len,
            ciphertext_len,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct RecordIndex {
    offset: u64,
    generation: u64,
    plaintext_len: u32,
    ciphertext_len: u32,
}

pub struct Volume {
    path: PathBuf,
    file: File,
    bootstrap: Bootstrap,
    keys: VolumeKeys,
    state: SuperState,
    active_super: u8,
    index: HashMap<u64, RecordIndex>,
}

impl Volume {
    pub fn create(path: &Path, master: &MasterKey, options: VolumeOptions) -> Result<Self> {
        let bootstrap = Bootstrap::new(options)?;
        let keys = derive_keys(master, &bootstrap)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(&bootstrap.encode())?;
        file.set_len(LOG_START)?;

        let primary = SuperState {
            generation: 1,
            committed_end: LOG_START,
            record_count: 0,
            clean: true,
        };
        let backup = SuperState {
            generation: 0,
            committed_end: LOG_START,
            record_count: 0,
            clean: true,
        };
        write_superblock(&mut file, &bootstrap, &keys, 0, primary)?;
        write_superblock(&mut file, &bootstrap, &keys, 1, backup)?;
        file.sync_all()?;

        Ok(Self {
            path: path.to_path_buf(),
            file,
            bootstrap,
            keys,
            state: primary,
            active_super: 0,
            index: HashMap::new(),
        })
    }

    pub fn open(path: &Path, master: &MasterKey) -> Result<Self> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let mut bootstrap_bytes = [0_u8; BOOTSTRAP_SIZE];
        file.read_exact(&mut bootstrap_bytes)?;
        let bootstrap = Bootstrap::decode(&bootstrap_bytes)?;
        let keys = derive_keys(master, &bootstrap)?;

        let mut candidates = Vec::new();
        for slot in 0_u8..=1 {
            if let Ok(Some(state)) = read_superblock(&mut file, &bootstrap, &keys, slot) {
                candidates.push((slot, state));
            }
        }
        if candidates.is_empty() {
            return Err(VolumeError::AuthenticationFailed);
        }
        candidates.sort_by_key(|left| std::cmp::Reverse(left.1.generation));

        let file_len = file.metadata()?.len();
        for (slot, state) in candidates {
            if state.committed_end > file_len {
                continue;
            }
            if let Ok(index) = scan_log(&mut file, &bootstrap, &keys, state) {
                if file_len > state.committed_end {
                    file.set_len(state.committed_end)?;
                    file.sync_all()?;
                }
                return Ok(Self {
                    path: path.to_path_buf(),
                    file,
                    bootstrap,
                    keys,
                    state,
                    active_super: slot,
                    index,
                });
            }
        }
        Err(VolumeError::Corrupt(
            "no authenticated superblock has a valid committed log",
        ))
    }

    pub fn inspect_public(path: &Path) -> Result<VolumeInfo> {
        let mut file = File::open(path)?;
        let mut bytes = [0_u8; BOOTSTRAP_SIZE];
        file.read_exact(&mut bytes)?;
        let bootstrap = Bootstrap::decode(&bytes)?;
        Ok(VolumeInfo {
            version: bootstrap.version,
            logical_capacity: bootstrap.logical_capacity,
            block_size: bootstrap.block_size,
            volume_id: bootstrap.volume_id,
            generation: 0,
            clean: false,
            record_count: 0,
            allocated_blocks: 0,
        })
    }

    pub fn info(&self) -> VolumeInfo {
        VolumeInfo {
            version: self.bootstrap.version,
            logical_capacity: self.bootstrap.logical_capacity,
            block_size: self.bootstrap.block_size,
            volume_id: self.bootstrap.volume_id,
            generation: self.state.generation,
            clean: self.state.clean,
            record_count: self.state.record_count,
            allocated_blocks: self.index.len(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn block_count(&self) -> u64 {
        self.bootstrap.block_count()
    }

    pub fn read_block(&mut self, block_index: u64) -> Result<Option<Vec<u8>>> {
        self.validate_block_index(block_index)?;
        let Some(record) = self.index.get(&block_index).copied() else {
            return Ok(None);
        };
        let (header, plaintext) =
            read_record_at(&mut self.file, &self.bootstrap, &self.keys, record.offset)?;
        if header.block_index != block_index
            || header.generation != record.generation
            || header.plaintext_len != record.plaintext_len
            || header.ciphertext_len != record.ciphertext_len
        {
            return Err(VolumeError::Corrupt("block index metadata mismatch"));
        }
        Ok(Some(plaintext))
    }

    pub fn write_block(&mut self, block_index: u64, plaintext: &[u8]) -> Result<u64> {
        self.validate_block_index(block_index)?;
        if plaintext.len() > self.bootstrap.block_size as usize {
            return Err(VolumeError::InvalidInput(format!(
                "block payload exceeds {} bytes",
                self.bootstrap.block_size
            )));
        }
        let generation = self
            .index
            .get(&block_index)
            .map(|record| record.generation.saturating_add(1))
            .unwrap_or(1);
        if generation == 0 {
            return Err(VolumeError::InvalidInput(
                "block generation exhausted".to_owned(),
            ));
        }
        let plaintext_len = u32::try_from(plaintext.len())
            .map_err(|_| VolumeError::InvalidInput("block payload is too large".to_owned()))?;
        let ciphertext_len = plaintext_len
            .checked_add(AEAD_TAG_SIZE as u32)
            .ok_or_else(|| VolumeError::InvalidInput("block length overflow".to_owned()))?;
        let header = RecordHeader {
            block_index,
            generation,
            plaintext_len,
            ciphertext_len,
        };
        let header_bytes = header.encode();
        let nonce = record_nonce(&self.keys, &self.bootstrap, block_index, generation);
        let aad = record_aad(&self.bootstrap, &header_bytes);
        let cipher = XChaCha20Poly1305::new_from_slice(&self.keys.key)
            .map_err(|_| VolumeError::AuthenticationFailed)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| VolumeError::AuthenticationFailed)?;

        let offset = self.state.committed_end;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(&header_bytes)?;
        self.file.write_all(&ciphertext)?;
        self.file.sync_data()?;

        let committed_end = offset
            .checked_add(RECORD_HEADER_SIZE as u64)
            .and_then(|value| value.checked_add(ciphertext.len() as u64))
            .ok_or_else(|| VolumeError::InvalidInput("volume offset overflow".to_owned()))?;
        let next_state = SuperState {
            generation: self.state.generation.saturating_add(1),
            committed_end,
            record_count: self.state.record_count.saturating_add(1),
            clean: false,
        };
        if next_state.generation == 0 {
            return Err(VolumeError::InvalidInput(
                "superblock generation exhausted".to_owned(),
            ));
        }
        let next_slot = 1 - self.active_super;
        write_superblock(
            &mut self.file,
            &self.bootstrap,
            &self.keys,
            next_slot,
            next_state,
        )?;
        self.file.sync_all()?;

        self.index.insert(
            block_index,
            RecordIndex {
                offset,
                generation,
                plaintext_len,
                ciphertext_len,
            },
        );
        self.state = next_state;
        self.active_super = next_slot;
        Ok(generation)
    }

    pub fn mark_clean(&mut self) -> Result<()> {
        self.set_clean_state(true)
    }

    pub fn mark_dirty(&mut self) -> Result<()> {
        self.set_clean_state(false)
    }

    pub fn sync(&mut self) -> Result<()> {
        self.file.sync_all()?;
        Ok(())
    }

    pub fn block_generation(&self, block_index: u64) -> Result<Option<u64>> {
        self.validate_block_index(block_index)?;
        Ok(self.index.get(&block_index).map(|record| record.generation))
    }

    fn set_clean_state(&mut self, clean: bool) -> Result<()> {
        if self.state.clean == clean {
            return Ok(());
        }
        let next_state = SuperState {
            generation: self.state.generation.saturating_add(1),
            clean,
            ..self.state
        };
        if next_state.generation == 0 {
            return Err(VolumeError::InvalidInput(
                "superblock generation exhausted".to_owned(),
            ));
        }
        let next_slot = 1 - self.active_super;
        write_superblock(
            &mut self.file,
            &self.bootstrap,
            &self.keys,
            next_slot,
            next_state,
        )?;
        self.file.sync_all()?;
        self.state = next_state;
        self.active_super = next_slot;
        Ok(())
    }

    fn validate_block_index(&self, block_index: u64) -> Result<()> {
        if block_index >= self.bootstrap.block_count() {
            return Err(VolumeError::BlockOutOfRange);
        }
        Ok(())
    }
}

fn validate_options(options: VolumeOptions) -> Result<()> {
    if options.logical_capacity == 0 {
        return Err(VolumeError::InvalidInput(
            "logical capacity must be greater than zero".to_owned(),
        ));
    }
    if !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&options.block_size)
        || !options.block_size.is_power_of_two()
    {
        return Err(VolumeError::InvalidInput(format!(
            "block size must be a power of two between {MIN_BLOCK_SIZE} and {MAX_BLOCK_SIZE}"
        )));
    }
    Ok(())
}

fn derive_keys(master: &MasterKey, bootstrap: &Bootstrap) -> Result<VolumeKeys> {
    let hkdf = Hkdf::<Sha384>::new(Some(&bootstrap.salt), master.as_bytes());
    let mut output = [0_u8; 64];
    let mut info = Vec::with_capacity(80);
    info.extend_from_slice(b"OrIsyVra/volume/guarded/v1");
    info.extend_from_slice(&bootstrap.volume_id);
    hkdf.expand(&info, &mut output)
        .map_err(|_| VolumeError::AuthenticationFailed)?;
    let mut key = [0_u8; 32];
    key.copy_from_slice(&output[..32]);
    let mut nonce_key = [0_u8; 32];
    nonce_key.copy_from_slice(&output[32..]);
    output.zeroize();
    Ok(VolumeKeys { key, nonce_key })
}

fn derive_nonce(
    keys: &VolumeKeys,
    bootstrap: &Bootstrap,
    domain: &[u8],
    first: u64,
    second: u64,
) -> [u8; 24] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&keys.nonce_key)
        .expect("HMAC accepts arbitrary key lengths");
    mac.update(b"OrIsyVra/volume/nonce/v1");
    mac.update(&bootstrap.volume_id);
    mac.update(&(domain.len() as u64).to_le_bytes());
    mac.update(domain);
    mac.update(&first.to_le_bytes());
    mac.update(&second.to_le_bytes());
    let digest = mac.finalize().into_bytes();
    let mut nonce = [0_u8; 24];
    nonce.copy_from_slice(&digest[..24]);
    nonce
}

fn super_offset(slot: u8) -> Result<u64> {
    match slot {
        0 => Ok(SUPER_A_OFFSET),
        1 => Ok(SUPER_B_OFFSET),
        _ => Err(VolumeError::InvalidInput(
            "invalid superblock slot".to_owned(),
        )),
    }
}

fn super_aad(bootstrap: &Bootstrap, slot: u8, generation: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(BOOTSTRAP_SIZE + 16);
    aad.extend_from_slice(&bootstrap.encode());
    aad.extend_from_slice(b"super");
    aad.push(slot);
    aad.extend_from_slice(&generation.to_le_bytes());
    aad
}

fn write_superblock(
    file: &mut File,
    bootstrap: &Bootstrap,
    keys: &VolumeKeys,
    slot: u8,
    state: SuperState,
) -> Result<()> {
    let nonce = derive_nonce(keys, bootstrap, b"super", slot as u64, state.generation);
    let aad = super_aad(bootstrap, slot, state.generation);
    let cipher = XChaCha20Poly1305::new_from_slice(&keys.key)
        .map_err(|_| VolumeError::AuthenticationFailed)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &state.encode(),
                aad: &aad,
            },
        )
        .map_err(|_| VolumeError::AuthenticationFailed)?;
    if ciphertext.len() + 16 > SUPER_SLOT_SIZE {
        return Err(VolumeError::InvalidInput(
            "superblock payload exceeds its slot".to_owned(),
        ));
    }
    let mut bytes = [0_u8; SUPER_SLOT_SIZE];
    bytes[..8].copy_from_slice(&state.generation.to_le_bytes());
    bytes[8..12].copy_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    bytes[16..16 + ciphertext.len()].copy_from_slice(&ciphertext);
    file.seek(SeekFrom::Start(super_offset(slot)?))?;
    file.write_all(&bytes)?;
    Ok(())
}

fn read_superblock(
    file: &mut File,
    bootstrap: &Bootstrap,
    keys: &VolumeKeys,
    slot: u8,
) -> Result<Option<SuperState>> {
    let mut bytes = [0_u8; SUPER_SLOT_SIZE];
    file.seek(SeekFrom::Start(super_offset(slot)?))?;
    file.read_exact(&mut bytes)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    let generation = u64::from_le_bytes(bytes[..8].try_into().expect("fixed field"));
    let ciphertext_len = u32::from_le_bytes(bytes[8..12].try_into().expect("fixed field")) as usize;
    if ciphertext_len == 0 || ciphertext_len + 16 > SUPER_SLOT_SIZE {
        return Err(VolumeError::Corrupt("invalid superblock slot length"));
    }
    let nonce = derive_nonce(keys, bootstrap, b"super", slot as u64, generation);
    let aad = super_aad(bootstrap, slot, generation);
    let cipher = XChaCha20Poly1305::new_from_slice(&keys.key)
        .map_err(|_| VolumeError::AuthenticationFailed)?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &bytes[16..16 + ciphertext_len],
                aad: &aad,
            },
        )
        .map_err(|_| VolumeError::AuthenticationFailed)?;
    let state = SuperState::decode(&plaintext)?;
    if state.generation != generation {
        return Err(VolumeError::Corrupt("superblock generation mismatch"));
    }
    Ok(Some(state))
}

fn record_nonce(
    keys: &VolumeKeys,
    bootstrap: &Bootstrap,
    block_index: u64,
    generation: u64,
) -> [u8; 24] {
    derive_nonce(keys, bootstrap, b"data", block_index, generation)
}

fn record_aad(bootstrap: &Bootstrap, header: &[u8; RECORD_HEADER_SIZE]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(BOOTSTRAP_SIZE + RECORD_HEADER_SIZE + 4);
    aad.extend_from_slice(&bootstrap.encode());
    aad.extend_from_slice(b"data");
    aad.extend_from_slice(header);
    aad
}

fn read_record_at(
    file: &mut File,
    bootstrap: &Bootstrap,
    keys: &VolumeKeys,
    offset: u64,
) -> Result<(RecordHeader, Vec<u8>)> {
    file.seek(SeekFrom::Start(offset))?;
    let mut header_bytes = [0_u8; RECORD_HEADER_SIZE];
    file.read_exact(&mut header_bytes)?;
    let header = RecordHeader::decode(&header_bytes)?;
    if header.block_index >= bootstrap.block_count() {
        return Err(VolumeError::Corrupt("block index exceeds logical capacity"));
    }
    if header.plaintext_len > bootstrap.block_size {
        return Err(VolumeError::Corrupt(
            "block plaintext exceeds configured block size",
        ));
    }
    let mut ciphertext = vec![0_u8; header.ciphertext_len as usize];
    file.read_exact(&mut ciphertext)?;
    let nonce = record_nonce(keys, bootstrap, header.block_index, header.generation);
    let aad = record_aad(bootstrap, &header_bytes);
    let cipher = XChaCha20Poly1305::new_from_slice(&keys.key)
        .map_err(|_| VolumeError::AuthenticationFailed)?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| VolumeError::AuthenticationFailed)?;
    if plaintext.len() != header.plaintext_len as usize {
        return Err(VolumeError::Corrupt("decrypted block length mismatch"));
    }
    Ok((header, plaintext))
}

fn scan_log(
    file: &mut File,
    bootstrap: &Bootstrap,
    keys: &VolumeKeys,
    state: SuperState,
) -> Result<HashMap<u64, RecordIndex>> {
    let mut index: HashMap<u64, RecordIndex> = HashMap::new();
    let mut offset = LOG_START;
    let mut count = 0_u64;
    while offset < state.committed_end {
        let (header, _plaintext) = read_record_at(file, bootstrap, keys, offset)?;
        if let Some(previous) = index.get(&header.block_index) {
            if header.generation <= previous.generation {
                return Err(VolumeError::Corrupt("block generation did not increase"));
            }
        } else if header.generation == 0 {
            return Err(VolumeError::Corrupt("block generation zero is invalid"));
        }
        let record_len = (RECORD_HEADER_SIZE as u64)
            .checked_add(header.ciphertext_len as u64)
            .ok_or(VolumeError::Corrupt("block record length overflow"))?;
        let next = offset
            .checked_add(record_len)
            .ok_or(VolumeError::Corrupt("block record offset overflow"))?;
        if next > state.committed_end {
            return Err(VolumeError::Corrupt(
                "block record extends past committed log",
            ));
        }
        index.insert(
            header.block_index,
            RecordIndex {
                offset,
                generation: header.generation,
                plaintext_len: header.plaintext_len,
                ciphertext_len: header.ciphertext_len,
            },
        );
        offset = next;
        count = count.saturating_add(1);
    }
    if offset != state.committed_end || count != state.record_count {
        return Err(VolumeError::Corrupt("committed log accounting mismatch"));
    }
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use orisyvra::{create_keyfile, unlock_keyfile, KeyfileParams};
    use std::io::{Seek, SeekFrom, Write};

    fn make_master(directory: &Path, name: &str, password: &[u8]) -> MasterKey {
        let path = directory.join(format!("{name}.orisyvra-key"));
        create_keyfile(
            &path,
            password,
            KeyfileParams {
                memory_kib: 8 * 1024,
                iterations: 1,
                parallelism: 1,
            },
            false,
        )
        .expect("create keyfile");
        unlock_keyfile(&path, password).expect("unlock keyfile")
    }

    #[test]
    fn sparse_log_round_trip_and_reopen() {
        let directory = tempfile::tempdir().expect("tempdir");
        let master = make_master(directory.path(), "main", b"correct horse battery staple");
        let path = directory.path().join("vault.orisyvra-volume");
        let mut volume = Volume::create(
            &path,
            &master,
            VolumeOptions {
                logical_capacity: 100 * 1024 * 1024 * 1024,
                block_size: 64 * 1024,
            },
        )
        .expect("create volume");
        assert!(volume.read_block(100_000).expect("read empty").is_none());
        assert_eq!(volume.write_block(100_000, b"hello volume").unwrap(), 1);
        assert_eq!(
            volume.write_block(100_000, b"second generation").unwrap(),
            2
        );
        volume.mark_clean().expect("mark clean");
        drop(volume);

        let physical = std::fs::metadata(&path).expect("metadata").len();
        assert!(
            physical < 2 * 1024 * 1024,
            "logical 100 GiB volume must stay physically small after one allocated block"
        );

        let mut reopened = Volume::open(&path, &master).expect("open volume");
        assert_eq!(
            reopened.read_block(100_000).unwrap().unwrap(),
            b"second generation"
        );
        assert_eq!(reopened.block_generation(100_000).unwrap(), Some(2));
        assert!(reopened.info().clean);
    }

    #[test]
    fn wrong_master_key_is_rejected() {
        let directory = tempfile::tempdir().expect("tempdir");
        let master = make_master(directory.path(), "main", b"correct horse battery staple");
        let wrong = make_master(directory.path(), "wrong", b"another correct horse phrase");
        let path = directory.path().join("vault.orisyvra-volume");
        let mut volume =
            Volume::create(&path, &master, VolumeOptions::new(1024 * 1024)).expect("create volume");
        volume.write_block(0, b"secret").expect("write");
        volume.mark_clean().expect("clean");
        drop(volume);
        assert!(matches!(
            Volume::open(&path, &wrong),
            Err(VolumeError::AuthenticationFailed)
        ));
    }

    #[test]
    fn relocated_record_header_is_rejected() {
        let directory = tempfile::tempdir().expect("tempdir");
        let master = make_master(directory.path(), "main", b"correct horse battery staple");
        let path = directory.path().join("vault.orisyvra-volume");
        let mut volume = Volume::create(&path, &master, VolumeOptions::new(8 * 1024 * 1024))
            .expect("create volume");
        volume
            .write_block(2, b"authenticated block")
            .expect("write");
        volume.mark_clean().expect("clean");
        let record_offset = volume.index.get(&2).expect("index").offset;
        drop(volume);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::Start(record_offset + 4)).unwrap();
        file.write_all(&3_u64.to_le_bytes()).unwrap();
        file.sync_all().unwrap();
        drop(file);

        assert!(matches!(
            Volume::open(&path, &master),
            Err(VolumeError::Corrupt(_))
        ));
    }

    #[test]
    fn uncommitted_tail_is_discarded() {
        let directory = tempfile::tempdir().expect("tempdir");
        let master = make_master(directory.path(), "main", b"correct horse battery staple");
        let path = directory.path().join("vault.orisyvra-volume");
        let mut volume = Volume::create(&path, &master, VolumeOptions::new(8 * 1024 * 1024))
            .expect("create volume");
        volume.write_block(1, b"committed").expect("write");
        volume.mark_clean().expect("clean");
        let committed_end = volume.state.committed_end;
        drop(volume);

        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"uncommitted crash tail").unwrap();
        file.sync_all().unwrap();
        drop(file);

        let mut reopened = Volume::open(&path, &master).expect("open recovered volume");
        assert_eq!(reopened.read_block(1).unwrap().unwrap(), b"committed");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), committed_end);
    }

    #[test]
    fn out_of_range_block_is_rejected() {
        let directory = tempfile::tempdir().expect("tempdir");
        let master = make_master(directory.path(), "main", b"correct horse battery staple");
        let path = directory.path().join("vault.orisyvra-volume");
        let mut volume = Volume::create(
            &path,
            &master,
            VolumeOptions {
                logical_capacity: 64 * 1024,
                block_size: 64 * 1024,
            },
        )
        .expect("create volume");
        assert!(matches!(
            volume.write_block(1, b"nope"),
            Err(VolumeError::BlockOutOfRange)
        ));
    }
}
