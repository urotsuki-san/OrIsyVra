use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha384};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::keyfile::MasterKey;

const FILE_MAGIC: &[u8; 8] = b"OYVFILE1";
const FILE_VERSION: u16 = 1;
const HEADER_SIZE: usize = 80;
const DATA_RECORD: u8 = 1;
const MANIFEST_RECORD: u8 = 255;
const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;
const MIN_CHUNK_SIZE: usize = 4 * 1024;
const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;
const MAX_RECORDS: u64 = 1 << 20;
const NATIVE_TAG_SIZE: usize = 32;
const GUARD_TAG_SIZE: usize = 16;
const MANIFEST_PAYLOAD_SIZE: usize = 64;
const MANIFEST_INNER_SIZE: usize = MANIFEST_PAYLOAD_SIZE + NATIVE_TAG_SIZE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Mode {
    NativeResearch = 0,
    Guarded = 1,
}

impl Mode {
    fn from_byte(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::NativeResearch),
            1 => Ok(Self::Guarded),
            _ => Err(Error::InvalidFormat("unsupported encryption mode")),
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Self::NativeResearch => "native-research",
            Self::Guarded => "guarded",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EncryptOptions {
    pub mode: Mode,
    pub chunk_size: usize,
    pub overwrite: bool,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self {
            mode: Mode::Guarded,
            chunk_size: DEFAULT_CHUNK_SIZE,
            overwrite: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct FileInfo {
    pub version: u16,
    pub mode: Mode,
    pub chunk_size: usize,
    pub file_id: [u8; 32],
}

#[derive(Clone)]
struct Header {
    version: u16,
    mode: Mode,
    flags: u8,
    chunk_size: u32,
    salt: [u8; 32],
    file_id: [u8; 32],
}

impl Header {
    fn new(mode: Mode, chunk_size: usize) -> Result<Self> {
        validate_chunk_size(chunk_size)?;
        let mut salt = [0_u8; 32];
        let mut file_id = [0_u8; 32];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut file_id);
        Ok(Self {
            version: FILE_VERSION,
            mode,
            flags: 0,
            chunk_size: chunk_size as u32,
            salt,
            file_id,
        })
    }

    fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0_u8; HEADER_SIZE];
        bytes[..8].copy_from_slice(FILE_MAGIC);
        bytes[8..10].copy_from_slice(&self.version.to_le_bytes());
        bytes[10] = self.mode as u8;
        bytes[11] = self.flags;
        bytes[12..16].copy_from_slice(&self.chunk_size.to_le_bytes());
        bytes[16..48].copy_from_slice(&self.salt);
        bytes[48..80].copy_from_slice(&self.file_id);
        bytes
    }

    fn decode(bytes: &[u8; HEADER_SIZE]) -> Result<Self> {
        if &bytes[..8] != FILE_MAGIC {
            return Err(Error::InvalidFormat("not an OrIsyVra file"));
        }
        let version = u16::from_le_bytes(bytes[8..10].try_into().expect("fixed header"));
        if version != FILE_VERSION {
            return Err(Error::InvalidFormat("unsupported file version"));
        }
        let mode = Mode::from_byte(bytes[10])?;
        let flags = bytes[11];
        if flags != 0 {
            return Err(Error::InvalidFormat("unsupported critical file flags"));
        }
        let chunk_size = u32::from_le_bytes(bytes[12..16].try_into().expect("fixed header"));
        validate_chunk_size(chunk_size as usize)?;
        let mut salt = [0_u8; 32];
        salt.copy_from_slice(&bytes[16..48]);
        let mut file_id = [0_u8; 32];
        file_id.copy_from_slice(&bytes[48..80]);
        Ok(Self {
            version,
            mode,
            flags,
            chunk_size,
            salt,
            file_id,
        })
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct NativeKeys {
    siv: [u8; orisyvra_core::KEY_SIZE],
    stream: [u8; orisyvra_core::KEY_SIZE],
    manifest: [u8; orisyvra_core::KEY_SIZE],
    header: [u8; orisyvra_core::KEY_SIZE],
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct GuardKeys {
    key: [u8; 32],
    nonce_key: [u8; 32],
}

fn validate_chunk_size(chunk_size: usize) -> Result<()> {
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
        return Err(Error::InvalidInput(format!(
            "chunk size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE} bytes"
        )));
    }
    Ok(())
}

fn derive_native_keys(master: &MasterKey, header: &Header) -> NativeKeys {
    let header_bytes = header.encode();
    NativeKeys {
        siv: orisyvra_core::derive_key(master.as_bytes(), b"OrIsyVra/native/siv/v1", &header_bytes),
        stream: orisyvra_core::derive_key(
            master.as_bytes(),
            b"OrIsyVra/native/stream/v1",
            &header_bytes,
        ),
        manifest: orisyvra_core::derive_key(
            master.as_bytes(),
            b"OrIsyVra/native/manifest/v1",
            &header_bytes,
        ),
        header: orisyvra_core::derive_key(
            master.as_bytes(),
            b"OrIsyVra/native/header/v1",
            &header_bytes,
        ),
    }
}

fn derive_guard_keys(master: &MasterKey, header: &Header) -> Result<GuardKeys> {
    let hkdf = Hkdf::<Sha384>::new(Some(&header.salt), master.as_bytes());
    let mut output = [0_u8; 64];
    let mut info = Vec::with_capacity(64);
    info.extend_from_slice(b"OrIsyVra/guarded/XChaCha20Poly1305/v1");
    info.extend_from_slice(&header.file_id);
    hkdf.expand(&info, &mut output)
        .map_err(|_| Error::Crypto("guard-key derivation failed"))?;
    let mut key = [0_u8; 32];
    key.copy_from_slice(&output[..32]);
    let mut nonce_key = [0_u8; 32];
    nonce_key.copy_from_slice(&output[32..]);
    output.zeroize();
    Ok(GuardKeys { key, nonce_key })
}

fn header_binding(keys: &NativeKeys, header: &Header) -> [u8; 32] {
    orisyvra_core::mac32(
        &keys.header,
        orisyvra_core::Domain::HeaderBinding,
        &[&header.encode()],
    )
}

fn record_frame(index: u64, plaintext_length: u32, body_length: u32) -> [u8; 17] {
    let mut frame = [0_u8; 17];
    frame[0] = DATA_RECORD;
    frame[1..9].copy_from_slice(&index.to_le_bytes());
    frame[9..13].copy_from_slice(&plaintext_length.to_le_bytes());
    frame[13..17].copy_from_slice(&body_length.to_le_bytes());
    frame
}

fn manifest_frame(body_length: u32) -> [u8; 5] {
    let mut frame = [0_u8; 5];
    frame[0] = MANIFEST_RECORD;
    frame[1..5].copy_from_slice(&body_length.to_le_bytes());
    frame
}

fn record_context(binding: &[u8; 32], index: u64, plaintext_length: u32) -> [u8; 44] {
    let mut context = [0_u8; 44];
    context[..32].copy_from_slice(binding);
    context[32..40].copy_from_slice(&index.to_le_bytes());
    context[40..44].copy_from_slice(&plaintext_length.to_le_bytes());
    context
}

fn seal_native(
    keys: &NativeKeys,
    binding: &[u8; 32],
    index: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let plaintext_length = u32::try_from(plaintext.len())
        .map_err(|_| Error::LimitExceeded("record larger than u32"))?;
    let context = record_context(binding, index, plaintext_length);
    let siv = orisyvra_core::mac32(
        &keys.siv,
        orisyvra_core::Domain::RecordSiv,
        &[&context, plaintext],
    );
    let mut stream = vec![0_u8; plaintext.len()];
    orisyvra_core::prf_parts(
        &keys.stream,
        orisyvra_core::Domain::Stream,
        &[&context, &siv],
        &mut stream,
    );
    let mut output = Vec::with_capacity(NATIVE_TAG_SIZE + plaintext.len());
    output.extend_from_slice(&siv);
    output.extend(
        plaintext
            .iter()
            .zip(stream.iter())
            .map(|(plain, key)| *plain ^ *key),
    );
    stream.zeroize();
    Ok(output)
}

fn open_native(
    keys: &NativeKeys,
    binding: &[u8; 32],
    index: u64,
    plaintext_length: u32,
    body: &[u8],
) -> Result<Vec<u8>> {
    let expected_body_length = NATIVE_TAG_SIZE
        .checked_add(plaintext_length as usize)
        .ok_or(Error::LimitExceeded("record length overflow"))?;
    if body.len() != expected_body_length {
        return Err(Error::InvalidFormat("native record length mismatch"));
    }
    let (stored_siv, ciphertext) = body.split_at(NATIVE_TAG_SIZE);
    let context = record_context(binding, index, plaintext_length);
    let mut stream = vec![0_u8; ciphertext.len()];
    orisyvra_core::prf_parts(
        &keys.stream,
        orisyvra_core::Domain::Stream,
        &[&context, stored_siv],
        &mut stream,
    );
    let mut plaintext: Vec<u8> = ciphertext
        .iter()
        .zip(stream.iter())
        .map(|(cipher, key)| *cipher ^ *key)
        .collect();
    stream.zeroize();
    let expected_siv = orisyvra_core::mac32(
        &keys.siv,
        orisyvra_core::Domain::RecordSiv,
        &[&context, &plaintext],
    );
    if !bool::from(expected_siv.as_slice().ct_eq(stored_siv)) {
        plaintext.zeroize();
        return Err(Error::AuthenticationFailed);
    }
    Ok(plaintext)
}

fn guard_nonce(keys: &GuardKeys, header: &Header, index: u64, kind: u8) -> [u8; 24] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(&keys.nonce_key).expect("HMAC key length is valid");
    mac.update(b"OrIsyVra/guarded/nonce/v1");
    mac.update(&header.file_id);
    mac.update(&[kind]);
    mac.update(&index.to_le_bytes());
    let digest = mac.finalize().into_bytes();
    let mut nonce = [0_u8; 24];
    nonce.copy_from_slice(&digest[..24]);
    nonce
}

fn guard_seal(
    keys: &GuardKeys,
    header: &Header,
    index: u64,
    kind: u8,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(&keys.key)
        .map_err(|_| Error::Crypto("invalid guard key"))?;
    cipher
        .encrypt(
            XNonce::from_slice(&guard_nonce(keys, header, index, kind)),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto("guarded encryption failed"))
}

fn guard_open(
    keys: &GuardKeys,
    header: &Header,
    index: u64,
    kind: u8,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(&keys.key)
        .map_err(|_| Error::Crypto("invalid guard key"))?;
    cipher
        .decrypt(
            XNonce::from_slice(&guard_nonce(keys, header, index, kind)),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::AuthenticationFailed)
}

fn native_manifest_inner(
    native_keys: &NativeKeys,
    binding: &[u8; 32],
    total_length: u64,
    record_count: u64,
    transcript_digest: &[u8; 48],
) -> [u8; MANIFEST_INNER_SIZE] {
    let mut payload = [0_u8; MANIFEST_PAYLOAD_SIZE];
    payload[..8].copy_from_slice(&total_length.to_le_bytes());
    payload[8..16].copy_from_slice(&record_count.to_le_bytes());
    payload[16..64].copy_from_slice(transcript_digest);
    let tag = orisyvra_core::mac32(
        &native_keys.manifest,
        orisyvra_core::Domain::Manifest,
        &[binding, &payload],
    );
    let mut inner = [0_u8; MANIFEST_INNER_SIZE];
    inner[..MANIFEST_PAYLOAD_SIZE].copy_from_slice(&payload);
    inner[MANIFEST_PAYLOAD_SIZE..].copy_from_slice(&tag);
    inner
}

fn verify_manifest_inner(
    native_keys: &NativeKeys,
    binding: &[u8; 32],
    inner: &[u8],
    expected_total: u64,
    expected_count: u64,
    expected_digest: &[u8; 48],
) -> Result<()> {
    if inner.len() != MANIFEST_INNER_SIZE {
        return Err(Error::InvalidFormat("manifest length mismatch"));
    }
    let payload = &inner[..MANIFEST_PAYLOAD_SIZE];
    let stored_tag = &inner[MANIFEST_PAYLOAD_SIZE..];
    let expected_tag = orisyvra_core::mac32(
        &native_keys.manifest,
        orisyvra_core::Domain::Manifest,
        &[binding, payload],
    );
    if !bool::from(expected_tag.as_slice().ct_eq(stored_tag)) {
        return Err(Error::AuthenticationFailed);
    }
    let total_length = u64::from_le_bytes(payload[..8].try_into().expect("manifest payload"));
    let record_count = u64::from_le_bytes(payload[8..16].try_into().expect("manifest payload"));
    if total_length != expected_total
        || record_count != expected_count
        || !bool::from(expected_digest.as_slice().ct_eq(&payload[16..64]))
    {
        return Err(Error::AuthenticationFailed);
    }
    Ok(())
}

fn read_exact_array<const N: usize>(reader: &mut impl Read) -> Result<[u8; N]> {
    let mut bytes = [0_u8; N];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn create_output_temp(path: &Path, overwrite: bool) -> Result<tempfile::NamedTempFile> {
    if path.exists() && !overwrite {
        return Err(Error::OutputExists(path.display().to_string()));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    tempfile::NamedTempFile::new_in(parent).map_err(Error::from)
}

fn persist_output(
    mut temporary: tempfile::NamedTempFile,
    path: &Path,
    overwrite: bool,
) -> Result<()> {
    temporary.as_file_mut().sync_all()?;
    if path.exists() && overwrite {
        fs::remove_file(path)?;
    }
    temporary
        .persist(path)
        .map_err(|error| Error::Io(error.error))?;
    Ok(())
}

pub fn inspect_file(path: &Path) -> Result<FileInfo> {
    let mut input = File::open(path)?;
    let header = Header::decode(&read_exact_array::<HEADER_SIZE>(&mut input)?)?;
    Ok(FileInfo {
        version: header.version,
        mode: header.mode,
        chunk_size: header.chunk_size as usize,
        file_id: header.file_id,
    })
}

pub fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    master_key: &MasterKey,
    options: EncryptOptions,
) -> Result<()> {
    validate_chunk_size(options.chunk_size)?;
    if input_path == output_path {
        return Err(Error::InvalidInput(
            "input and output paths must be different".into(),
        ));
    }
    let header = Header::new(options.mode, options.chunk_size)?;
    let header_bytes = header.encode();
    let native_keys = derive_native_keys(master_key, &header);
    let guard_keys = if options.mode == Mode::Guarded {
        Some(derive_guard_keys(master_key, &header)?)
    } else {
        None
    };
    let binding = header_binding(&native_keys, &header);
    let mut input = File::open(input_path)?;
    let mut temporary = create_output_temp(output_path, options.overwrite)?;
    temporary.write_all(&header_bytes)?;
    let mut transcript = Sha384::new();
    transcript.update(header_bytes);
    let mut buffer = vec![0_u8; options.chunk_size];
    let mut record_index = 0_u64;
    let mut total_length = 0_u64;

    loop {
        let mut filled = 0;
        while filled < buffer.len() {
            let read = input.read(&mut buffer[filled..])?;
            if read == 0 {
                break;
            }
            filled += read;
        }
        if filled == 0 {
            break;
        }
        if record_index >= MAX_RECORDS {
            return Err(Error::LimitExceeded("too many records in one file"));
        }
        let plaintext = &buffer[..filled];
        let native_body = seal_native(&native_keys, &binding, record_index, plaintext)?;
        let plaintext_length =
            u32::try_from(filled).map_err(|_| Error::LimitExceeded("record too large"))?;
        let body = match options.mode {
            Mode::NativeResearch => native_body,
            Mode::Guarded => {
                let body_length = native_body
                    .len()
                    .checked_add(GUARD_TAG_SIZE)
                    .ok_or(Error::LimitExceeded("record length overflow"))?;
                let frame = record_frame(
                    record_index,
                    plaintext_length,
                    u32::try_from(body_length)
                        .map_err(|_| Error::LimitExceeded("record too large"))?,
                );
                let mut aad = Vec::with_capacity(HEADER_SIZE + frame.len());
                aad.extend_from_slice(&header_bytes);
                aad.extend_from_slice(&frame);
                guard_seal(
                    guard_keys.as_ref().expect("guard keys exist"),
                    &header,
                    record_index,
                    DATA_RECORD,
                    &aad,
                    &native_body,
                )?
            }
        };
        let frame = record_frame(
            record_index,
            plaintext_length,
            u32::try_from(body.len()).map_err(|_| Error::LimitExceeded("record too large"))?,
        );
        temporary.write_all(&frame)?;
        temporary.write_all(&body)?;
        transcript.update(frame);
        transcript.update(&body);
        total_length = total_length
            .checked_add(filled as u64)
            .ok_or(Error::LimitExceeded("file length overflow"))?;
        record_index += 1;
    }

    buffer.zeroize();
    let transcript_digest: [u8; 48] = transcript.finalize().into();
    let manifest_inner = native_manifest_inner(
        &native_keys,
        &binding,
        total_length,
        record_index,
        &transcript_digest,
    );
    let manifest_body = match options.mode {
        Mode::NativeResearch => manifest_inner.to_vec(),
        Mode::Guarded => {
            let frame = manifest_frame((MANIFEST_INNER_SIZE + GUARD_TAG_SIZE) as u32);
            let mut aad = Vec::with_capacity(HEADER_SIZE + frame.len());
            aad.extend_from_slice(&header_bytes);
            aad.extend_from_slice(&frame);
            guard_seal(
                guard_keys.as_ref().expect("guard keys exist"),
                &header,
                u64::MAX,
                MANIFEST_RECORD,
                &aad,
                &manifest_inner,
            )?
        }
    };
    let frame = manifest_frame(
        u32::try_from(manifest_body.len())
            .map_err(|_| Error::LimitExceeded("manifest too large"))?,
    );
    temporary.write_all(&frame)?;
    temporary.write_all(&manifest_body)?;
    temporary.flush()?;
    persist_output(temporary, output_path, options.overwrite)
}

pub fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    master_key: &MasterKey,
    overwrite: bool,
) -> Result<FileInfo> {
    if input_path == output_path {
        return Err(Error::InvalidInput(
            "input and output paths must be different".into(),
        ));
    }
    let mut input = File::open(input_path)?;
    let header_bytes = read_exact_array::<HEADER_SIZE>(&mut input)?;
    let header = Header::decode(&header_bytes)?;
    let native_keys = derive_native_keys(master_key, &header);
    let guard_keys = if header.mode == Mode::Guarded {
        Some(derive_guard_keys(master_key, &header)?)
    } else {
        None
    };
    let binding = header_binding(&native_keys, &header);
    let mut temporary = create_output_temp(output_path, overwrite)?;
    let mut transcript = Sha384::new();
    transcript.update(header_bytes);
    let mut expected_index = 0_u64;
    let mut total_length = 0_u64;
    let mut saw_manifest = false;

    loop {
        let mut kind = [0_u8; 1];
        if input.read(&mut kind)? == 0 {
            break;
        }
        match kind[0] {
            DATA_RECORD => {
                if saw_manifest {
                    return Err(Error::InvalidFormat("data after manifest"));
                }
                let rest = read_exact_array::<16>(&mut input)?;
                let index = u64::from_le_bytes(rest[..8].try_into().expect("record frame"));
                let plaintext_length =
                    u32::from_le_bytes(rest[8..12].try_into().expect("record frame"));
                let body_length =
                    u32::from_le_bytes(rest[12..16].try_into().expect("record frame"));
                if index != expected_index {
                    return Err(Error::AuthenticationFailed);
                }
                if index >= MAX_RECORDS {
                    return Err(Error::LimitExceeded("too many records"));
                }
                if plaintext_length as usize > header.chunk_size as usize {
                    return Err(Error::InvalidFormat("record exceeds header chunk size"));
                }
                let expected_body_length = match header.mode {
                    Mode::NativeResearch => NATIVE_TAG_SIZE + plaintext_length as usize,
                    Mode::Guarded => NATIVE_TAG_SIZE + plaintext_length as usize + GUARD_TAG_SIZE,
                };
                if body_length as usize != expected_body_length {
                    return Err(Error::InvalidFormat("record body length mismatch"));
                }
                let mut body = vec![0_u8; body_length as usize];
                input.read_exact(&mut body)?;
                let mut frame = [0_u8; 17];
                frame[0] = DATA_RECORD;
                frame[1..].copy_from_slice(&rest);
                transcript.update(frame);
                transcript.update(&body);
                let native_body = match header.mode {
                    Mode::NativeResearch => body,
                    Mode::Guarded => {
                        let mut aad = Vec::with_capacity(HEADER_SIZE + frame.len());
                        aad.extend_from_slice(&header_bytes);
                        aad.extend_from_slice(&frame);
                        guard_open(
                            guard_keys.as_ref().expect("guard keys exist"),
                            &header,
                            index,
                            DATA_RECORD,
                            &aad,
                            &body,
                        )?
                    }
                };
                let mut plaintext = open_native(
                    &native_keys,
                    &binding,
                    index,
                    plaintext_length,
                    &native_body,
                )?;
                temporary.write_all(&plaintext)?;
                plaintext.zeroize();
                total_length = total_length
                    .checked_add(plaintext_length as u64)
                    .ok_or(Error::LimitExceeded("file length overflow"))?;
                expected_index += 1;
            }
            MANIFEST_RECORD => {
                if saw_manifest {
                    return Err(Error::InvalidFormat("duplicate manifest"));
                }
                saw_manifest = true;
                let body_length = u32::from_le_bytes(read_exact_array::<4>(&mut input)?);
                let expected_length = match header.mode {
                    Mode::NativeResearch => MANIFEST_INNER_SIZE,
                    Mode::Guarded => MANIFEST_INNER_SIZE + GUARD_TAG_SIZE,
                };
                if body_length as usize != expected_length {
                    return Err(Error::InvalidFormat("manifest body length mismatch"));
                }
                let mut body = vec![0_u8; body_length as usize];
                input.read_exact(&mut body)?;
                let frame = manifest_frame(body_length);
                let inner = match header.mode {
                    Mode::NativeResearch => body,
                    Mode::Guarded => {
                        let mut aad = Vec::with_capacity(HEADER_SIZE + frame.len());
                        aad.extend_from_slice(&header_bytes);
                        aad.extend_from_slice(&frame);
                        guard_open(
                            guard_keys.as_ref().expect("guard keys exist"),
                            &header,
                            u64::MAX,
                            MANIFEST_RECORD,
                            &aad,
                            &body,
                        )?
                    }
                };
                let digest: [u8; 48] = transcript.clone().finalize().into();
                verify_manifest_inner(
                    &native_keys,
                    &binding,
                    &inner,
                    total_length,
                    expected_index,
                    &digest,
                )?;
                let mut trailing = [0_u8; 1];
                if input.read(&mut trailing)? != 0 {
                    return Err(Error::InvalidFormat("trailing bytes after manifest"));
                }
                break;
            }
            _ => return Err(Error::InvalidFormat("unknown record type")),
        }
    }

    if !saw_manifest {
        return Err(Error::AuthenticationFailed);
    }
    temporary.flush()?;
    persist_output(temporary, output_path, overwrite)?;
    Ok(FileInfo {
        version: header.version,
        mode: header.mode,
        chunk_size: header.chunk_size as usize,
        file_id: header.file_id,
    })
}

#[cfg(test)]
mod tests {
    use super::{decrypt_file, encrypt_file, EncryptOptions, Mode};
    use crate::keyfile::{create_keyfile, unlock_keyfile, KeyfileParams};
    use std::fs;

    fn round_trip(mode: Mode) {
        let directory = tempfile::tempdir().expect("temp directory");
        let key_path = directory.path().join("test.orisyvra-key");
        let input_path = directory.path().join("input.bin");
        let encrypted_path = directory.path().join("input.bin.orisyvra");
        let output_path = directory.path().join("output.bin");
        let data: Vec<u8> = (0..250_000_u32)
            .map(|value| (value.wrapping_mul(37) ^ (value >> 3)) as u8)
            .collect();
        fs::write(&input_path, &data).expect("write input");
        create_keyfile(
            &key_path,
            b"test passphrase long enough",
            KeyfileParams {
                memory_kib: 8 * 1024,
                iterations: 1,
                parallelism: 1,
            },
            false,
        )
        .expect("create key");
        let key = unlock_keyfile(&key_path, b"test passphrase long enough").expect("unlock key");
        encrypt_file(
            &input_path,
            &encrypted_path,
            &key,
            EncryptOptions {
                mode,
                chunk_size: 64 * 1024,
                overwrite: false,
            },
        )
        .expect("encrypt");
        decrypt_file(&encrypted_path, &output_path, &key, false).expect("decrypt");
        assert_eq!(fs::read(output_path).expect("read output"), data);
    }

    #[test]
    fn guarded_round_trip() {
        round_trip(Mode::Guarded);
    }

    #[test]
    fn native_round_trip() {
        round_trip(Mode::NativeResearch);
    }
}
