#![cfg_attr(not(windows), forbid(unsafe_code))]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroize;

const TEMPORARY_MOUNT_SECRET_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, thiserror::Error)]
pub enum WindowsIntegrationError {
    #[error("Windows integration is unavailable on this platform")]
    Unsupported,
    #[error("Windows API error {0}")]
    WindowsApi(u32),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid mount entry: {0}")]
    InvalidEntry(String),
}

pub type Result<T> = std::result::Result<T, WindowsIntegrationError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountEntry {
    pub id: String,
    pub volume_path: PathBuf,
    pub key_path: PathBuf,
    pub preferred_letter: Option<char>,
    pub read_only: bool,
    pub auto_mount: bool,
    pub auto_unlock: bool,
    pub task_registered: bool,
}

impl MountEntry {
    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty()
            || !self
                .id
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || value == b'-' || value == b'_')
        {
            return Err(WindowsIntegrationError::InvalidEntry(
                "entry id contains unsupported characters".to_owned(),
            ));
        }
        if let Some(letter) = self.preferred_letter {
            if !letter.is_ascii_alphabetic() {
                return Err(WindowsIntegrationError::InvalidEntry(
                    "preferred drive letter must be A-Z".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

pub fn volume_id_hex(volume_id: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in volume_id {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

pub fn automount_root() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let base = std::env::var_os("APPDATA").ok_or(WindowsIntegrationError::Unsupported)?;
        return Ok(PathBuf::from(base).join("OrIsyVra").join("automount"));
    }
    #[cfg(not(windows))]
    {
        Err(WindowsIntegrationError::Unsupported)
    }
}

pub fn entry_path(id: &str) -> Result<PathBuf> {
    Ok(automount_root()?.join("entries").join(format!("{id}.conf")))
}

pub fn secret_path(id: &str) -> Result<PathBuf> {
    Ok(automount_root()?.join("secrets").join(format!("{id}.dpapi")))
}

pub fn credential_path(id: &str) -> Result<PathBuf> {
    Ok(automount_root()?
        .join("credentials")
        .join(format!("{id}.orisyvra-key")))
}

pub fn stop_path(id: &str) -> Result<PathBuf> {
    Ok(automount_root()?.join("state").join(format!("{id}.stop")))
}

pub fn state_path(id: &str) -> Result<PathBuf> {
    Ok(automount_root()?.join("state").join(format!("{id}.mounted")))
}

pub fn task_name(id: &str) -> String {
    format!(r"\OrIsyVra\Volume-{id}")
}

pub fn save_entry(entry: &MountEntry) -> Result<()> {
    entry.validate()?;
    let path = entry_path(&entry.id)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let letter = entry
        .preferred_letter
        .map(|value| value.to_ascii_uppercase().to_string())
        .unwrap_or_default();
    let text = format!(
        "version=1\nid={}\nvolume={}\nkey={}\nletter={}\nread_only={}\nauto_mount={}\nauto_unlock={}\ntask_registered={}\n",
        entry.id,
        entry.volume_path.display(),
        entry.key_path.display(),
        letter,
        u8::from(entry.read_only),
        u8::from(entry.auto_mount),
        u8::from(entry.auto_unlock),
        u8::from(entry.task_registered),
    );
    fs::write(path, text)?;
    Ok(())
}

pub fn load_entry(id: &str) -> Result<MountEntry> {
    let text = fs::read_to_string(entry_path(id)?)?;
    parse_entry(&text)
}

pub fn list_entries() -> Result<Vec<MountEntry>> {
    let dir = automount_root()?.join("entries");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for item in fs::read_dir(dir)? {
        let item = item?;
        if !item.file_type()?.is_file() {
            continue;
        }
        if item.path().extension().and_then(|value| value.to_str()) != Some("conf") {
            continue;
        }
        if let Ok(text) = fs::read_to_string(item.path()) {
            if let Ok(entry) = parse_entry(&text) {
                entries.push(entry);
            }
        }
    }
    entries.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(entries)
}

pub fn remove_entry_files(id: &str) -> Result<()> {
    for path in [
        entry_path(id)?,
        secret_path(id)?,
        credential_path(id)?,
        stop_path(id)?,
        state_path(id)?,
    ] {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn parse_entry(text: &str) -> Result<MountEntry> {
    let mut id = None;
    let mut volume_path = None;
    let mut key_path = None;
    let mut preferred_letter = None;
    let mut read_only = false;
    let mut auto_mount = false;
    let mut auto_unlock = false;
    let mut task_registered = false;

    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "id" => id = Some(value.to_owned()),
            "volume" => volume_path = Some(PathBuf::from(value)),
            "key" => key_path = Some(PathBuf::from(value)),
            "letter" => {
                preferred_letter = value
                    .chars()
                    .next()
                    .filter(|letter| letter.is_ascii_alphabetic())
                    .map(|letter| letter.to_ascii_uppercase());
            }
            "read_only" => read_only = value == "1",
            "auto_mount" => auto_mount = value == "1",
            "auto_unlock" => auto_unlock = value == "1",
            "task_registered" => task_registered = value == "1",
            _ => {}
        }
    }

    let entry = MountEntry {
        id: id.ok_or_else(|| WindowsIntegrationError::InvalidEntry("missing id".to_owned()))?,
        volume_path: volume_path
            .ok_or_else(|| WindowsIntegrationError::InvalidEntry("missing volume path".to_owned()))?,
        key_path: key_path
            .ok_or_else(|| WindowsIntegrationError::InvalidEntry("missing key path".to_owned()))?,
        preferred_letter,
        read_only,
        auto_mount,
        auto_unlock,
        task_registered,
    };
    entry.validate()?;
    Ok(entry)
}

pub fn write_protected_secret(path: &Path, plaintext: &[u8]) -> Result<()> {
    let protected = protect_current_user(plaintext)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, protected)?;
    Ok(())
}

fn entry_id_from_secret_path(path: &Path) -> Option<&str> {
    path.file_stem()?.to_str()
}

fn remove_stale_mount_material(id: &str, secret: &Path) {
    let _ = fs::remove_file(secret);
    if let Ok(credential) = credential_path(id) {
        let _ = fs::remove_file(credential);
    }
}

pub fn read_protected_secret(path: &Path) -> Result<Vec<u8>> {
    if let Some(id) = entry_id_from_secret_path(path) {
        if let Ok(entry) = load_entry(id) {
            if entry.auto_unlock && !entry.auto_mount {
                remove_stale_mount_material(id, path);
                return Err(WindowsIntegrationError::InvalidEntry(
                    "automatic unlock is disabled because automatic mounting is disabled".to_owned(),
                ));
            }

            if !entry.auto_unlock {
                let fresh = fs::metadata(path)
                    .and_then(|metadata| metadata.modified())
                    .ok()
                    .and_then(|modified| modified.elapsed().ok())
                    .is_some_and(|age| age <= TEMPORARY_MOUNT_SECRET_TTL);
                if !fresh {
                    remove_stale_mount_material(id, path);
                    return Err(WindowsIntegrationError::InvalidEntry(
                        "temporary mount credential expired".to_owned(),
                    ));
                }
            }
        }
    }

    let mut protected = fs::read(path)?;
    let result = unprotect_current_user(&protected);
    protected.zeroize();
    result
}

#[cfg(windows)]
mod dpapi {
    use super::{Result, WindowsIntegrationError};
    use std::ffi::c_void;
    use std::ptr;

    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(
            data_in: *const DataBlob,
            description: *const u16,
            optional_entropy: *const DataBlob,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            data_out: *mut DataBlob,
        ) -> i32;
        fn CryptUnprotectData(
            data_in: *const DataBlob,
            description: *mut *mut u16,
            optional_entropy: *const DataBlob,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            data_out: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
        fn GetLastError() -> u32;
    }

    pub fn protect(data: &[u8]) -> Result<Vec<u8>> {
        if data.len() > u32::MAX as usize {
            return Err(WindowsIntegrationError::InvalidEntry(
                "secret is too large".to_owned(),
            ));
        }
        let input = DataBlob {
            cb_data: data.len() as u32,
            pb_data: data.as_ptr() as *mut u8,
        };
        let mut output = DataBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };
        let ok = unsafe {
            CryptProtectData(
                &input,
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(WindowsIntegrationError::WindowsApi(unsafe { GetLastError() }));
        }
        let result = unsafe {
            let slice = std::slice::from_raw_parts(output.pb_data, output.cb_data as usize);
            let bytes = slice.to_vec();
            LocalFree(output.pb_data.cast::<c_void>());
            bytes
        };
        Ok(result)
    }

    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>> {
        if data.len() > u32::MAX as usize {
            return Err(WindowsIntegrationError::InvalidEntry(
                "protected secret is too large".to_owned(),
            ));
        }
        let input = DataBlob {
            cb_data: data.len() as u32,
            pb_data: data.as_ptr() as *mut u8,
        };
        let mut output = DataBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(WindowsIntegrationError::WindowsApi(unsafe { GetLastError() }));
        }
        let result = unsafe {
            let slice = std::slice::from_raw_parts(output.pb_data, output.cb_data as usize);
            let bytes = slice.to_vec();
            LocalFree(output.pb_data.cast::<c_void>());
            bytes
        };
        Ok(result)
    }
}

pub fn protect_current_user(data: &[u8]) -> Result<Vec<u8>> {
    #[cfg(windows)]
    {
        dpapi::protect(data)
    }
    #[cfg(not(windows))]
    {
        let _ = data;
        Err(WindowsIntegrationError::Unsupported)
    }
}

pub fn unprotect_current_user(data: &[u8]) -> Result<Vec<u8>> {
    #[cfg(windows)]
    {
        dpapi::unprotect(data)
    }
    #[cfg(not(windows))]
    {
        let _ = data;
        Err(WindowsIntegrationError::Unsupported)
    }
}
