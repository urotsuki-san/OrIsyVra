#[cfg(not(windows))]
fn main() {
    eprintln!("orisyvra-volume-mount is currently a Windows-only component.");
    std::process::exit(2);
}

#[cfg(all(windows, not(target_pointer_width = "64")))]
compile_error!("orisyvra-volume-mount currently supports 64-bit Windows only");

#[cfg(all(windows, target_pointer_width = "64"))]
mod windows_app {
    use std::collections::{HashMap, HashSet};
    use std::ffi::c_void;
    use std::io::Write as _;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::ptr;
    use std::process::Command;
    use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::thread;
    use std::time::Duration;

    use orisyvra::{unlock_key_source, unlock_keyfile, MasterKey};
    use orisyvra_volume::{Volume, VolumeError, VolumeOptions};
    use orisyvra_windows::{
        automount_root, load_entry, read_protected_secret, secret_path, state_path, stop_path,
        MountEntry,
    };
    use zeroize::{Zeroize, Zeroizing};

    const ERROR_SUCCESS: u32 = 0;
    const SECTOR_SIZE: u32 = 4096;
    const DEFAULT_INTERNAL_BLOCK_SIZE: u32 = 64 * 1024;
    const MAX_TRANSFER_LENGTH: u32 = 64 * 1024;

    const SCSISTAT_GOOD: u8 = 0x00;
    const SCSISTAT_CHECK_CONDITION: u8 = 0x02;
    const SENSE_MEDIUM_ERROR: u8 = 0x03;
    const SENSE_ILLEGAL_REQUEST: u8 = 0x05;
    const ASC_UNRECOVERED_READ_ERROR: u8 = 0x11;
    const ASC_WRITE_ERROR: u8 = 0x0c;
    const ASC_LBA_OUT_OF_RANGE: u8 = 0x21;

    const STD_INPUT_HANDLE: u32 = 0xffff_fff6;
    const ENABLE_ECHO_INPUT: u32 = 0x0004;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    #[repr(C)]
    struct StorageUnitParams {
        guid: Guid,
        block_count: u64,
        block_length: u32,
        product_id: [u8; 16],
        product_revision_level: [u8; 4],
        device_type: u8,
        _padding0: [u8; 3],
        flags: u32,
        max_transfer_length: u32,
        _padding1: u32,
        reserved: [u64; 8],
    }

    impl StorageUnitParams {
        fn new(volume_id: [u8; 32], block_count: u64, read_only: bool) -> Self {
            let mut product_id = [b' '; 16];
            product_id[..15].copy_from_slice(b"OrIsyVra Volume");
            let product_revision_level = *b"0.2 ";
            let flags = u32::from(read_only) | (1 << 1);
            Self {
                guid: guid_from_volume_id(volume_id),
                block_count,
                block_length: SECTOR_SIZE,
                product_id,
                product_revision_level,
                device_type: 0,
                _padding0: [0; 3],
                flags,
                max_transfer_length: MAX_TRANSFER_LENGTH,
                _padding1: 0,
                reserved: [0; 8],
            }
        }
    }

    #[repr(C)]
    #[derive(Default)]
    struct StorageUnitStatus {
        scsi_status: u8,
        sense_key: u8,
        asc: u8,
        ascq: u8,
        _padding0: [u8; 4],
        information: u64,
        reserved_csi: u64,
        reserved_sks: u32,
        flags: u32,
    }

    #[repr(C)]
    struct UnmapDescriptor {
        block_address: u64,
        block_count: u32,
        reserved: u32,
    }

    type ReadCallback = unsafe extern "C" fn(
        *mut c_void,
        *mut c_void,
        u64,
        u32,
        u8,
        *mut StorageUnitStatus,
    ) -> u8;
    type WriteCallback = ReadCallback;
    type FlushCallback = unsafe extern "C" fn(
        *mut c_void,
        u64,
        u32,
        *mut StorageUnitStatus,
    ) -> u8;
    type UnmapCallback = unsafe extern "C" fn(
        *mut c_void,
        *mut UnmapDescriptor,
        u32,
        *mut StorageUnitStatus,
    ) -> u8;

    #[repr(C)]
    struct StorageUnitInterface {
        read: Option<ReadCallback>,
        write: Option<WriteCallback>,
        flush: Option<FlushCallback>,
        unmap: Option<UnmapCallback>,
        reserved: [usize; 12],
    }

    static INTERFACE: StorageUnitInterface = StorageUnitInterface {
        read: Some(read_callback),
        write: Some(write_callback),
        flush: Some(flush_callback),
        unmap: None,
        reserved: [0; 12],
    };

    type StorageUnitCreateFn = unsafe extern "C" fn(
        *mut u16,
        *const StorageUnitParams,
        *const StorageUnitInterface,
        *mut *mut c_void,
    ) -> u32;
    type StorageUnitDeleteFn = unsafe extern "C" fn(*mut c_void);
    type StorageUnitShutdownFn = unsafe extern "C" fn(*mut c_void);
    type StorageUnitStartDispatcherFn = unsafe extern "C" fn(*mut c_void, u32) -> u32;
    type StorageUnitWaitDispatcherFn = unsafe extern "C" fn(*mut c_void);
    type VersionFn = unsafe extern "C" fn(*mut u32) -> u32;

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryW(path: *const u16) -> *mut c_void;
        fn FreeLibrary(module: *mut c_void) -> i32;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
        fn GetLastError() -> u32;
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(u32) -> i32>,
            add: i32,
        ) -> i32;
        fn GetStdHandle(which: u32) -> *mut c_void;
        fn GetConsoleMode(handle: *mut c_void, mode: *mut u32) -> i32;
        fn SetConsoleMode(handle: *mut c_void, mode: u32) -> i32;
        fn ReadConsoleW(
            handle: *mut c_void,
            buffer: *mut c_void,
            chars_to_read: u32,
            chars_read: *mut u32,
            input_control: *mut c_void,
        ) -> i32;
    }

    struct WinSpdApi {
        module: *mut c_void,
        create: StorageUnitCreateFn,
        delete: StorageUnitDeleteFn,
        shutdown: StorageUnitShutdownFn,
        start_dispatcher: StorageUnitStartDispatcherFn,
        wait_dispatcher: StorageUnitWaitDispatcherFn,
        version: VersionFn,
    }

    impl WinSpdApi {
        fn load() -> Result<Self, String> {
            let mut candidates = Vec::new();
            if let Some(path) = std::env::var_os("WINSPD_DLL") {
                candidates.push(PathBuf::from(path));
            }
            candidates.push(PathBuf::from("winspd-x64.dll"));
            if let Some(program_files) = std::env::var_os("ProgramFiles") {
                candidates.push(
                    PathBuf::from(program_files)
                        .join("WinSpd")
                        .join("sys")
                        .join("winspd-x64.dll"),
                );
            }
            if let Some(program_files) = std::env::var_os("ProgramFiles(x86)") {
                candidates.push(
                    PathBuf::from(program_files)
                        .join("WinSpd")
                        .join("sys")
                        .join("winspd-x64.dll"),
                );
            }

            let mut module = ptr::null_mut();
            let mut tried = Vec::new();
            for candidate in candidates {
                let wide = wide_path(&candidate);
                tried.push(candidate.display().to_string());
                module = unsafe { LoadLibraryW(wide.as_ptr()) };
                if !module.is_null() {
                    break;
                }
            }
            if module.is_null() {
                let code = unsafe { GetLastError() };
                return Err(format!(
                    "WinSpd runtime was not found (LoadLibrary error {code}). Tried: {}",
                    tried.join(", ")
                ));
            }

            unsafe {
                Ok(Self {
                    module,
                    create: load_symbol(module, b"SpdStorageUnitCreate\0")?,
                    delete: load_symbol(module, b"SpdStorageUnitDelete\0")?,
                    shutdown: load_symbol(module, b"SpdStorageUnitShutdown\0")?,
                    start_dispatcher: load_symbol(module, b"SpdStorageUnitStartDispatcher\0")?,
                    wait_dispatcher: load_symbol(module, b"SpdStorageUnitWaitDispatcher\0")?,
                    version: load_symbol(module, b"SpdVersion\0")?,
                })
            }
        }
    }

    impl Drop for WinSpdApi {
        fn drop(&mut self) {
            unsafe {
                if !self.module.is_null() {
                    FreeLibrary(self.module);
                }
            }
        }
    }

    unsafe fn load_symbol<T>(module: *mut c_void, name: &'static [u8]) -> Result<T, String>
    where
        T: Copy,
    {
        let address = GetProcAddress(module, name.as_ptr());
        if address.is_null() {
            return Err(format!(
                "WinSpd export {} was not found",
                String::from_utf8_lossy(&name[..name.len().saturating_sub(1)])
            ));
        }
        if std::mem::size_of::<T>() != std::mem::size_of::<*mut c_void>() {
            return Err("unexpected WinSpd function-pointer size".to_owned());
        }
        Ok(std::mem::transmute_copy(&address))
    }

    struct MountContext {
        volume: Volume,
        read_only: bool,
    }

    fn contexts() -> &'static Mutex<HashMap<usize, Arc<Mutex<MountContext>>>> {
        static CONTEXTS: OnceLock<Mutex<HashMap<usize, Arc<Mutex<MountContext>>>>> =
            OnceLock::new();
        CONTEXTS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    static ACTIVE_STORAGE_UNIT: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
    static SHUTDOWN_FUNCTION: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "system" fn console_ctrl_handler(_control_type: u32) -> i32 {
        request_shutdown();
        1
    }

    unsafe fn request_shutdown() {
        let storage = ACTIVE_STORAGE_UNIT.load(Ordering::Acquire);
        let function = SHUTDOWN_FUNCTION.load(Ordering::Acquire);
        if !storage.is_null() && function != 0 {
            let shutdown: StorageUnitShutdownFn = std::mem::transmute(function);
            shutdown(storage);
        }
    }

    unsafe extern "C" fn read_callback(
        storage_unit: *mut c_void,
        buffer: *mut c_void,
        block_address: u64,
        block_count: u32,
        flush_flag: u8,
        status: *mut StorageUnitStatus,
    ) -> u8 {
        let Some(context) = context_for(storage_unit) else {
            set_error(status, SENSE_MEDIUM_ERROR, ASC_UNRECOVERED_READ_ERROR, None);
            return 1;
        };
        let Some(length) = (block_count as usize).checked_mul(SECTOR_SIZE as usize) else {
            set_error(
                status,
                SENSE_ILLEGAL_REQUEST,
                ASC_LBA_OUT_OF_RANGE,
                Some(block_address),
            );
            return 1;
        };
        let Some(offset) = block_address.checked_mul(SECTOR_SIZE as u64) else {
            set_error(
                status,
                SENSE_ILLEGAL_REQUEST,
                ASC_LBA_OUT_OF_RANGE,
                Some(block_address),
            );
            return 1;
        };
        if length == 0 {
            set_good(status);
            return 1;
        }
        if buffer.is_null() {
            set_error(
                status,
                SENSE_MEDIUM_ERROR,
                ASC_UNRECOVERED_READ_ERROR,
                Some(block_address),
            );
            return 1;
        }

        let output = std::slice::from_raw_parts_mut(buffer.cast::<u8>(), length);
        let result = context
            .lock()
            .map_err(|_| "mount context lock poisoned".to_owned())
            .and_then(|mut context| {
                if flush_flag != 0 {
                    context.volume.sync().map_err(volume_error)?;
                }
                read_bytes(&mut context.volume, offset, output).map_err(volume_error)
            });
        match result {
            Ok(()) => set_good(status),
            Err(_) => set_error(
                status,
                SENSE_MEDIUM_ERROR,
                ASC_UNRECOVERED_READ_ERROR,
                Some(block_address),
            ),
        }
        1
    }

    unsafe extern "C" fn write_callback(
        storage_unit: *mut c_void,
        buffer: *mut c_void,
        block_address: u64,
        block_count: u32,
        flush_flag: u8,
        status: *mut StorageUnitStatus,
    ) -> u8 {
        let Some(context) = context_for(storage_unit) else {
            set_error(status, SENSE_MEDIUM_ERROR, ASC_WRITE_ERROR, None);
            return 1;
        };
        let Some(length) = (block_count as usize).checked_mul(SECTOR_SIZE as usize) else {
            set_error(
                status,
                SENSE_ILLEGAL_REQUEST,
                ASC_LBA_OUT_OF_RANGE,
                Some(block_address),
            );
            return 1;
        };
        let Some(offset) = block_address.checked_mul(SECTOR_SIZE as u64) else {
            set_error(
                status,
                SENSE_ILLEGAL_REQUEST,
                ASC_LBA_OUT_OF_RANGE,
                Some(block_address),
            );
            return 1;
        };
        if length == 0 {
            set_good(status);
            return 1;
        }
        if buffer.is_null() {
            set_error(status, SENSE_MEDIUM_ERROR, ASC_WRITE_ERROR, Some(block_address));
            return 1;
        }

        let input = std::slice::from_raw_parts(buffer.cast::<u8>(), length);
        let result = context
            .lock()
            .map_err(|_| "mount context lock poisoned".to_owned())
            .and_then(|mut context| {
                if context.read_only {
                    return Err("volume is mounted read-only".to_owned());
                }
                write_bytes(&mut context.volume, offset, input).map_err(volume_error)?;
                if flush_flag != 0 {
                    context.volume.sync().map_err(volume_error)?;
                }
                Ok(())
            });
        match result {
            Ok(()) => set_good(status),
            Err(_) => set_error(status, SENSE_MEDIUM_ERROR, ASC_WRITE_ERROR, Some(block_address)),
        }
        1
    }

    unsafe extern "C" fn flush_callback(
        storage_unit: *mut c_void,
        _block_address: u64,
        _block_count: u32,
        status: *mut StorageUnitStatus,
    ) -> u8 {
        let Some(context) = context_for(storage_unit) else {
            set_error(status, SENSE_MEDIUM_ERROR, ASC_WRITE_ERROR, None);
            return 1;
        };
        match context
            .lock()
            .map_err(|_| "mount context lock poisoned".to_owned())
            .and_then(|mut context| context.volume.sync().map_err(volume_error))
        {
            Ok(()) => set_good(status),
            Err(_) => set_error(status, SENSE_MEDIUM_ERROR, ASC_WRITE_ERROR, None),
        }
        1
    }

    fn context_for(storage_unit: *mut c_void) -> Option<Arc<Mutex<MountContext>>> {
        contexts()
            .lock()
            .ok()?
            .get(&(storage_unit as usize))
            .cloned()
    }

    unsafe fn set_good(status: *mut StorageUnitStatus) {
        if !status.is_null() {
            ptr::write(status, StorageUnitStatus::default());
            (*status).scsi_status = SCSISTAT_GOOD;
        }
    }

    unsafe fn set_error(
        status: *mut StorageUnitStatus,
        sense_key: u8,
        asc: u8,
        information: Option<u64>,
    ) {
        if status.is_null() {
            return;
        }
        ptr::write(status, StorageUnitStatus::default());
        (*status).scsi_status = SCSISTAT_CHECK_CONDITION;
        (*status).sense_key = sense_key;
        (*status).asc = asc;
        if let Some(information) = information {
            (*status).information = information;
            (*status).flags |= 1 << 8;
        }
    }

    fn read_bytes(volume: &mut Volume, offset: u64, output: &mut [u8]) -> Result<(), VolumeError> {
        let info = volume.info();
        let end = offset
            .checked_add(output.len() as u64)
            .ok_or(VolumeError::BlockOutOfRange)?;
        if end > info.logical_capacity {
            return Err(VolumeError::BlockOutOfRange);
        }

        output.fill(0);
        let block_size = info.block_size as u64;
        let mut done = 0usize;
        while done < output.len() {
            let absolute = offset + done as u64;
            let block_index = absolute / block_size;
            let block_offset = (absolute % block_size) as usize;
            let take = (output.len() - done).min(info.block_size as usize - block_offset);
            if let Some(block) = volume.read_block(block_index)? {
                let available = block.len().saturating_sub(block_offset).min(take);
                if available > 0 {
                    output[done..done + available]
                        .copy_from_slice(&block[block_offset..block_offset + available]);
                }
            }
            done += take;
        }
        Ok(())
    }

    fn write_bytes(volume: &mut Volume, offset: u64, input: &[u8]) -> Result<(), VolumeError> {
        let info = volume.info();
        let end = offset
            .checked_add(input.len() as u64)
            .ok_or(VolumeError::BlockOutOfRange)?;
        if end > info.logical_capacity {
            return Err(VolumeError::BlockOutOfRange);
        }

        let block_size = info.block_size as u64;
        let mut done = 0usize;
        while done < input.len() {
            let absolute = offset + done as u64;
            let block_index = absolute / block_size;
            let block_start = block_index * block_size;
            let block_offset = (absolute - block_start) as usize;
            let logical_block_len = (info.logical_capacity - block_start).min(block_size) as usize;
            let take = (input.len() - done).min(logical_block_len - block_offset);

            let mut block = volume
                .read_block(block_index)?
                .unwrap_or_else(|| vec![0; logical_block_len]);
            block.resize(logical_block_len, 0);
            block[block_offset..block_offset + take]
                .copy_from_slice(&input[done..done + take]);
            volume.write_block(block_index, &block)?;
            done += take;
        }
        Ok(())
    }

    fn initialize_mbr(volume: &mut Volume) -> Result<(), String> {
        let info = volume.info();
        if info.logical_capacity < 16 * 1024 * 1024 {
            return Err("volume is too small for the Windows partition layout".to_owned());
        }
        if info.logical_capacity % SECTOR_SIZE as u64 != 0 {
            return Err(format!(
                "logical capacity must be divisible by {SECTOR_SIZE}"
            ));
        }

        let mut existing = [0u8; 512];
        read_bytes(volume, 0, &mut existing).map_err(volume_error)?;
        if existing.iter().any(|byte| *byte != 0) {
            return Err(
                "sector 0 is not empty; refusing to overwrite an existing partition table".to_owned(),
            );
        }

        let block_count = info.logical_capacity / SECTOR_SIZE as u64;
        let start_lba = 1u64;
        let partition_count = block_count
            .checked_sub(start_lba)
            .ok_or_else(|| "volume has no space for a partition".to_owned())?;
        if partition_count > u32::MAX as u64 {
            return Err("MBR layout supports at most 2^32 logical sectors".to_owned());
        }

        let mut mbr = [0u8; 512];
        mbr[..5].copy_from_slice(&[0xcd, 0x18, 0xf4, 0xeb, 0xfd]);
        mbr[440..444].copy_from_slice(&info.volume_id[..4]);
        let entry = &mut mbr[446..462];
        entry[0] = 0;
        entry[1..4].copy_from_slice(&lba_to_chs(start_lba as u32));
        entry[4] = 0x07;
        let last_lba = (start_lba + partition_count).min(u32::MAX as u64) as u32;
        entry[5..8].copy_from_slice(&lba_to_chs(last_lba));
        entry[8..12].copy_from_slice(&(start_lba as u32).to_le_bytes());
        entry[12..16].copy_from_slice(&(partition_count as u32).to_le_bytes());
        mbr[510] = 0x55;
        mbr[511] = 0xaa;

        write_bytes(volume, 0, &mbr).map_err(volume_error)?;
        volume.sync().map_err(volume_error)?;
        Ok(())
    }

    fn lba_to_chs(lba: u32) -> [u8; 3] {
        const SECTORS_PER_TRACK: u32 = 63;
        const HEADS_PER_CYLINDER: u32 = 255;
        let mut cylinder = lba / (HEADS_PER_CYLINDER * SECTORS_PER_TRACK);
        let mut head = (lba / SECTORS_PER_TRACK) % HEADS_PER_CYLINDER;
        let mut sector = (lba % SECTORS_PER_TRACK) + 1;
        if cylinder > 1023 {
            cylinder = 1023;
            head = 254;
            sector = 63;
        }
        [
            head as u8,
            ((sector & 0x3f) | ((cylinder >> 2) & 0xc0)) as u8,
            (cylinder & 0xff) as u8,
        ]
    }

    fn guid_from_volume_id(volume_id: [u8; 32]) -> Guid {
        Guid {
            data1: u32::from_le_bytes(volume_id[0..4].try_into().expect("fixed GUID field")),
            data2: u16::from_le_bytes(volume_id[4..6].try_into().expect("fixed GUID field")),
            data3: u16::from_le_bytes(volume_id[6..8].try_into().expect("fixed GUID field")),
            data4: volume_id[8..16].try_into().expect("fixed GUID field"),
        }
    }

    fn prompt_passphrase() -> Result<Zeroizing<String>, String> {
        print!("Visual-key passphrase: ");
        std::io::stdout().flush().map_err(|error| error.to_string())?;

        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if handle.is_null() || handle as isize == -1 {
            return Err("no Windows console input handle is available".to_owned());
        }
        let mut original_mode = 0u32;
        if unsafe { GetConsoleMode(handle, &mut original_mode) } == 0 {
            return Err("passphrase input requires a Windows console".to_owned());
        }
        if unsafe { SetConsoleMode(handle, original_mode & !ENABLE_ECHO_INPUT) } == 0 {
            return Err("could not disable console echo".to_owned());
        }

        let mut buffer = [0u16; 1024];
        let mut read = 0u32;
        let result = unsafe {
            ReadConsoleW(
                handle,
                buffer.as_mut_ptr().cast::<c_void>(),
                buffer.len() as u32 - 1,
                &mut read,
                ptr::null_mut(),
            )
        };
        unsafe {
            SetConsoleMode(handle, original_mode);
        }
        println!();
        if result == 0 {
            buffer.zeroize();
            return Err("could not read the passphrase from the Windows console".to_owned());
        }

        let mut password = String::from_utf16(&buffer[..read as usize])
            .map_err(|_| "passphrase contained invalid UTF-16".to_owned())?;
        buffer.zeroize();
        while password.ends_with(['\r', '\n']) {
            password.pop();
        }
        if password.is_empty() {
            password.zeroize();
            return Err("passphrase cannot be empty".to_owned());
        }
        Ok(Zeroizing::new(password))
    }

    fn volume_error(error: VolumeError) -> String {
        error.to_string()
    }

    fn wide_path(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    fn credential_path(id: &str) -> Result<PathBuf, String> {
        Ok(automount_root()
            .map_err(|error| error.to_string())?
            .join("credentials")
            .join(format!("{id}.orisyvra-key")))
    }

    fn scheduled_task_name(id: &str) -> String {
        format!("OrIsyVra-Volume-{id}")
    }

    fn unlock_entry_master(entry: &MountEntry) -> Result<Option<MasterKey>, String> {
        let secret = secret_path(&entry.id).map_err(|error| error.to_string())?;
        if !secret.is_file() {
            return Ok(None);
        }
        let mut mount_password = read_protected_secret(&secret).map_err(|error| error.to_string())?;
        if !entry.auto_unlock {
            let _ = std::fs::remove_file(&secret);
        }
        let credential = credential_path(&entry.id)?;
        let master = unlock_keyfile(&credential, &mount_password)
            .map_err(|error| format!("could not unlock the dedicated mount credential: {error}"));
        mount_password.zeroize();
        master.map(Some)
    }

    fn register_entry(id: &str) -> Result<(), String> {
        let _entry = load_entry(id).map_err(|error| error.to_string())?;
        let executable = std::env::current_exe().map_err(|error| error.to_string())?;
        let action = format!("\"{}\" run-entry {}", executable.display(), id);
        let status = Command::new("schtasks.exe")
            .args([
                "/Create",
                "/TN",
                &scheduled_task_name(id),
                "/TR",
                &action,
                "/SC",
                "ONLOGON",
                "/RL",
                "HIGHEST",
                "/IT",
                "/F",
            ])
            .status()
            .map_err(|error| format!("could not launch schtasks.exe: {error}"))?;
        if !status.success() {
            return Err(format!(
                "Task Scheduler registration failed with exit code {:?}",
                status.code()
            ));
        }
        println!("Registered Windows mount task: {}", scheduled_task_name(id));
        Ok(())
    }

    fn unregister_entry(id: &str) -> Result<(), String> {
        let status = Command::new("schtasks.exe")
            .args(["/Delete", "/TN", &scheduled_task_name(id), "/F"])
            .status()
            .map_err(|error| format!("could not launch schtasks.exe: {error}"))?;
        if !status.success() {
            return Err(format!(
                "Task Scheduler removal failed with exit code {:?}",
                status.code()
            ));
        }
        Ok(())
    }

    #[derive(Default)]
    struct VolumeMountSnapshot {
        guids: HashSet<String>,
    }

    fn mountvol_snapshot() -> VolumeMountSnapshot {
        let Ok(output) = Command::new("mountvol.exe").output() else {
            return VolumeMountSnapshot::default();
        };
        let text = String::from_utf8_lossy(&output.stdout);
        let guids = text
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with(r"\\?\Volume{") && line.ends_with('\\'))
            .map(ToOwned::to_owned)
            .collect();
        VolumeMountSnapshot { guids }
    }

    fn move_new_volume_to_preferred_letter(before: VolumeMountSnapshot, letter: char) {
        let preferred = letter.to_ascii_uppercase();
        let drive_root = format!("{preferred}:\\");
        if Path::new(&drive_root).exists() {
            eprintln!("Preferred drive letter {preferred}: is already in use; Windows assignment is kept.");
            return;
        }
        for _ in 0..40 {
            thread::sleep(Duration::from_millis(500));
            let after = mountvol_snapshot();
            let mut new_guids = after
                .guids
                .difference(&before.guids)
                .cloned()
                .collect::<Vec<_>>();
            new_guids.sort();
            if new_guids.len() == 1 {
                let status = Command::new("mountvol.exe")
                    .arg(format!("{preferred}:"))
                    .arg(&new_guids[0])
                    .status();
                if status.is_ok_and(|value| value.success()) {
                    println!("Preferred drive letter assigned: {preferred}:");
                } else {
                    eprintln!("Windows did not accept preferred drive letter {preferred}:; its automatic assignment is kept.");
                }
                return;
            }
        }
    }

    struct MountFiles {
        state: Option<PathBuf>,
        stop: Option<PathBuf>,
        preferred_letter: Option<char>,
    }

    fn mount_volume_with_master(
        volume_path: &Path,
        master: &MasterKey,
        read_only: bool,
        files: MountFiles,
    ) -> Result<(), String> {
        let mut volume = Volume::open(volume_path, master).map_err(volume_error)?;
        let info = volume.info();
        if info.logical_capacity % SECTOR_SIZE as u64 != 0 {
            return Err(format!(
                "logical capacity is not divisible by the sector size {SECTOR_SIZE}"
            ));
        }
        let sector_count = info.logical_capacity / SECTOR_SIZE as u64;
        if sector_count == 0 {
            return Err("volume has no addressable sectors".to_owned());
        }
        volume.mark_dirty().map_err(volume_error)?;

        if let Some(state) = &files.state {
            if let Some(parent) = state.parent() {
                std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            }
            let _ = std::fs::remove_file(state);
        }
        if let Some(stop) = &files.stop {
            if let Some(parent) = stop.parent() {
                std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            }
            let _ = std::fs::remove_file(stop);
        }

        let api = WinSpdApi::load()?;
        let mut runtime_version = 0u32;
        let version_error = unsafe { (api.version)(&mut runtime_version) };
        if version_error != ERROR_SUCCESS {
            return Err(format!("SpdVersion failed with error {version_error}"));
        }
        println!("WinSpd runtime version: 0x{runtime_version:08x}");

        let before = mountvol_snapshot();
        let params = StorageUnitParams::new(info.volume_id, sector_count, read_only);
        let mut storage_unit = ptr::null_mut();
        let create_error = unsafe {
            (api.create)(
                ptr::null_mut(),
                &params,
                &INTERFACE,
                &mut storage_unit,
            )
        };
        if create_error != ERROR_SUCCESS || storage_unit.is_null() {
            return Err(format!(
                "SpdStorageUnitCreate failed with error {create_error}. Windows mount tasks must run elevated."
            ));
        }

        let context = Arc::new(Mutex::new(MountContext { volume, read_only }));
        contexts()
            .lock()
            .map_err(|_| "mount context map lock poisoned".to_owned())?
            .insert(storage_unit as usize, Arc::clone(&context));

        ACTIVE_STORAGE_UNIT.store(storage_unit, Ordering::Release);
        SHUTDOWN_FUNCTION.store(api.shutdown as usize, Ordering::Release);
        unsafe {
            SetConsoleCtrlHandler(Some(console_ctrl_handler), 1);
        }

        let start_error = unsafe { (api.start_dispatcher)(storage_unit, 0) };
        if start_error != ERROR_SUCCESS {
            contexts()
                .lock()
                .ok()
                .and_then(|mut map| map.remove(&(storage_unit as usize)));
            ACTIVE_STORAGE_UNIT.store(ptr::null_mut(), Ordering::Release);
            SHUTDOWN_FUNCTION.store(0, Ordering::Release);
            unsafe {
                SetConsoleCtrlHandler(Some(console_ctrl_handler), 0);
                (api.delete)(storage_unit);
            }
            return Err(format!(
                "SpdStorageUnitStartDispatcher failed with error {start_error}"
            ));
        }

        if let Some(state) = &files.state {
            std::fs::write(state, format!("pid={}\nvolume={}\n", std::process::id(), volume_path.display()))
                .map_err(|error| error.to_string())?;
        }

        if let Some(letter) = files.preferred_letter {
            thread::spawn(move || move_new_volume_to_preferred_letter(before, letter));
        }

        if let Some(stop) = files.stop.clone() {
            thread::spawn(move || loop {
                thread::sleep(Duration::from_millis(350));
                if stop.exists() {
                    let _ = std::fs::remove_file(&stop);
                    unsafe {
                        request_shutdown();
                    }
                    break;
                }
                if ACTIVE_STORAGE_UNIT.load(Ordering::Acquire).is_null() {
                    break;
                }
            });
        }

        println!("Encrypted virtual disk is attached. Windows will expose the partition as a normal disk/volume.");
        unsafe {
            (api.wait_dispatcher)(storage_unit);
        }

        ACTIVE_STORAGE_UNIT.store(ptr::null_mut(), Ordering::Release);
        SHUTDOWN_FUNCTION.store(0, Ordering::Release);
        unsafe {
            SetConsoleCtrlHandler(Some(console_ctrl_handler), 0);
        }
        contexts()
            .lock()
            .ok()
            .and_then(|mut map| map.remove(&(storage_unit as usize)));
        if let Ok(mut context) = context.lock() {
            let _ = context.volume.sync();
            let _ = context.volume.mark_clean();
        }
        unsafe {
            (api.delete)(storage_unit);
        }
        if let Some(state) = files.state {
            let _ = std::fs::remove_file(state);
        }
        if let Some(stop) = files.stop {
            let _ = std::fs::remove_file(stop);
        }
        println!("Encrypted virtual disk detached cleanly.");
        Ok(())
    }

    fn run_entry(id: &str) -> Result<(), String> {
        let entry = load_entry(id).map_err(|error| error.to_string())?;
        let state = state_path(id).map_err(|error| error.to_string())?;
        if state.is_file() {
            return Ok(());
        }
        let Some(master) = unlock_entry_master(&entry)? else {
            return Ok(());
        };
        mount_volume_with_master(
            &entry.volume_path,
            &master,
            entry.read_only,
            MountFiles {
                state: Some(state),
                stop: Some(stop_path(id).map_err(|error| error.to_string())?),
                preferred_letter: entry.preferred_letter,
            },
        )
    }

    enum ParsedCommand {
        Probe,
        Create {
            volume: PathBuf,
            key: PathBuf,
            size_gib: u64,
            internal_block_size: u32,
        },
        Mount {
            volume: PathBuf,
            key: PathBuf,
            read_only: bool,
            initialize_mbr: bool,
        },
        RunEntry { id: String },
        RegisterEntry { id: String },
        UnregisterEntry { id: String },
    }

    fn parse_args() -> Result<ParsedCommand, String> {
        let mut args = std::env::args_os().skip(1).collect::<Vec<_>>();
        if args.is_empty() {
            return Err(usage());
        }
        let command = args.remove(0).to_string_lossy().to_ascii_lowercase();
        match command.as_str() {
            "probe" => return Ok(ParsedCommand::Probe),
            "run-entry" | "register-entry" | "unregister-entry" => {
                if args.len() != 1 {
                    return Err(usage());
                }
                let id = args.remove(0).to_string_lossy().into_owned();
                return Ok(match command.as_str() {
                    "run-entry" => ParsedCommand::RunEntry { id },
                    "register-entry" => ParsedCommand::RegisterEntry { id },
                    _ => ParsedCommand::UnregisterEntry { id },
                });
            }
            "create" | "mount" => {}
            _ => return Err(usage()),
        }
        if args.is_empty() {
            return Err(usage());
        }
        let volume = PathBuf::from(args.remove(0));
        let mut key = None;
        let mut size_gib = None;
        let mut internal_block_size = DEFAULT_INTERNAL_BLOCK_SIZE;
        let mut read_only = false;
        let mut initialize_partition = false;

        let mut index = 0usize;
        while index < args.len() {
            let flag = args[index].to_string_lossy().to_string();
            match flag.as_str() {
                "--key" => {
                    index += 1;
                    let value = args.get(index).ok_or_else(usage)?;
                    key = Some(PathBuf::from(value));
                }
                "--size-gib" => {
                    index += 1;
                    let value = args.get(index).ok_or_else(usage)?;
                    size_gib = Some(
                        value
                            .to_string_lossy()
                            .parse::<u64>()
                            .map_err(|_| "--size-gib must be an integer".to_owned())?,
                    );
                }
                "--internal-block-size" => {
                    index += 1;
                    let value = args.get(index).ok_or_else(usage)?;
                    internal_block_size = value
                        .to_string_lossy()
                        .parse::<u32>()
                        .map_err(|_| "--internal-block-size must be an integer".to_owned())?;
                }
                "--read-only" => read_only = true,
                "--init-mbr" => initialize_partition = true,
                _ => return Err(format!("unknown option: {flag}\n\n{}", usage())),
            }
            index += 1;
        }

        let key = key.ok_or_else(|| format!("--key is required\n\n{}", usage()))?;
        if command == "create" {
            let size_gib = size_gib.ok_or_else(|| format!("--size-gib is required\n\n{}", usage()))?;
            return Ok(ParsedCommand::Create {
                volume,
                key,
                size_gib,
                internal_block_size,
            });
        }
        Ok(ParsedCommand::Mount {
            volume,
            key,
            read_only,
            initialize_mbr: initialize_partition,
        })
    }

    fn usage() -> String {
        format!(
            "OrIsyVra Windows virtual-disk host\n\n\
             Usage:\n\
               orisyvra-volume-mount probe\n\
               orisyvra-volume-mount create <volume.orisyvra-volume> --key <visual-key.png> --size-gib <N> [--internal-block-size 65536]\n\
               orisyvra-volume-mount mount <volume.orisyvra-volume> --key <visual-key.png> [--read-only] [--init-mbr]\n\
               orisyvra-volume-mount run-entry <id>\n\
               orisyvra-volume-mount register-entry <id>\n\
               orisyvra-volume-mount unregister-entry <id>\n\n\
             Windows storage uses {SECTOR_SIZE}-byte logical sectors through WinSpd."
        )
    }

    fn create_volume(
        volume_path: &Path,
        key_path: &Path,
        size_gib: u64,
        internal_block_size: u32,
    ) -> Result<(), String> {
        let password = prompt_passphrase()?;
        let master = unlock_key_source(key_path, password.as_bytes()).map_err(|error| error.to_string())?;
        let capacity = size_gib
            .checked_mul(1024 * 1024 * 1024)
            .ok_or_else(|| "requested capacity is too large".to_owned())?;
        let mut volume = Volume::create(
            volume_path,
            &master,
            VolumeOptions {
                logical_capacity: capacity,
                block_size: internal_block_size,
            },
        )
        .map_err(volume_error)?;
        initialize_mbr(&mut volume)?;
        volume.mark_clean().map_err(volume_error)?;
        println!(
            "Created {} GiB encrypted volume: {}",
            size_gib,
            volume_path.display()
        );
        println!("The Windows partition table is initialized. On the first attachment, format the partition as NTFS/exFAT once before normal use.");
        Ok(())
    }

    fn mount_volume(
        volume_path: &Path,
        key_path: &Path,
        read_only: bool,
        initialize_partition: bool,
    ) -> Result<(), String> {
        let password = prompt_passphrase()?;
        let master = unlock_key_source(key_path, password.as_bytes()).map_err(|error| error.to_string())?;
        if initialize_partition {
            let mut volume = Volume::open(volume_path, &master).map_err(volume_error)?;
            initialize_mbr(&mut volume)?;
            volume.mark_clean().map_err(volume_error)?;
            drop(volume);
        }
        mount_volume_with_master(
            volume_path,
            &master,
            read_only,
            MountFiles {
                state: None,
                stop: None,
                preferred_letter: None,
            },
        )
    }

    pub fn run() -> Result<(), String> {
        match parse_args()? {
            ParsedCommand::Probe => {
                let api = WinSpdApi::load()?;
                let mut version = 0u32;
                let error = unsafe { (api.version)(&mut version) };
                if error != ERROR_SUCCESS {
                    return Err(format!("SpdVersion failed with error {error}"));
                }
                println!("WinSpd runtime detected: 0x{version:08x}");
                Ok(())
            }
            ParsedCommand::Create {
                volume,
                key,
                size_gib,
                internal_block_size,
            } => create_volume(&volume, &key, size_gib, internal_block_size),
            ParsedCommand::Mount {
                volume,
                key,
                read_only,
                initialize_mbr,
            } => mount_volume(&volume, &key, read_only, initialize_mbr),
            ParsedCommand::RunEntry { id } => run_entry(&id),
            ParsedCommand::RegisterEntry { id } => register_entry(&id),
            ParsedCommand::UnregisterEntry { id } => unregister_entry(&id),
        }
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn main() {
    if let Err(error) = windows_app::run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
