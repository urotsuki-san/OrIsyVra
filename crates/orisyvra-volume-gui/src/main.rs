#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use eframe::egui;
use orisyvra::{
    export_recovery_keyfile_from_master, key_source_info, unlock_key_source, KeyfileParams,
    MasterKey,
};
use orisyvra_volume::{Volume, VolumeOptions};
use orisyvra_windows::{
    automount_root, list_entries, remove_entry_files, save_entry, secret_path, state_path,
    stop_path, volume_id_hex, write_protected_secret, MountEntry,
};
use rand::rngs::OsRng;
use rand::RngCore;
use rfd::FileDialog;
use zeroize::{Zeroize, Zeroizing};

const WINDOWS_SECTOR_SIZE: u64 = 4096;
const INTERNAL_BLOCK_SIZE: u32 = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StatusKind {
    Info,
    Success,
    Error,
}

struct Status {
    kind: StatusKind,
    message: String,
}

#[derive(Clone, Copy)]
enum EntryAction {
    None,
    Mount(usize),
    Unmount(usize),
    Register(usize),
    Remove(usize),
    OpenFolder(usize),
}

struct App {
    japanese: bool,
    entries: Vec<MountEntry>,
    key_path: String,
    key_fingerprint: Option<String>,
    passphrase: String,
    show_passphrase: bool,
    master: Option<Arc<MasterKey>>,
    create_size_gib: u64,
    create_letter: String,
    create_read_only: bool,
    create_auto_mount: bool,
    create_auto_unlock: bool,
    status: Option<Status>,
    runtime_status: String,
    startup_mode: bool,
    startup_keys: Vec<PathBuf>,
    startup_index: usize,
}

impl Drop for App {
    fn drop(&mut self) {
        self.passphrase.zeroize();
        self.master = None;
    }
}

fn tr<'a>(jp: bool, ja: &'a str, en: &'a str) -> &'a str {
    if jp { ja } else { en }
}

fn configure_style(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = egui::Color32::from_rgb(7, 13, 29);
    visuals.window_fill = egui::Color32::from_rgb(14, 18, 38);
    visuals.extreme_bg_color = egui::Color32::from_rgb(5, 9, 22);
    visuals.selection.bg_fill = egui::Color32::from_rgb(105, 78, 160);
    ctx.set_visuals(visuals);
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(14.0, 8.0);
    style.spacing.interact_size.y = 36.0;
    ctx.set_style(style);
}

fn japanese_font_candidates() -> Vec<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let windows = std::env::var_os("WINDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        let fonts = windows.join("Fonts");
        return vec![
            fonts.join("YuGothM.ttc"),
            fonts.join("YuGothR.ttc"),
            fonts.join("meiryo.ttc"),
            fonts.join("msgothic.ttc"),
        ];
    }
    #[cfg(target_os = "macos")]
    {
        return vec![
            PathBuf::from("/System/Library/Fonts/ヒラギノ角ゴシック W3.ttc"),
            PathBuf::from("/Library/Fonts/NotoSansCJK-Regular.ttc"),
        ];
    }
    #[cfg(target_os = "linux")]
    {
        return vec![
            PathBuf::from("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"),
            PathBuf::from("/usr/share/fonts/opentype/noto/NotoSansCJKjp-Regular.otf"),
        ];
    }
    #[allow(unreachable_code)]
    Vec::new()
}

fn install_japanese_font(ctx: &egui::Context) -> bool {
    for path in japanese_font_candidates() {
        let Ok(bytes) = fs::read(path) else { continue; };
        let mut fonts = egui::FontDefinitions::default();
        let name = "orisyvra-volume-japanese".to_owned();
        fonts
            .font_data
            .insert(name.clone(), egui::FontData::from_owned(bytes).into());
        if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
            family.insert(0, name.clone());
        }
        if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
            family.insert(0, name);
        }
        ctx.set_fonts(fonts);
        return true;
    }
    false
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

fn mount_host_path() -> Result<PathBuf, String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let directory = executable
        .parent()
        .ok_or_else(|| "application directory could not be determined".to_owned())?;
    let same_directory = directory.join("orisyvra-volume-mount.exe");
    if same_directory.is_file() {
        return Ok(same_directory);
    }
    let installed = directory.join("bin").join("orisyvra-volume-mount.exe");
    if installed.is_file() {
        return Ok(installed);
    }
    Err("orisyvra-volume-mount.exe is missing from the installation".to_owned())
}

fn probe_runtime() -> String {
    if !cfg!(windows) {
        return "Windows only".to_owned();
    }
    let Ok(host) = mount_host_path() else {
        return "Mount host missing".to_owned();
    };
    match Command::new(host).arg("probe").output() {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            if text.is_empty() { "WinSpd ready".to_owned() } else { text }
        }
        Ok(output) => {
            let text = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            if text.is_empty() { "WinSpd not ready".to_owned() } else { text }
        }
        Err(error) => format!("WinSpd probe failed: {error}"),
    }
}

fn powershell_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn elevated_host_command(command: &str, id: &str) -> Result<(), String> {
    let host = mount_host_path()?;
    let script = format!(
        "$p = Start-Process -FilePath {} -ArgumentList @({}, {}) -Verb RunAs -Wait -PassThru; exit $p.ExitCode",
        powershell_literal(&host.display().to_string()),
        powershell_literal(command),
        powershell_literal(id),
    );
    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", &script])
        .status()
        .map_err(|error| format!("could not start elevated mount setup: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("Windows mount setup was cancelled or failed".to_owned())
    }
}

fn run_task(id: &str) -> Result<(), String> {
    let status = Command::new("schtasks.exe")
        .args(["/Run", "/TN", &scheduled_task_name(id)])
        .status()
        .map_err(|error| format!("could not start Windows mount task: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("Windows mount task could not be started".to_owned())
    }
}

fn set_gui_startup(enabled: bool) -> Result<(), String> {
    if !cfg!(windows) {
        return Ok(());
    }
    let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
    if enabled {
        let executable = std::env::current_exe().map_err(|error| error.to_string())?;
        let value = format!("\"{}\" --startup-automount", executable.display());
        let status = Command::new("reg.exe")
            .args([
                "ADD",
                key,
                "/v",
                "OrIsyVraVolumes",
                "/t",
                "REG_SZ",
                "/d",
                &value,
                "/f",
            ])
            .status()
            .map_err(|error| error.to_string())?;
        if !status.success() {
            return Err("could not register OrIsyVra startup".to_owned());
        }
    } else {
        let _ = Command::new("reg.exe")
            .args(["DELETE", key, "/v", "OrIsyVraVolumes", "/f"])
            .status();
    }
    Ok(())
}

fn initialize_windows_mbr(volume: &mut Volume) -> Result<(), String> {
    let info = volume.info();
    if info.logical_capacity < 16 * 1024 * 1024 {
        return Err("volume must be at least 16 MiB".to_owned());
    }
    if info.logical_capacity % WINDOWS_SECTOR_SIZE != 0 {
        return Err("volume capacity must be divisible by 4096 bytes".to_owned());
    }
    let mut block = volume
        .read_block(0)
        .map_err(|error| error.to_string())?
        .unwrap_or_else(|| vec![0; info.block_size as usize]);
    block.resize(info.block_size as usize, 0);
    if block[..512].iter().any(|value| *value != 0) {
        return Err("volume already contains a partition table".to_owned());
    }

    let sectors = info.logical_capacity / WINDOWS_SECTOR_SIZE;
    let partition_count = sectors
        .checked_sub(1)
        .ok_or_else(|| "volume is too small".to_owned())?;
    if partition_count > u32::MAX as u64 {
        return Err("current Windows MBR layout supports up to 2^32 sectors".to_owned());
    }

    let mbr = &mut block[..512];
    mbr[..5].copy_from_slice(&[0xcd, 0x18, 0xf4, 0xeb, 0xfd]);
    mbr[440..444].copy_from_slice(&info.volume_id[..4]);
    let partition = &mut mbr[446..462];
    partition[0] = 0;
    partition[1..4].copy_from_slice(&[0, 2, 0]);
    partition[4] = 0x07;
    partition[5..8].copy_from_slice(&[254, 255, 255]);
    partition[8..12].copy_from_slice(&1_u32.to_le_bytes());
    partition[12..16].copy_from_slice(&(partition_count as u32).to_le_bytes());
    mbr[510] = 0x55;
    mbr[511] = 0xaa;
    volume.write_block(0, &block).map_err(|error| error.to_string())?;
    volume.sync().map_err(|error| error.to_string())?;
    Ok(())
}

fn entry_is_mounted(entry: &MountEntry) -> bool {
    if !cfg!(windows) {
        return false;
    }
    let Ok(path) = state_path(&entry.id) else { return false; };
    if !path.is_file() {
        return false;
    }
    let Ok(text) = fs::read_to_string(&path) else { return true; };
    let Some(pid) = text
        .lines()
        .find_map(|line| line.strip_prefix("pid="))
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return true;
    };
    let output = Command::new("tasklist.exe")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .output();
    match output {
        Ok(output) if String::from_utf8_lossy(&output.stdout).contains(&pid.to_string()) => true,
        _ => {
            let _ = fs::remove_file(path);
            false
        }
    }
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_style(&cc.egui_ctx);
        let japanese = install_japanese_font(&cc.egui_ctx);
        let entries = list_entries().unwrap_or_default();
        let startup_mode = std::env::args().any(|arg| arg == "--startup-automount");
        let mut startup_keys = Vec::new();
        if startup_mode {
            for entry in &entries {
                if entry.auto_mount && !entry.auto_unlock && !startup_keys.contains(&entry.key_path) {
                    startup_keys.push(entry.key_path.clone());
                }
                if entry.auto_mount && entry.auto_unlock {
                    let _ = run_task(&entry.id);
                }
            }
        }
        let key_path = startup_keys
            .first()
            .map(|value| value.display().to_string())
            .unwrap_or_default();
        let status = if startup_mode && !startup_keys.is_empty() {
            Some(Status {
                kind: StatusKind::Info,
                message: if japanese {
                    "Windows自動マウント: ビジュアルキーを一度解除してください。".to_owned()
                } else {
                    "Windows auto-mount: unlock the visual key once.".to_owned()
                },
            })
        } else {
            None
        };
        Self {
            japanese,
            entries,
            key_path,
            key_fingerprint: None,
            passphrase: String::new(),
            show_passphrase: false,
            master: None,
            create_size_gib: 10,
            create_letter: "O".to_owned(),
            create_read_only: false,
            create_auto_mount: false,
            create_auto_unlock: false,
            status,
            runtime_status: probe_runtime(),
            startup_mode,
            startup_keys,
            startup_index: 0,
        }
    }

    fn set_status(&mut self, kind: StatusKind, message: impl Into<String>) {
        self.status = Some(Status {
            kind,
            message: message.into(),
        });
    }

    fn refresh_entries(&mut self) {
        self.entries = list_entries().unwrap_or_default();
    }

    fn sync_startup(&mut self) {
        let prompt_startup = self
            .entries
            .iter()
            .any(|entry| entry.auto_mount && !entry.auto_unlock);
        if let Err(error) = set_gui_startup(prompt_startup) {
            self.set_status(StatusKind::Error, error);
        }
    }

    fn choose_key(&mut self) {
        let Some(path) = FileDialog::new()
            .add_filter("OrIsyVra visual key", &["png", "orisyvra-key"])
            .pick_file()
        else {
            return;
        };
        match key_source_info(&path) {
            Ok(info) => {
                self.key_path = path.display().to_string();
                self.key_fingerprint = Some(info.card_id);
                self.master = None;
                self.passphrase.zeroize();
                self.status = None;
            }
            Err(error) => self.set_status(StatusKind::Error, error.to_string()),
        }
    }

    fn unlock_key(&mut self) {
        if self.key_path.trim().is_empty() {
            self.set_status(
                StatusKind::Error,
                tr(self.japanese, "先にビジュアルキーを選んでください。", "Choose a visual key first."),
            );
            return;
        }
        let password = Zeroizing::new(std::mem::take(&mut self.passphrase));
        match unlock_key_source(Path::new(self.key_path.trim()), password.as_bytes()) {
            Ok(master) => {
                self.master = Some(Arc::new(master));
                self.set_status(
                    StatusKind::Success,
                    tr(self.japanese, "ビジュアルキーを解除しました。", "Visual key unlocked."),
                );
                if self.startup_mode {
                    self.mount_startup_entries_for_current_key();
                }
            }
            Err(error) => self.set_status(StatusKind::Error, error.to_string()),
        }
    }

    fn current_master_for(&self, entry: &MountEntry) -> Option<Arc<MasterKey>> {
        if Path::new(self.key_path.trim()) == entry.key_path {
            self.master.as_ref().map(Arc::clone)
        } else {
            None
        }
    }

    fn prepare_credential(&self, entry: &MountEntry, master: &MasterKey) -> Result<(), String> {
        let mut mount_password = [0_u8; 32];
        OsRng.fill_bytes(&mut mount_password);
        let credential = credential_path(&entry.id)?;
        if let Some(parent) = credential.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        export_recovery_keyfile_from_master(
            master,
            &mount_password,
            KeyfileParams::default(),
            &credential,
            true,
        )
        .map_err(|error| error.to_string())?;
        write_protected_secret(
            &secret_path(&entry.id).map_err(|error| error.to_string())?,
            &mount_password,
        )
        .map_err(|error| error.to_string())?;
        mount_password.zeroize();
        Ok(())
    }

    fn ensure_task(&mut self, index: usize) -> Result<(), String> {
        if self.entries[index].task_registered {
            return Ok(());
        }
        let id = self.entries[index].id.clone();
        elevated_host_command("register-entry", &id)?;
        self.entries[index].task_registered = true;
        save_entry(&self.entries[index]).map_err(|error| error.to_string())?;
        Ok(())
    }

    fn mount_entry(&mut self, index: usize) {
        if let Err(error) = self.ensure_task(index) {
            self.set_status(StatusKind::Error, error);
            return;
        }
        let entry = self.entries[index].clone();
        let secret = secret_path(&entry.id).ok();
        let usable_persistent_secret = entry.auto_unlock
            && secret.as_ref().is_some_and(|path| path.is_file());
        if !usable_persistent_secret {
            let Some(master) = self.current_master_for(&entry) else {
                self.key_path = entry.key_path.display().to_string();
                self.master = None;
                self.passphrase.zeroize();
                self.set_status(
                    StatusKind::Info,
                    tr(
                        self.japanese,
                        "このボリュームのビジュアルキーを一度解除してから、もう一度マウントしてください。",
                        "Unlock this volume's visual key once, then press Mount again.",
                    ),
                );
                return;
            };
            if let Err(error) = self.prepare_credential(&entry, master.as_ref()) {
                self.set_status(StatusKind::Error, error);
                return;
            }
        }
        match run_task(&entry.id) {
            Ok(()) => self.set_status(
                StatusKind::Success,
                tr(
                    self.japanese,
                    "暗号ドライブのマウントを開始しました。初回だけWindowsでNTFS/exFATへフォーマットしてください。",
                    "Encrypted drive mount started. On first use, format the new partition as NTFS/exFAT once.",
                ),
            ),
            Err(error) => self.set_status(StatusKind::Error, error),
        }
    }

    fn unmount_entry(&mut self, index: usize) {
        let entry = self.entries[index].clone();
        match stop_path(&entry.id) {
            Ok(path) => {
                if let Some(parent) = path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                match fs::write(path, b"stop\n") {
                    Ok(()) => self.set_status(
                        StatusKind::Info,
                        tr(self.japanese, "安全なアンマウントを要求しました。", "Clean unmount requested."),
                    ),
                    Err(error) => self.set_status(StatusKind::Error, error.to_string()),
                }
            }
            Err(error) => self.set_status(StatusKind::Error, error.to_string()),
        }
    }

    fn register_entry(&mut self, index: usize) {
        let id = self.entries[index].id.clone();
        match elevated_host_command("register-entry", &id) {
            Ok(()) => {
                self.entries[index].task_registered = true;
                let _ = save_entry(&self.entries[index]);
                self.set_status(StatusKind::Success, tr(self.japanese, "Windowsマウントタスクを登録しました。", "Windows mount task registered."));
            }
            Err(error) => self.set_status(StatusKind::Error, error),
        }
    }

    fn remove_entry(&mut self, index: usize) {
        let entry = self.entries[index].clone();
        if entry_is_mounted(&entry) {
            self.unmount_entry(index);
            self.set_status(StatusKind::Info, tr(self.japanese, "先にアンマウントしています。数秒後に削除を再実行してください。", "Unmounting first. Remove the entry again in a few seconds."));
            return;
        }
        if entry.task_registered {
            let _ = elevated_host_command("unregister-entry", &entry.id);
        }
        let _ = fs::remove_file(credential_path(&entry.id).unwrap_or_default());
        match remove_entry_files(&entry.id) {
            Ok(()) => {
                self.refresh_entries();
                self.sync_startup();
                self.set_status(StatusKind::Success, tr(self.japanese, "登録を削除しました。暗号ボリューム本体は削除していません。", "Registration removed. The encrypted volume file itself was not deleted."));
            }
            Err(error) => self.set_status(StatusKind::Error, error.to_string()),
        }
    }

    fn apply_entry_policy(&mut self, index: usize) {
        if !self.entries[index].auto_mount {
            self.entries[index].auto_unlock = false;
            if let Ok(path) = secret_path(&self.entries[index].id) {
                let _ = fs::remove_file(path);
            }
        } else if self.entries[index].auto_unlock {
            let entry = self.entries[index].clone();
            let Some(master) = self.current_master_for(&entry) else {
                self.entries[index].auto_unlock = false;
                self.key_path = entry.key_path.display().to_string();
                self.master = None;
                self.set_status(StatusKind::Info, tr(self.japanese, "完全自動マウントを有効にするには、このボリュームのビジュアルキーを一度解除してください。", "Unlock this volume's visual key once before enabling full automatic mount."));
                let _ = save_entry(&self.entries[index]);
                self.sync_startup();
                return;
            };
            if let Err(error) = self.prepare_credential(&entry, master.as_ref()) {
                self.entries[index].auto_unlock = false;
                self.set_status(StatusKind::Error, error);
            }
        } else if let Ok(path) = secret_path(&self.entries[index].id) {
            let _ = fs::remove_file(path);
        }
        if let Err(error) = save_entry(&self.entries[index]) {
            self.set_status(StatusKind::Error, error.to_string());
        }
        self.sync_startup();
    }

    fn mount_startup_entries_for_current_key(&mut self) {
        let key = PathBuf::from(self.key_path.trim());
        let targets = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.auto_mount && !entry.auto_unlock && entry.key_path == key)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        for index in targets {
            self.mount_entry(index);
        }
        self.startup_index = self.startup_index.saturating_add(1);
        if let Some(next) = self.startup_keys.get(self.startup_index).cloned() {
            self.master = None;
            self.key_path = next.display().to_string();
            self.key_fingerprint = key_source_info(&next).ok().map(|info| info.card_id);
            self.passphrase.zeroize();
            self.set_status(StatusKind::Info, tr(self.japanese, "次のビジュアルキーを解除してください。", "Unlock the next visual key."));
        } else {
            self.startup_mode = false;
            self.set_status(StatusKind::Success, tr(self.japanese, "Windows自動マウントの開始処理が完了しました。", "Windows auto-mount startup processing is complete."));
        }
    }

    fn create_volume(&mut self) {
        if !cfg!(windows) {
            self.set_status(StatusKind::Error, "Encrypted drive mounting is currently Windows-only.");
            return;
        }
        let Some(master) = self.master.as_ref().map(Arc::clone) else {
            self.set_status(StatusKind::Error, tr(self.japanese, "先にビジュアルキーを解除してください。", "Unlock a visual key first."));
            return;
        };
        let key_path = PathBuf::from(self.key_path.trim());
        if !key_path.is_file() {
            self.set_status(StatusKind::Error, tr(self.japanese, "ビジュアルキーが見つかりません。", "Visual key file not found."));
            return;
        }
        let Some(output) = FileDialog::new()
            .add_filter("OrIsyVra encrypted volume", &["orisyvra-volume"])
            .set_file_name("vault.orisyvra-volume")
            .save_file()
        else {
            return;
        };
        let capacity = match self.create_size_gib.checked_mul(1024 * 1024 * 1024) {
            Some(value) if value > 0 => value,
            _ => {
                self.set_status(StatusKind::Error, "Invalid capacity.");
                return;
            }
        };
        let options = VolumeOptions {
            logical_capacity: capacity,
            block_size: INTERNAL_BLOCK_SIZE,
        };
        let mut volume = match Volume::create(&output, master.as_ref(), options) {
            Ok(volume) => volume,
            Err(error) => {
                self.set_status(StatusKind::Error, error.to_string());
                return;
            }
        };
        if let Err(error) = initialize_windows_mbr(&mut volume) {
            drop(volume);
            let _ = fs::remove_file(&output);
            self.set_status(StatusKind::Error, error);
            return;
        }
        let info = volume.info();
        if let Err(error) = volume.mark_clean() {
            self.set_status(StatusKind::Error, error.to_string());
            return;
        }
        drop(volume);

        let id = volume_id_hex(&info.volume_id)[..24].to_owned();
        let letter = self
            .create_letter
            .chars()
            .find(|value| value.is_ascii_alphabetic())
            .map(|value| value.to_ascii_uppercase());
        let entry = MountEntry {
            id,
            volume_path: output.clone(),
            key_path,
            preferred_letter: letter,
            read_only: self.create_read_only,
            auto_mount: self.create_auto_mount,
            auto_unlock: self.create_auto_mount && self.create_auto_unlock,
            task_registered: false,
        };
        if let Err(error) = save_entry(&entry) {
            self.set_status(StatusKind::Error, error.to_string());
            return;
        }
        self.refresh_entries();
        let Some(index) = self.entries.iter().position(|item| item.id == entry.id) else {
            self.set_status(StatusKind::Error, "Created volume registration could not be reloaded.");
            return;
        };
        if let Err(error) = self.ensure_task(index) {
            self.set_status(StatusKind::Error, format!("Volume created, but Windows mount setup failed: {error}"));
            return;
        }
        if self.entries[index].auto_unlock {
            if let Err(error) = self.prepare_credential(&self.entries[index], master.as_ref()) {
                self.set_status(StatusKind::Error, error);
                return;
            }
        }
        self.sync_startup();
        self.mount_entry(index);
        self.set_status(StatusKind::Success, format!("{} {}", tr(self.japanese, "暗号ボリュームを作成し、Windowsへの接続を開始しました:", "Encrypted volume created and Windows attachment started:"), output.display()));
    }

    fn key_panel(&mut self, ui: &mut egui::Ui) {
        let jp = self.japanese;
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.strong(tr(jp, "ビジュアルキー", "Visual key"));
            if self.key_path.is_empty() {
                ui.label(tr(jp, "暗号ドライブの作成・マウントに使うPNGキーを選択します。", "Choose the PNG key used for encrypted volumes."));
            } else {
                ui.label(egui::RichText::new(&self.key_path).monospace());
                if let Some(fingerprint) = &self.key_fingerprint {
                    ui.label(format!("{}: {}", tr(jp, "指紋", "Fingerprint"), fingerprint));
                }
            }
            ui.horizontal(|ui| {
                if ui.button(tr(jp, "キーを選ぶ", "Choose key")).clicked() {
                    self.choose_key();
                }
                if self.master.is_some() && ui.button(tr(jp, "ロック", "Lock")).clicked() {
                    self.master = None;
                    self.passphrase.zeroize();
                }
            });
            if self.master.is_none() && !self.key_path.is_empty() {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.passphrase)
                            .password(!self.show_passphrase)
                            .hint_text(tr(jp, "パスフレーズ", "Passphrase")),
                    );
                    ui.checkbox(&mut self.show_passphrase, tr(jp, "表示", "Show"));
                    if ui
                        .add_enabled(!self.passphrase.is_empty(), egui::Button::new(tr(jp, "解除", "Unlock")))
                        .clicked()
                    {
                        self.unlock_key();
                    }
                });
            } else if self.master.is_some() {
                ui.label(
                    egui::RichText::new(tr(jp, "● 解除済み — このセッション中は再入力不要", "● Unlocked — no re-entry for this session"))
                        .color(egui::Color32::from_rgb(160, 125, 230)),
                );
            }
        });
    }

    fn create_panel(&mut self, ui: &mut egui::Ui) {
        let jp = self.japanese;
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.strong(tr(jp, "新しい暗号ドライブ", "New encrypted drive"));
            ui.label(tr(jp, "容量は論理容量です。実ファイルは書き込んだ分だけ増えるスパース方式です。", "Capacity is logical; the sparse backing file grows only as data is written."));
            ui.horizontal(|ui| {
                ui.label(tr(jp, "容量 (GiB)", "Capacity (GiB)"));
                ui.add(egui::DragValue::new(&mut self.create_size_gib).range(1..=16_384).speed(1));
                ui.separator();
                ui.label(tr(jp, "希望ドライブ文字", "Preferred drive letter"));
                ui.add(egui::TextEdit::singleline(&mut self.create_letter).desired_width(36.0).char_limit(1));
            });
            ui.horizontal_wrapped(|ui| {
                ui.checkbox(&mut self.create_read_only, tr(jp, "読み取り専用", "Read-only"));
                ui.checkbox(&mut self.create_auto_mount, tr(jp, "Windowsサインイン時に自動マウント", "Auto-mount at Windows sign-in"));
                ui.add_enabled_ui(self.create_auto_mount, |ui| {
                    ui.checkbox(&mut self.create_auto_unlock, tr(jp, "完全自動（Windows保護資格情報を使用）", "Fully automatic (Windows-protected credential)"));
                });
            });
            ui.label(egui::RichText::new(tr(jp, "完全自動を選ばない場合、Windowsサインイン後にビジュアルキーを1回解除すると登録済みドライブをまとめてマウントします。", "Without full automatic mode, unlock the visual key once after sign-in and all configured drives using it are mounted.")).weak());
            if ui
                .add_enabled(self.master.is_some(), egui::Button::new(tr(jp, "暗号ドライブを作成してマウント", "Create and mount encrypted drive")))
                .clicked()
            {
                self.create_volume();
            }
        });
    }

    fn entries_panel(&mut self, ui: &mut egui::Ui) {
        let jp = self.japanese;
        ui.heading(tr(jp, "登録済み暗号ドライブ", "Registered encrypted drives"));
        if self.entries.is_empty() {
            ui.label(tr(jp, "まだ登録されていません。", "No encrypted drives are registered yet."));
            return;
        }
        for index in 0..self.entries.len() {
            let mut action = EntryAction::None;
            let mounted = entry_is_mounted(&self.entries[index]);
            let mut policy_changed = false;
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_width(ui.available_width());
                let entry = &mut self.entries[index];
                ui.horizontal(|ui| {
                    ui.strong(
                        entry
                            .volume_path
                            .file_name()
                            .map(|value| value.to_string_lossy().into_owned())
                            .unwrap_or_else(|| entry.id.clone()),
                    );
                    let state = if mounted {
                        tr(jp, "● マウント中", "● Mounted")
                    } else {
                        tr(jp, "○ 未マウント", "○ Unmounted")
                    };
                    ui.label(
                        egui::RichText::new(state).color(if mounted {
                            egui::Color32::from_rgb(160, 125, 230)
                        } else {
                            egui::Color32::GRAY
                        }),
                    );
                    if let Some(letter) = entry.preferred_letter {
                        ui.label(format!("{}: {letter}:\\", tr(jp, "希望", "Preferred")));
                    }
                });
                ui.label(egui::RichText::new(entry.volume_path.display().to_string()).monospace().weak());
                ui.horizontal_wrapped(|ui| {
                    policy_changed |= ui.checkbox(&mut entry.read_only, tr(jp, "読み取り専用", "Read-only")).changed();
                    policy_changed |= ui.checkbox(&mut entry.auto_mount, tr(jp, "サインイン時に自動マウント", "Auto-mount at sign-in")).changed();
                    if !entry.auto_mount {
                        entry.auto_unlock = false;
                    }
                    policy_changed |= ui
                        .add_enabled(entry.auto_mount, egui::Checkbox::new(&mut entry.auto_unlock, tr(jp, "完全自動", "Fully automatic")))
                        .changed();
                });
                ui.horizontal_wrapped(|ui| {
                    if !mounted && ui.button(tr(jp, "マウント", "Mount")).clicked() {
                        action = EntryAction::Mount(index);
                    }
                    if mounted && ui.button(tr(jp, "アンマウント", "Unmount")).clicked() {
                        action = EntryAction::Unmount(index);
                    }
                    if !entry.task_registered && ui.button(tr(jp, "Windows連携を設定", "Configure Windows integration")).clicked() {
                        action = EntryAction::Register(index);
                    }
                    if ui.button(tr(jp, "保存場所を開く", "Open location")).clicked() {
                        action = EntryAction::OpenFolder(index);
                    }
                    if ui.button(tr(jp, "登録を削除", "Remove registration")).clicked() {
                        action = EntryAction::Remove(index);
                    }
                });
            });
            if policy_changed {
                self.apply_entry_policy(index);
            }
            match action {
                EntryAction::None => {}
                EntryAction::Mount(index) => self.mount_entry(index),
                EntryAction::Unmount(index) => self.unmount_entry(index),
                EntryAction::Register(index) => self.register_entry(index),
                EntryAction::Remove(index) => self.remove_entry(index),
                EntryAction::OpenFolder(index) => {
                    if let Some(parent) = self.entries[index].volume_path.parent() {
                        let _ = Command::new("explorer.exe").arg(parent).spawn();
                    }
                }
            }
            ui.add_space(8.0);
        }
    }

    fn status_panel(&self, ui: &mut egui::Ui) {
        if let Some(status) = &self.status {
            let fill = match status.kind {
                StatusKind::Info => egui::Color32::from_rgb(28, 30, 58),
                StatusKind::Success => egui::Color32::from_rgb(43, 31, 70),
                StatusKind::Error => egui::Color32::from_rgb(72, 27, 43),
            };
            egui::Frame::group(ui.style()).fill(fill).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(&status.message);
            });
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("OrIsyVra Encrypted Volumes");
                ui.label(egui::RichText::new(&self.runtime_status).weak());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button(if self.japanese { "EN" } else { "日本語" }).clicked() {
                        self.japanese = !self.japanese;
                    }
                    if ui.button(tr(self.japanese, "WinSpd再確認", "Recheck WinSpd")).clicked() {
                        self.runtime_status = probe_runtime();
                    }
                });
            });
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                if !cfg!(windows) {
                    ui.heading("Windows required");
                    ui.label("Encrypted-volume drive mounting is currently available on 64-bit Windows only.");
                    return;
                }
                self.key_panel(ui);
                ui.add_space(12.0);
                self.create_panel(ui);
                ui.add_space(16.0);
                self.entries_panel(ui);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button(tr(self.japanese, "ディスクの管理を開く", "Open Disk Management")).clicked() {
                        let _ = Command::new("mmc.exe").arg("diskmgmt.msc").spawn();
                    }
                    ui.label(egui::RichText::new(tr(self.japanese, "初回だけ新しいパーティションをNTFSまたはexFATへフォーマットしてください。以後は通常のドライブとして使えます。", "On first use only, format the new partition as NTFS or exFAT. Afterwards it behaves like a normal drive.")).weak());
                });
                ui.add_space(8.0);
                self.status_panel(ui);
            });
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 820.0])
            .with_min_inner_size([800.0, 620.0]),
        ..Default::default()
    };
    eframe::run_native(
        "OrIsyVra Encrypted Volumes",
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}
