#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

mod mascot;

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eframe::egui;
use orisyvra::{
    create_keycard, decrypt_file, encrypt_file, export_keycard,
    export_recovery_keycard_from_master, key_source_info, unlock_key_source, EncryptOptions,
    Error as OrisyvraError, KeyfileParams, MasterKey, Mode,
};
use orisyvra_pin::{
    copy_pin_card, create_pin_card, create_pin_card_from_master, pin_card_state, pin_is_valid,
    unlock_pin_card, PinCardState,
};
use rfd::FileDialog;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Page {
    Home,
    Keys,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Encrypt,
    Decrypt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StatusKind {
    Info,
    Success,
    Error,
}

#[derive(Clone, Debug)]
struct Status {
    kind: StatusKind,
    message: String,
}

#[derive(Default)]
struct UnlockDialog {
    open: bool,
    secret: String,
    show_secret: bool,
}

#[derive(Default)]
struct CreateKeyDialog {
    open: bool,
    secret: String,
    confirmation: String,
    show_secret: bool,
}

#[derive(Default)]
struct RecoveryDialog {
    open: bool,
    passphrase: String,
    confirmation: String,
    show_password: bool,
}

struct TaskOutcome {
    message: String,
    selected_key: Option<PathBuf>,
    fingerprint: Option<String>,
    unlocked_key: Option<Arc<MasterKey>>,
    output: Option<PathBuf>,
}

enum TaskEvent {
    Progress {
        current: usize,
        total: usize,
        label: String,
    },
    Finished(Result<TaskOutcome, String>),
}

struct RunningTask {
    receiver: Receiver<TaskEvent>,
    current: usize,
    total: usize,
    label: String,
}

struct App {
    japanese: bool,
    page: Page,
    operation: Operation,
    mode: Mode,
    native_ack: bool,
    source: String,
    output_dir: String,
    key_source: String,
    key_fingerprint: Option<String>,
    unlocked_key: Option<Arc<MasterKey>>,
    status: Option<Status>,
    task: Option<RunningTask>,
    unlock: UnlockDialog,
    create_key: CreateKeyDialog,
    recovery: RecoveryDialog,
    last_output: Option<PathBuf>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            japanese: true,
            page: Page::Home,
            operation: Operation::Encrypt,
            mode: Mode::Guarded,
            native_ack: false,
            source: String::new(),
            output_dir: String::new(),
            key_source: String::new(),
            key_fingerprint: None,
            unlocked_key: None,
            status: None,
            task: None,
            unlock: UnlockDialog::default(),
            create_key: CreateKeyDialog::default(),
            recovery: RecoveryDialog::default(),
            last_output: None,
        }
    }
}

impl Drop for App {
    fn drop(&mut self) {
        self.unlock.secret.zeroize();
        self.create_key.secret.zeroize();
        self.create_key.confirmation.zeroize();
        self.recovery.passphrase.zeroize();
        self.recovery.confirmation.zeroize();
        self.unlocked_key = None;
    }
}

fn tr<'a>(jp: bool, ja: &'a str, en: &'a str) -> &'a str {
    if jp { ja } else { en }
}

fn configure_style(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = egui::Color32::from_rgb(12, 17, 27);
    visuals.window_fill = egui::Color32::from_rgb(17, 24, 39);
    visuals.extreme_bg_color = egui::Color32::from_rgb(8, 13, 22);
    visuals.faint_bg_color = egui::Color32::from_rgb(18, 27, 42);
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
        let name = "orisyvra-japanese".to_owned();
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

fn app_icon() -> egui::IconData {
    const SIZE: u32 = 64;
    let mut rgba = vec![0_u8; (SIZE * SIZE * 4) as usize];
    for y in 0..SIZE {
        for x in 0..SIZE {
            let fx = x as f32 / SIZE as f32;
            let fy = y as f32 / SIZE as f32;
            let index = ((y * SIZE + x) * 4) as usize;
            let shield = fy > 0.10
                && fy < 0.90
                && fx > 0.16 + (fy - 0.50).abs() * 0.18
                && fx < 0.84 - (fy - 0.50).abs() * 0.18;
            if !shield { continue; }
            rgba[index..index + 4].copy_from_slice(&[17, 24, 39, 255]);
            let border = fx < 0.21 + (fy - 0.50).abs() * 0.18
                || fx > 0.79 - (fy - 0.50).abs() * 0.18
                || fy < 0.15
                || fy > 0.84;
            if border {
                rgba[index..index + 4].copy_from_slice(&[52, 211, 153, 255]);
            }
        }
    }
    egui::IconData { rgba, width: SIZE, height: SIZE }
}

fn settings_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        return std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .map(|base| base.join("OrIsyVra").join("settings.txt"));
    }
    #[cfg(target_os = "macos")]
    {
        return std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|base| base.join("Library/Application Support/OrIsyVra/settings.txt"));
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(base) = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from) {
            return Some(base.join("orisyvra/settings.txt"));
        }
        return std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|base| base.join(".config/orisyvra/settings.txt"));
    }
    #[allow(unreachable_code)]
    None
}

fn load_last_key() -> Option<PathBuf> {
    let value = fs::read_to_string(settings_path()?).ok()?;
    let key = PathBuf::from(value.trim());
    key.is_file().then_some(key)
}

fn remember_key(path: Option<&Path>) {
    let Some(settings) = settings_path() else { return; };
    if let Some(parent) = settings.parent() { let _ = fs::create_dir_all(parent); }
    match path {
        Some(path) => { let _ = fs::write(settings, path.display().to_string()); }
        None => { let _ = fs::remove_file(settings); }
    }
}

fn is_orisyvra_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|v| v.to_str())
        .is_some_and(|v| v.to_ascii_lowercase().ends_with(".orisyvra"))
}

fn is_legacy_keyfile(path: &Path) -> bool {
    path.file_name()
        .and_then(|v| v.to_str())
        .is_some_and(|v| v.to_ascii_lowercase().ends_with(".orisyvra-key"))
}

fn is_visual_key(path: &Path) -> bool {
    path.is_file() && key_source_info(path).is_ok()
}

fn grouped_fingerprint(value: &str) -> String {
    value
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("-")
}

fn pin_state(path: &Path) -> PinCardState {
    pin_card_state(path).unwrap_or(PinCardState::NotPinCard)
}

fn friendly_error(jp: bool, error: OrisyvraError) -> String {
    match error {
        OrisyvraError::AuthenticationFailed => tr(
            jp,
            "入力が違うか、鍵または暗号化ファイルが破損しています。",
            "The credential is incorrect or the key/encrypted file is damaged.",
        )
        .to_owned(),
        OrisyvraError::KeyCardDecode => tr(
            jp,
            "この画像からOrIsyVraのビジュアルキーを読み取れません。",
            "This image does not contain a readable OrIsyVra visual key.",
        )
        .to_owned(),
        other => other.to_string(),
    }
}

fn auto_file_name(path: &Path, operation: Operation) -> OsString {
    let name = path.file_name().and_then(|v| v.to_str()).unwrap_or("output");
    match operation {
        Operation::Encrypt => OsString::from(format!("{name}.orisyvra")),
        Operation::Decrypt => {
            let stripped = name.strip_suffix(".orisyvra").unwrap_or(name);
            OsString::from(if stripped.is_empty() { "decrypted" } else { stripped })
        }
    }
}

fn auto_folder_name(path: &Path, operation: Operation) -> OsString {
    let name = path.file_name().and_then(|v| v.to_str()).unwrap_or("folder");
    match operation {
        Operation::Encrypt => OsString::from(format!("{name}_encrypted")),
        Operation::Decrypt => OsString::from(format!("{name}_decrypted")),
    }
}

fn unique_path(path: PathBuf, directory: bool) -> PathBuf {
    if !path.exists() { return path; }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path.file_name().and_then(|v| v.to_str()).unwrap_or("output");
    for index in 2..10_000 {
        let candidate = if directory {
            parent.join(format!("{name} ({index})"))
        } else {
            let stem = path.file_stem().and_then(|v| v.to_str()).unwrap_or(name);
            match path.extension().and_then(|v| v.to_str()) {
                Some(ext) if !ext.is_empty() => parent.join(format!("{stem} ({index}).{ext}")),
                _ => parent.join(format!("{stem} ({index})")),
            }
        };
        if !candidate.exists() { return candidate; }
    }
    path
}

fn collect_regular_files(root: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() { continue; }
        let path = entry.path();
        if file_type.is_dir() {
            collect_regular_files(&path, files)?;
        } else if file_type.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn batch_temp_path(final_path: &Path) -> PathBuf {
    let parent = final_path.parent().unwrap_or_else(|| Path::new("."));
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    parent.join(format!(".orisyvra-partial-{}-{stamp}", std::process::id()))
}

fn process_directory(
    input: &Path,
    output: &Path,
    key: &MasterKey,
    operation: Operation,
    mode: Mode,
    selected_key: &Path,
    jp: bool,
    sender: &Sender<TaskEvent>,
) -> Result<(usize, usize), String> {
    let mut files = Vec::new();
    collect_regular_files(input, &mut files).map_err(|e| e.to_string())?;
    files.sort();
    let canonical_key = selected_key.canonicalize().ok();
    let mut selected = Vec::new();
    let mut skipped = 0_usize;
    for path in files {
        let same_key = canonical_key
            .as_ref()
            .and_then(|key| path.canonicalize().ok().map(|p| p == *key))
            .unwrap_or(false);
        match operation {
            Operation::Encrypt => {
                if same_key || is_orisyvra_file(&path) || is_legacy_keyfile(&path) || is_visual_key(&path) {
                    skipped += 1;
                } else {
                    selected.push(path);
                }
            }
            Operation::Decrypt => {
                if is_orisyvra_file(&path) { selected.push(path); } else { skipped += 1; }
            }
        }
    }
    if selected.is_empty() {
        return Err(tr(jp, "処理できるファイルがありません。", "No processable files were found.").to_owned());
    }
    let temporary = batch_temp_path(output);
    fs::create_dir_all(&temporary).map_err(|e| e.to_string())?;
    let result = (|| {
        for (index, source) in selected.iter().enumerate() {
            let relative = source.strip_prefix(input).map_err(|e| e.to_string())?;
            let destination = temporary
                .join(relative.parent().unwrap_or_else(|| Path::new("")))
                .join(auto_file_name(source, operation));
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let _ = sender.send(TaskEvent::Progress {
                current: index,
                total: selected.len(),
                label: relative.display().to_string(),
            });
            match operation {
                Operation::Encrypt => encrypt_file(
                    source,
                    &destination,
                    key,
                    EncryptOptions { mode, ..EncryptOptions::default() },
                )
                .map_err(|e| friendly_error(jp, e))?,
                Operation::Decrypt => {
                    decrypt_file(source, &destination, key, false).map_err(|e| friendly_error(jp, e))?;
                }
            }
        }
        Ok::<(), String>(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&temporary);
        return Err(error);
    }
    if output.exists() {
        let _ = fs::remove_dir_all(&temporary);
        return Err(tr(jp, "出力先が既に存在します。", "The output already exists.").to_owned());
    }
    fs::rename(&temporary, output).map_err(|error| {
        let _ = fs::remove_dir_all(&temporary);
        error.to_string()
    })?;
    let _ = sender.send(TaskEvent::Progress {
        current: selected.len(),
        total: selected.len(),
        label: tr(jp, "完了", "Done").to_owned(),
    });
    Ok((selected.len(), skipped))
}

fn open_in_file_manager(path: &Path) {
    let target = if path.is_dir() { path } else { path.parent().unwrap_or(path) };
    #[cfg(target_os = "windows")]
    { let _ = Command::new("explorer.exe").arg(target).spawn(); }
    #[cfg(target_os = "macos")]
    { let _ = Command::new("open").arg(target).spawn(); }
    #[cfg(target_os = "linux")]
    { let _ = Command::new("xdg-open").arg(target).spawn(); }
}

fn launch_volume_gui() -> Result<(), String> {
    if !cfg!(windows) {
        return Err("Encrypted drives are currently Windows-only.".to_owned());
    }
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    let directory = executable.parent().ok_or_else(|| "application directory is unavailable".to_owned())?;
    for candidate in [
        directory.join("orisyvra-volume-gui.exe"),
        directory.join("bin").join("orisyvra-volume-gui.exe"),
    ] {
        if candidate.is_file() {
            Command::new(candidate).spawn().map_err(|e| e.to_string())?;
            return Ok(());
        }
    }
    Err("OrIsyVra Encrypted Volumes is not installed next to this application.".to_owned())
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_style(&cc.egui_ctx);
        let mut app = Self::default();
        if let Some(key) = load_last_key() {
            if let Ok(info) = key_source_info(&key) {
                app.key_source = key.display().to_string();
                app.key_fingerprint = Some(info.card_id);
                app.unlock.open = true;
            }
        }
        if !install_japanese_font(&cc.egui_ctx) {
            app.japanese = false;
            app.status = Some(Status {
                kind: StatusKind::Info,
                message: "Japanese system font was not found. English UI is active.".to_owned(),
            });
        }
        app
    }

    fn set_status(&mut self, kind: StatusKind, message: impl Into<String>) {
        self.status = Some(Status { kind, message: message.into() });
    }

    fn start_task<F>(&mut self, ctx: &egui::Context, label: impl Into<String>, task: F)
    where
        F: FnOnce(Sender<TaskEvent>) -> Result<TaskOutcome, String> + Send + 'static,
    {
        if self.task.is_some() { return; }
        let (sender, receiver) = mpsc::channel();
        let worker_sender = sender.clone();
        let repaint = ctx.clone();
        self.task = Some(RunningTask { receiver, current: 0, total: 0, label: label.into() });
        thread::spawn(move || {
            let result = task(worker_sender.clone());
            let _ = worker_sender.send(TaskEvent::Finished(result));
            repaint.request_repaint();
        });
    }

    fn poll_task(&mut self) {
        let mut finished = None;
        if let Some(task) = &mut self.task {
            while let Ok(event) = task.receiver.try_recv() {
                match event {
                    TaskEvent::Progress { current, total, label } => {
                        task.current = current;
                        task.total = total;
                        task.label = label;
                    }
                    TaskEvent::Finished(result) => finished = Some(result),
                }
            }
        }
        let Some(result) = finished else { return; };
        self.task = None;
        match result {
            Ok(outcome) => {
                if let Some(key) = outcome.selected_key {
                    self.key_source = key.display().to_string();
                    remember_key(Some(&key));
                }
                if outcome.fingerprint.is_some() { self.key_fingerprint = outcome.fingerprint; }
                if outcome.unlocked_key.is_some() { self.unlocked_key = outcome.unlocked_key; }
                self.last_output = outcome.output;
                self.set_status(StatusKind::Success, outcome.message);
            }
            Err(error) => self.set_status(StatusKind::Error, error),
        }
    }

    fn select_key(&mut self, path: PathBuf, open_unlock: bool) {
        match key_source_info(&path) {
            Ok(info) => {
                self.key_source = path.display().to_string();
                self.key_fingerprint = Some(info.card_id);
                self.unlocked_key = None;
                remember_key(Some(&path));
                self.status = None;
                if open_unlock {
                    self.unlock.secret.zeroize();
                    self.unlock.open = true;
                }
            }
            Err(error) => self.set_status(StatusKind::Error, friendly_error(self.japanese, error)),
        }
    }

    fn set_source(&mut self, path: PathBuf) {
        if is_visual_key(&path) {
            self.select_key(path, true);
            return;
        }
        if path.is_file() && is_orisyvra_file(&path) { self.operation = Operation::Decrypt; }
        self.source = path.display().to_string();
        self.output_dir.clear();
        self.last_output = None;
        self.status = None;
    }

    fn choose_source_file(&mut self) {
        if let Some(path) = FileDialog::new().pick_file() { self.set_source(path); }
    }

    fn choose_source_folder(&mut self) {
        if let Some(path) = FileDialog::new().pick_folder() { self.set_source(path); }
    }

    fn choose_output_folder(&mut self) {
        if let Some(path) = FileDialog::new().pick_folder() {
            self.output_dir = path.display().to_string();
            self.status = None;
        }
    }

    fn choose_key(&mut self) {
        if let Some(path) = FileDialog::new()
            .add_filter("OrIsyVra visual key", &["png", "orisyvra-key"])
            .pick_file()
        {
            self.select_key(path, true);
        }
    }

    fn lock_key(&mut self) {
        self.unlocked_key = None;
        self.unlock.secret.zeroize();
        self.set_status(StatusKind::Info, tr(self.japanese, "キーをロックしました。", "The key is locked."));
    }

    fn forget_key(&mut self) {
        self.unlocked_key = None;
        self.key_source.clear();
        self.key_fingerprint = None;
        self.unlock.secret.zeroize();
        remember_key(None);
    }

    fn computed_output(&self) -> Option<PathBuf> {
        if self.source.trim().is_empty() { return None; }
        let source = Path::new(self.source.trim());
        if !source.exists() { return None; }
        let base = if self.output_dir.trim().is_empty() {
            source.parent().unwrap_or_else(|| Path::new("."))
        } else {
            Path::new(self.output_dir.trim())
        };
        let path = if source.is_dir() {
            base.join(auto_folder_name(source, self.operation))
        } else {
            base.join(auto_file_name(source, self.operation))
        };
        Some(unique_path(path, source.is_dir()))
    }

    fn blocker(&self) -> Option<String> {
        let jp = self.japanese;
        if self.source.trim().is_empty() {
            return Some(tr(jp, "まずファイルかフォルダを選んでください。", "Choose a file or folder first.").to_owned());
        }
        let source = Path::new(self.source.trim());
        if !source.exists() {
            return Some(tr(jp, "選択した場所が見つかりません。", "The selected source does not exist.").to_owned());
        }
        if self.key_source.trim().is_empty() || !Path::new(self.key_source.trim()).is_file() {
            return Some(tr(jp, "ビジュアルキーを選ぶか、新しく作成してください。", "Choose or create a visual key.").to_owned());
        }
        if self.unlocked_key.is_none() {
            return Some(tr(jp, "ビジュアルキーを解除してください。", "Unlock the visual key.").to_owned());
        }
        if self.operation == Operation::Encrypt && self.mode == Mode::NativeResearch && !self.native_ack {
            return Some(tr(jp, "Native Research Modeは研究用途への同意が必要です。", "Acknowledge that Native Research Mode is experimental.").to_owned());
        }
        let Some(output) = self.computed_output() else {
            return Some(tr(jp, "出力先を決められません。", "The output path could not be determined.").to_owned());
        };
        if source.is_dir() && output.starts_with(source) {
            return Some(tr(jp, "保存先は入力フォルダの外を選んでください。", "Choose an output location outside the input folder.").to_owned());
        }
        None
    }

    fn execute(&mut self, ctx: &egui::Context) {
        if let Some(reason) = self.blocker() {
            self.set_status(StatusKind::Error, reason);
            return;
        }
        let source = PathBuf::from(self.source.trim());
        let output = self.computed_output().expect("validated output");
        let selected_key = PathBuf::from(self.key_source.trim());
        let key = Arc::clone(self.unlocked_key.as_ref().expect("validated key"));
        let operation = self.operation;
        let mode = self.mode;
        let jp = self.japanese;
        self.start_task(
            ctx,
            match operation {
                Operation::Encrypt => tr(jp, "暗号化しています…", "Encrypting…"),
                Operation::Decrypt => tr(jp, "復号しています…", "Decrypting…"),
            },
            move |sender| {
                if source.is_dir() {
                    let (processed, skipped) = process_directory(
                        &source, &output, key.as_ref(), operation, mode, &selected_key, jp, &sender,
                    )?;
                    Ok(TaskOutcome {
                        message: format!("{} {} ({}: {processed}, {}: {skipped})", tr(jp, "完了:", "Done:"), output.display(), tr(jp, "処理", "processed"), tr(jp, "スキップ", "skipped")),
                        selected_key: None,
                        fingerprint: None,
                        unlocked_key: None,
                        output: Some(output),
                    })
                } else {
                    let _ = sender.send(TaskEvent::Progress { current: 0, total: 1, label: source.display().to_string() });
                    match operation {
                        Operation::Encrypt => encrypt_file(
                            &source,
                            &output,
                            key.as_ref(),
                            EncryptOptions { mode, ..EncryptOptions::default() },
                        )
                        .map_err(|e| friendly_error(jp, e))?,
                        Operation::Decrypt => {
                            decrypt_file(&source, &output, key.as_ref(), false).map_err(|e| friendly_error(jp, e))?;
                        }
                    }
                    let _ = sender.send(TaskEvent::Progress { current: 1, total: 1, label: tr(jp, "完了", "Done").to_owned() });
                    Ok(TaskOutcome {
                        message: format!("{} {}", tr(jp, "完了:", "Done:"), output.display()),
                        selected_key: None,
                        fingerprint: None,
                        unlocked_key: None,
                        output: Some(output),
                    })
                }
            },
        );
    }

    fn export_png_copy(&mut self, ctx: &egui::Context) {
        let source = PathBuf::from(self.key_source.trim());
        if !source.is_file() { return; }
        let Some(output) = FileDialog::new()
            .add_filter("PNG", &["png"])
            .set_file_name("orisyvra-key-backup.png")
            .save_file()
        else { return; };
        let jp = self.japanese;
        let state = pin_state(&source);
        self.start_task(ctx, tr(jp, "バックアップを作成しています…", "Creating backup…"), move |_sender| {
            match state {
                PinCardState::NotPinCard => { export_keycard(&source, &output, false).map_err(|e| friendly_error(jp, e))?; }
                _ => { copy_pin_card(&source, &output, false)?; }
            }
            Ok(TaskOutcome {
                message: format!("{} {}", tr(jp, "PNGバックアップを作成しました:", "PNG backup created:"), output.display()),
                selected_key: None,
                fingerprint: None,
                unlocked_key: None,
                output: Some(output),
            })
        });
    }

    fn export_legacy_pdf(&mut self, ctx: &egui::Context) {
        let source = PathBuf::from(self.key_source.trim());
        if !source.is_file() || pin_state(&source) != PinCardState::NotPinCard { return; }
        let Some(output) = FileDialog::new()
            .add_filter("PDF", &["pdf"])
            .set_file_name("orisyvra-key-optical-recovery.pdf")
            .save_file()
        else { return; };
        let jp = self.japanese;
        self.start_task(ctx, tr(jp, "PDFを作成しています…", "Creating PDF…"), move |_sender| {
            export_keycard(&source, &output, false).map_err(|e| friendly_error(jp, e))?;
            Ok(TaskOutcome {
                message: format!("{} {}", tr(jp, "光学バックアップを作成しました:", "Optical backup created:"), output.display()),
                selected_key: None,
                fingerprint: None,
                unlocked_key: None,
                output: Some(output),
            })
        });
    }

    fn source_card(&mut self, ui: &mut egui::Ui) {
        let jp = self.japanese;
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.strong(tr(jp, "1  ファイル / フォルダ", "1  File / Folder"));
            if self.source.trim().is_empty() {
                if ui.add_sized(
                    [ui.available_width(), 84.0],
                    egui::Button::new(tr(jp, "ここにドロップ\nまたはクリックしてファイルを選択", "Drop here\nor click to choose a file")),
                ).clicked() {
                    self.choose_source_file();
                }
                ui.horizontal(|ui| {
                    if ui.button(tr(jp, "ファイルを選ぶ", "Choose file")).clicked() { self.choose_source_file(); }
                    if ui.button(tr(jp, "フォルダを選ぶ", "Choose folder")).clicked() { self.choose_source_folder(); }
                });
            } else {
                ui.label(egui::RichText::new(&self.source).monospace());
                ui.horizontal(|ui| {
                    if ui.button(tr(jp, "ファイルに変更", "Choose file")).clicked() { self.choose_source_file(); }
                    if ui.button(tr(jp, "フォルダに変更", "Choose folder")).clicked() { self.choose_source_folder(); }
                    if ui.button(tr(jp, "クリア", "Clear")).clicked() { self.source.clear(); self.output_dir.clear(); }
                });
            }
        });
    }

    fn mode_card(&mut self, ui: &mut egui::Ui) {
        if self.operation != Operation::Encrypt { return; }
        let jp = self.japanese;
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.strong(tr(jp, "2  暗号方式", "2  Encryption mode"));
            ui.horizontal(|ui| {
                if ui.selectable_label(self.mode == Mode::Guarded, tr(jp, "Guarded（推奨）", "Guarded (recommended)")).clicked() {
                    self.mode = Mode::Guarded;
                    self.native_ack = false;
                }
                if ui.selectable_label(self.mode == Mode::NativeResearch, "Native Research").clicked() {
                    self.mode = Mode::NativeResearch;
                }
            });
            if self.mode == Mode::NativeResearch {
                ui.label(egui::RichText::new(tr(jp, "実験用です。具体的な安全強度は未主張です。", "Experimental. No concrete security strength is claimed.")).color(egui::Color32::from_rgb(255, 190, 90)));
                ui.checkbox(&mut self.native_ack, tr(jp, "研究用途の実験モードであることを理解しました", "I understand this is an experimental research mode"));
            } else {
                ui.label(tr(jp, "通常利用向け。独自構成にXChaCha20-Poly1305を追加します。", "For normal use. Adds an independent XChaCha20-Poly1305 guard layer."));
            }
        });
    }

    fn output_card(&mut self, ui: &mut egui::Ui) {
        let jp = self.japanese;
        let number = if self.operation == Operation::Encrypt { "3" } else { "2" };
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.strong(format!("{}  {}", number, tr(jp, "保存先", "Output")));
            if self.output_dir.trim().is_empty() {
                ui.label(tr(jp, "自動: 入力と同じ場所へ上書きしない名前で保存します。", "Automatic: saves next to the input without overwriting."));
            } else {
                ui.label(format!("{}: {}", tr(jp, "保存先", "Output"), self.output_dir));
            }
            if let Some(output) = self.computed_output() {
                ui.label(egui::RichText::new(output.display().to_string()).monospace().weak());
            }
            ui.horizontal(|ui| {
                if ui.button(tr(jp, "保存先を変更", "Change output")).clicked() { self.choose_output_folder(); }
                if !self.output_dir.is_empty() && ui.button(tr(jp, "自動に戻す", "Use automatic")).clicked() { self.output_dir.clear(); }
            });
        });
    }

    fn key_card(&mut self, ui: &mut egui::Ui) {
        let jp = self.japanese;
        let number = if self.operation == Operation::Encrypt { "4" } else { "3" };
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.strong(format!("{}  {}", number, tr(jp, "ビジュアルキー", "Visual key")));
            if self.key_source.trim().is_empty() || !Path::new(self.key_source.trim()).is_file() {
                ui.label(tr(jp, "Windowsでは4桁PINのキーカードを作るのが標準です。", "On Windows, the standard key card uses a four-digit PIN."));
                ui.horizontal(|ui| {
                    if ui.button(tr(jp, "新しいキーカード", "New key card")).clicked() { self.create_key.open = true; }
                    if ui.button(tr(jp, "既存キーを選ぶ", "Choose existing key")).clicked() { self.choose_key(); }
                });
                return;
            }
            let path = Path::new(self.key_source.trim());
            let state = pin_state(path);
            ui.horizontal(|ui| {
                let name = path.file_name().map(|v| v.to_string_lossy()).unwrap_or_default();
                ui.label(egui::RichText::new(name).strong());
                if self.unlocked_key.is_some() {
                    ui.label(egui::RichText::new(tr(jp, "● 解除済み", "● Unlocked")).color(egui::Color32::from_rgb(80, 220, 150)));
                } else {
                    ui.label(egui::RichText::new(tr(jp, "● ロック中", "● Locked")).color(egui::Color32::from_rgb(245, 180, 80)));
                }
            });
            if let Some(fingerprint) = &self.key_fingerprint {
                ui.label(format!("{}: {}", tr(jp, "指紋", "Fingerprint"), grouped_fingerprint(fingerprint)));
            }
            match state {
                PinCardState::Ready => { ui.label(tr(jp, "4桁PINカード・このWindowsで利用可能", "4-digit PIN card · ready on this Windows account")); }
                PinCardState::BindingMissing => {
                    ui.label(egui::RichText::new(tr(jp, "このPINカードの端末登録がありません。コピーだけでは解除できません。", "This PIN card has no device binding here. A copied PNG alone cannot unlock it.")).color(egui::Color32::from_rgb(245, 180, 80)));
                }
                PinCardState::NotPinCard => { ui.label(tr(jp, "従来パスフレーズキー", "Legacy passphrase key")); }
            }
            ui.horizontal_wrapped(|ui| {
                if ui.button(tr(jp, "変更", "Change")).clicked() { self.choose_key(); }
                if self.unlocked_key.is_none() && state != PinCardState::BindingMissing && ui.button(tr(jp, "解除", "Unlock")).clicked() { self.unlock.open = true; }
                if self.unlocked_key.is_some() && ui.button(tr(jp, "ロック", "Lock")).clicked() { self.lock_key(); }
                if ui.button(tr(jp, "キー管理", "Key management")).clicked() { self.page = Page::Keys; }
            });
        });
    }

    fn home_page(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let jp = self.japanese;
        ui.heading(tr(jp, "ファイルを保護する", "Protect files"));
        ui.label(tr(jp, "PINカードなら覚えるのは4桁だけ。鍵の本体はPNGとWindows側の端末秘密で保護されます。", "With a PIN card, you remember only four digits. The key is protected by the PNG plus a Windows-bound device secret."));
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.selectable_label(self.operation == Operation::Encrypt, tr(jp, "暗号化", "Encrypt")).clicked() { self.operation = Operation::Encrypt; }
            if ui.selectable_label(self.operation == Operation::Decrypt, tr(jp, "復号", "Decrypt")).clicked() { self.operation = Operation::Decrypt; }
        });
        ui.add_space(10.0);
        self.source_card(ui);
        ui.add_space(10.0);
        self.mode_card(ui);
        if self.operation == Operation::Encrypt { ui.add_space(10.0); }
        self.output_card(ui);
        ui.add_space(10.0);
        self.key_card(ui);
        ui.add_space(14.0);
        let blocker = self.blocker();
        let action_text = match self.operation {
            Operation::Encrypt => tr(jp, "暗号化を開始", "Start encryption"),
            Operation::Decrypt => tr(jp, "復号を開始", "Start decryption"),
        };
        if ui.add_enabled(blocker.is_none() && self.task.is_none(), egui::Button::new(action_text).min_size([ui.available_width(), 50.0].into())).clicked() {
            self.execute(ctx);
        }
        if let Some(reason) = blocker { ui.label(egui::RichText::new(reason).weak()); }
    }

    fn keys_page(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let jp = self.japanese;
        ui.heading(tr(jp, "キーカード管理", "Key card management"));
        ui.label(tr(jp, "通常のPNGカードにはQRを使いません。右側のKey Sigilは目視確認用の視覚指紋です。", "Normal PNG cards do not use a QR code. The Key Sigil is a visual fingerprint for human verification."));
        ui.add_space(12.0);
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            if self.key_source.trim().is_empty() {
                ui.strong(tr(jp, "キーが選択されていません", "No key selected"));
            } else {
                ui.strong(tr(jp, "現在のキー", "Current key"));
                ui.label(egui::RichText::new(&self.key_source).monospace());
                if let Some(fingerprint) = &self.key_fingerprint {
                    ui.label(format!("{}: {}", tr(jp, "指紋", "Fingerprint"), grouped_fingerprint(fingerprint)));
                }
            }
            ui.horizontal_wrapped(|ui| {
                if ui.button(tr(jp, "新しいキーカード", "New key card")).clicked() { self.create_key.open = true; }
                if ui.button(tr(jp, "既存キーを選ぶ", "Choose existing key")).clicked() { self.choose_key(); }
                if self.unlocked_key.is_some() && ui.button(tr(jp, "ロック", "Lock")).clicked() { self.lock_key(); }
                if !self.key_source.is_empty() && ui.button(tr(jp, "このキーを忘れる", "Forget this key")).clicked() { self.forget_key(); }
            });
        });
        if Path::new(self.key_source.trim()).is_file() {
            let state = pin_state(Path::new(self.key_source.trim()));
            ui.add_space(12.0);
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.strong(tr(jp, "バックアップ", "Backup"));
                ui.label(tr(jp, "日常運用はPNGコピーだけで十分です。PINカードのコピーは同じ端末登録を使います。", "For normal use, a PNG copy is enough. A copied PIN card uses the same device binding."));
                ui.horizontal_wrapped(|ui| {
                    if ui.button(tr(jp, "PNGコピーを作る", "Create PNG copy")).clicked() { self.export_png_copy(ctx); }
                    if state == PinCardState::NotPinCard && ui.button(tr(jp, "従来PDF（詳細）", "Legacy PDF (advanced)")).clicked() { self.export_legacy_pdf(ctx); }
                    if self.unlocked_key.is_some() && cfg!(windows) && ui.button(tr(jp, "同じ鍵で新しいPINカード", "New PIN card for same key")).clicked() { self.create_key.open = true; }
                    if self.unlocked_key.is_some() && ui.button(tr(jp, "回復用パスフレーズキー（詳細）", "Recovery passphrase key (advanced)")).clicked() { self.recovery.open = true; }
                });
            });
        }
        if cfg!(windows) {
            ui.add_space(12.0);
            if ui.button(tr(jp, "暗号ドライブを管理", "Manage encrypted drives")).clicked() {
                match launch_volume_gui() {
                    Ok(()) => {}
                    Err(error) => self.set_status(StatusKind::Error, error),
                }
            }
        }
    }

    fn show_unlock_dialog(&mut self, ctx: &egui::Context) {
        if !self.unlock.open { return; }
        let source = PathBuf::from(self.key_source.trim());
        if !source.is_file() { self.unlock.open = false; return; }
        let state = pin_state(&source);
        if state == PinCardState::BindingMissing {
            self.unlock.open = false;
            self.set_status(StatusKind::Error, tr(self.japanese, "このPINカードはこのWindowsに登録されていません。元の端末または回復用キーが必要です。", "This PIN card is not registered on this Windows account. Use the original device or a recovery key."));
            return;
        }
        let jp = self.japanese;
        let mut open = self.unlock.open;
        let is_pin = state == PinCardState::Ready;
        egui::Window::new(tr(jp, "キーカードを解除", "Unlock key card"))
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.set_min_width(430.0);
                ui.label(if is_pin {
                    tr(jp, "4桁PINを入力してください。PINだけではコピーされたカードを解除できません。", "Enter the four-digit PIN. The PIN alone cannot unlock a copied card on another device.")
                } else {
                    tr(jp, "従来キーのパスフレーズを入力してください。", "Enter the passphrase for this legacy key.")
                });
                let mut edit = egui::TextEdit::singleline(&mut self.unlock.secret)
                    .password(!self.unlock.show_secret)
                    .desired_width(f32::INFINITY);
                if is_pin { edit = edit.char_limit(4).hint_text("PIN"); }
                ui.add(edit);
                ui.checkbox(&mut self.unlock.show_secret, tr(jp, "表示", "Show"));
                let valid = if is_pin { pin_is_valid(&self.unlock.secret) } else { !self.unlock.secret.is_empty() };
                if ui.add_enabled(valid && self.task.is_none(), egui::Button::new(tr(jp, "解除", "Unlock"))).clicked() {
                    let credential = Zeroizing::new(std::mem::take(&mut self.unlock.secret));
                    self.unlock.open = false;
                    self.start_task(ctx, tr(jp, "キーを解除しています…", "Unlocking key…"), move |_sender| {
                        let master = if is_pin {
                            unlock_pin_card(&source, credential.as_str())?
                        } else {
                            unlock_key_source(&source, credential.as_bytes()).map_err(|e| e.to_string())?
                        };
                        let info = key_source_info(&source).map_err(|e| e.to_string())?;
                        Ok(TaskOutcome {
                            message: tr(jp, "キーカードを解除しました。", "Key card unlocked.").to_owned(),
                            selected_key: Some(source),
                            fingerprint: Some(info.card_id),
                            unlocked_key: Some(Arc::new(master)),
                            output: None,
                        })
                    });
                }
            });
        self.unlock.open = open && self.unlock.open;
        if !self.unlock.open { self.unlock.secret.zeroize(); }
    }

    fn show_create_key_dialog(&mut self, ctx: &egui::Context) {
        if !self.create_key.open { return; }
        let jp = self.japanese;
        let mut open = self.create_key.open;
        let use_pin = cfg!(windows);
        let same_master = self.unlocked_key.as_ref().map(Arc::clone);
        egui::Window::new(tr(jp, "新しいキーカード", "New key card"))
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.set_min_width(470.0);
                if use_pin {
                    ui.label(tr(jp, "4桁PINを決めてください。ランダムな端末秘密をWindows DPAPIで保護するため、PNGとPINだけを別PCへコピーしても解除できません。", "Choose a four-digit PIN. A random device secret is protected by Windows DPAPI, so copying only the PNG and PIN to another PC is insufficient."));
                    ui.label(tr(jp, "PIN", "PIN"));
                } else {
                    ui.label(tr(jp, "このOSでは端末バインドPINは未対応のため、従来パスフレーズキーを作成します。", "Device-bound PIN cards are currently Windows-only; a legacy passphrase key will be created here."));
                    ui.label(tr(jp, "パスフレーズ", "Passphrase"));
                }
                let mut first = egui::TextEdit::singleline(&mut self.create_key.secret).password(!self.create_key.show_secret).desired_width(f32::INFINITY);
                let mut second = egui::TextEdit::singleline(&mut self.create_key.confirmation).password(!self.create_key.show_secret).desired_width(f32::INFINITY);
                if use_pin { first = first.char_limit(4); second = second.char_limit(4); }
                ui.add(first);
                ui.label(tr(jp, "確認", "Confirm"));
                ui.add(second);
                ui.checkbox(&mut self.create_key.show_secret, tr(jp, "表示", "Show"));
                let valid_secret = if use_pin { pin_is_valid(&self.create_key.secret) } else { self.create_key.secret.as_bytes().len() >= 12 };
                let valid = valid_secret && self.create_key.secret == self.create_key.confirmation && self.task.is_none();
                if !valid_secret {
                    ui.label(egui::RichText::new(if use_pin { tr(jp, "数字4桁で入力してください。", "Enter exactly four digits.") } else { tr(jp, "12バイト以上で入力してください。", "Use at least 12 bytes.") }).weak());
                }
                if ui.add_enabled(valid, egui::Button::new(tr(jp, "保存して作成", "Save and create"))).clicked() {
                    let Some(output) = FileDialog::new().add_filter("OrIsyVra visual key", &["png"]).set_file_name("my-key.orisyvra-key.png").save_file() else { return; };
                    let secret = Zeroizing::new(std::mem::take(&mut self.create_key.secret));
                    self.create_key.confirmation.zeroize();
                    self.create_key.open = false;
                    let existing_master = same_master.clone();
                    self.start_task(ctx, tr(jp, "キーカードを作成しています…", "Creating key card…"), move |_sender| {
                        let info = if use_pin {
                            if let Some(master) = existing_master.as_ref() {
                                create_pin_card_from_master(master.as_ref(), &output, secret.as_str(), KeyfileParams::default(), false)?
                            } else {
                                create_pin_card(&output, secret.as_str(), KeyfileParams::default(), false)?
                            }
                        } else if let Some(master) = existing_master.as_ref() {
                            export_recovery_keycard_from_master(master.as_ref(), secret.as_bytes(), KeyfileParams::default(), &output, false).map_err(|e| e.to_string())?
                        } else {
                            create_keycard(&output, secret.as_bytes(), KeyfileParams::default(), false).map_err(|e| e.to_string())?
                        };
                        let master = if use_pin {
                            unlock_pin_card(&output, secret.as_str())?
                        } else {
                            unlock_key_source(&output, secret.as_bytes()).map_err(|e| e.to_string())?
                        };
                        Ok(TaskOutcome {
                            message: format!("{} {}", tr(jp, "キーカードを作成しました:", "Key card created:"), output.display()),
                            selected_key: Some(output),
                            fingerprint: Some(info.card_id),
                            unlocked_key: Some(Arc::new(master)),
                            output: None,
                        })
                    });
                }
            });
        self.create_key.open = open && self.create_key.open;
        if !self.create_key.open {
            self.create_key.secret.zeroize();
            self.create_key.confirmation.zeroize();
        }
    }

    fn show_recovery_dialog(&mut self, ctx: &egui::Context) {
        if !self.recovery.open { return; }
        let Some(master) = self.unlocked_key.as_ref().map(Arc::clone) else {
            self.recovery.open = false;
            return;
        };
        let jp = self.japanese;
        let mut open = self.recovery.open;
        egui::Window::new(tr(jp, "回復用パスフレーズキー", "Recovery passphrase key"))
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.set_min_width(470.0);
                ui.label(tr(jp, "これは上級者向けの端末非依存バックアップです。日常利用では不要です。", "This is an advanced, device-independent recovery option and is not required for normal use."));
                ui.label(tr(jp, "回復用パスフレーズ", "Recovery passphrase"));
                ui.add(egui::TextEdit::singleline(&mut self.recovery.passphrase).password(!self.recovery.show_password).desired_width(f32::INFINITY));
                ui.label(tr(jp, "確認", "Confirm"));
                ui.add(egui::TextEdit::singleline(&mut self.recovery.confirmation).password(!self.recovery.show_password).desired_width(f32::INFINITY));
                ui.checkbox(&mut self.recovery.show_password, tr(jp, "表示", "Show"));
                let valid = self.recovery.passphrase.as_bytes().len() >= 12 && self.recovery.passphrase == self.recovery.confirmation && self.task.is_none();
                if ui.add_enabled(valid, egui::Button::new(tr(jp, "回復用キーを保存", "Save recovery key"))).clicked() {
                    let Some(output) = FileDialog::new().add_filter("PNG", &["png"]).set_file_name("orisyvra-recovery-key.png").save_file() else { return; };
                    let recovery = Zeroizing::new(std::mem::take(&mut self.recovery.passphrase));
                    self.recovery.confirmation.zeroize();
                    self.recovery.open = false;
                    self.start_task(ctx, tr(jp, "回復用キーを作成しています…", "Creating recovery key…"), move |_sender| {
                        export_recovery_keycard_from_master(master.as_ref(), recovery.as_bytes(), KeyfileParams::default(), &output, false).map_err(|e| e.to_string())?;
                        Ok(TaskOutcome {
                            message: format!("{} {}", tr(jp, "回復用キーを作成しました:", "Recovery key created:"), output.display()),
                            selected_key: None,
                            fingerprint: None,
                            unlocked_key: None,
                            output: Some(output),
                        })
                    });
                }
            });
        self.recovery.open = open && self.recovery.open;
        if !self.recovery.open {
            self.recovery.passphrase.zeroize();
            self.recovery.confirmation.zeroize();
        }
    }

    fn task_ui(&self, ui: &mut egui::Ui) {
        if let Some(task) = &self.task {
            let fraction = if task.total == 0 { 0.0 } else { (task.current as f32 / task.total as f32).clamp(0.0, 1.0) };
            ui.add_space(10.0);
            ui.add(egui::ProgressBar::new(fraction).show_percentage().text(task.label.clone()));
        }
    }

    fn status_ui(&mut self, ui: &mut egui::Ui) {
        let Some(status) = &self.status else { return; };
        let fill = match status.kind {
            StatusKind::Info => egui::Color32::from_rgb(24, 36, 56),
            StatusKind::Success => egui::Color32::from_rgb(17, 54, 43),
            StatusKind::Error => egui::Color32::from_rgb(70, 28, 34),
        };
        ui.add_space(10.0);
        egui::Frame::group(ui.style()).fill(fill).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(&status.message);
            if status.kind == StatusKind::Success {
                if let Some(output) = self.last_output.clone() {
                    if ui.button(tr(self.japanese, "保存先を開く", "Open output folder")).clicked() {
                        open_in_file_manager(&output);
                    }
                }
            }
        });
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        let jp = self.japanese;
        ui.horizontal(|ui| {
            ui.heading("OrIsyVra");
            ui.selectable_value(&mut self.page, Page::Home, tr(jp, "ホーム", "Home"));
            ui.selectable_value(&mut self.page, Page::Keys, tr(jp, "キーカード", "Key cards"));
            if cfg!(windows) && ui.button(tr(jp, "暗号ドライブ", "Encrypted drives")).clicked() {
                if let Err(error) = launch_volume_gui() { self.set_status(StatusKind::Error, error); }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button(if jp { "EN" } else { "日本語" }).clicked() { self.japanese = !jp; }
                if self.unlocked_key.is_some() && ui.button(tr(jp, "ロック", "Lock")).clicked() { self.lock_key(); }
            });
        });
    }

    fn accept_drops(&mut self, ctx: &egui::Context) {
        let dropped = ctx.input(|input| input.raw.dropped_files.clone());
        if dropped.is_empty() { return; }
        for file in dropped {
            let Some(path) = file.path else { continue; };
            if is_visual_key(&path) {
                self.select_key(path, true);
            } else {
                self.set_source(path);
                self.page = Page::Home;
                break;
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_task();
        self.accept_drops(ctx);
        if self.task.is_some() { ctx.request_repaint_after(Duration::from_millis(100)); }
        egui::TopBottomPanel::top("top").show(ctx, |ui| self.top_bar(ui));
        egui::CentralPanel::default().show(ctx, |ui| {
            let mascot_alpha = match self.page {
                Page::Home => 30,
                Page::Keys => 18,
            };
            mascot::paint_background(ui, mascot_alpha);
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add_enabled_ui(self.task.is_none(), |ui| match self.page {
                    Page::Home => self.home_page(ui, ctx),
                    Page::Keys => self.keys_page(ui, ctx),
                });
                self.task_ui(ui);
                self.status_ui(ui);
            });
        });
        self.show_unlock_dialog(ctx);
        self.show_create_key_dialog(ctx);
        self.show_recovery_dialog(ctx);
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([960.0, 780.0])
            .with_min_inner_size([780.0, 620.0])
            .with_icon(Arc::new(app_icon())),
        ..Default::default()
    };
    eframe::run_native(
        "OrIsyVra",
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}
