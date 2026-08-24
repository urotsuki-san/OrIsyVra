use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use zeroize::Zeroizing;

use orisyvra::{
    create_keycard, create_keyfile, decrypt_file, encrypt_file, export_keycard,
    export_recovery_keycard, import_keycard, inspect_file, unlock_key_source, EncryptOptions,
    KeyfileParams, Mode,
};

#[derive(Parser, Debug)]
#[command(name = "orisyvra", version, about = "OrIsyVra file encryption")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create a protected visual-key PNG. A legacy .orisyvra-key output is also accepted.
    Keygen {
        #[arg(short, long, default_value = "orisyvra-key.png")]
        output: PathBuf,
        /// Also export a second PNG/PDF copy of the protected key.
        #[arg(long)]
        card: Option<PathBuf>,
        #[arg(long)]
        force: bool,
        #[arg(long, default_value_t = 64 * 1024)]
        memory_kib: u32,
        #[arg(long, default_value_t = 3)]
        iterations: u32,
        #[arg(long, default_value_t = 1)]
        parallelism: u32,
    },
    /// Encrypt a file.
    Encrypt {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(short, long)]
        key: PathBuf,
        #[arg(long, value_enum, default_value_t = ModeArgument::Guarded)]
        mode: ModeArgument,
        #[arg(long)]
        acknowledge_experimental_native: bool,
        #[arg(long, default_value_t = 1024 * 1024)]
        chunk_size: usize,
        #[arg(long)]
        force: bool,
    },
    /// Decrypt and authenticate a file. Encryption mode is read from the file header.
    Decrypt {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(short, long)]
        key: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Display public container metadata.
    Inspect { input: PathBuf },
    /// Export, recover, or import visual-key material.
    Keycard {
        #[command(subcommand)]
        command: KeycardCommand,
    },
}

#[derive(Subcommand, Debug)]
enum KeycardCommand {
    /// Export a visual-key source as another PNG or printable PDF.
    Export {
        #[arg(short, long)]
        key: PathBuf,
        #[arg(short, long, default_value = "orisyvra-key-backup.png")]
        output: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Create a recovery visual key with a separate passphrase.
    Recovery {
        #[arg(short, long)]
        key: PathBuf,
        #[arg(short, long, default_value = "orisyvra-recovery-key.png")]
        output: PathBuf,
        #[arg(long)]
        force: bool,
        #[arg(long, default_value_t = 64 * 1024)]
        memory_kib: u32,
        #[arg(long, default_value_t = 3)]
        iterations: u32,
        #[arg(long, default_value_t = 1)]
        parallelism: u32,
    },
    /// Restore a legacy protected key capsule from a PNG visual key.
    Import {
        input: PathBuf,
        #[arg(short, long, default_value = "restored.orisyvra-key")]
        output: PathBuf,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ModeArgument {
    Guarded,
    Native,
}

impl From<ModeArgument> for Mode {
    fn from(value: ModeArgument) -> Self {
        match value {
            ModeArgument::Guarded => Mode::Guarded,
            ModeArgument::Native => Mode::NativeResearch,
        }
    }
}

fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(
        rpassword::prompt_password(prompt).context("failed to read passphrase")?,
    ))
}

fn prompt_new_password() -> Result<Zeroizing<String>> {
    let password = prompt_password("New passphrase: ")?;
    let confirmation = prompt_password("Confirm passphrase: ")?;
    if password.as_bytes() != confirmation.as_bytes() {
        bail!("passphrases do not match");
    }
    Ok(password)
}

fn is_png(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("png"))
}

fn encrypted_output(input: &Path) -> PathBuf {
    let mut name = input.as_os_str().to_os_string();
    name.push(".orisyvra");
    PathBuf::from(name)
}

fn decrypted_output(input: &Path) -> PathBuf {
    let file_name = input
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("decrypted");
    if let Some(stripped) = file_name.strip_suffix(".orisyvra") {
        input
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(if stripped.is_empty() {
                OsString::from("decrypted")
            } else {
                OsString::from(stripped)
            })
    } else {
        let mut name = input.as_os_str().to_os_string();
        name.push(".decrypted");
        PathBuf::from(name)
    }
}

fn print_file_id(file_id: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in file_id {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen {
            output,
            card,
            force,
            memory_kib,
            iterations,
            parallelism,
        } => {
            let password = prompt_new_password()?;
            let params = KeyfileParams {
                memory_kib,
                iterations,
                parallelism,
            };
            if is_png(&output) {
                let info = create_keycard(&output, password.as_bytes(), params, force)
                    .with_context(|| format!("failed to create {}", output.display()))?;
                println!("Visual key: {} ({})", output.display(), info.card_id);
            } else {
                create_keyfile(&output, password.as_bytes(), params, force)
                    .with_context(|| format!("failed to create {}", output.display()))?;
                println!("Legacy key capsule: {}", output.display());
            }
            if let Some(card) = card {
                let info = export_keycard(&output, &card, force)
                    .with_context(|| format!("failed to create {}", card.display()))?;
                println!("Backup: {} ({})", card.display(), info.card_id);
            }
        }
        Command::Encrypt {
            input,
            output,
            key,
            mode,
            acknowledge_experimental_native,
            chunk_size,
            force,
        } => {
            let mode: Mode = mode.into();
            if mode == Mode::NativeResearch && !acknowledge_experimental_native {
                bail!("native mode requires --acknowledge-experimental-native");
            }
            let output = output.unwrap_or_else(|| encrypted_output(&input));
            let password = prompt_password("Visual-key passphrase: ")?;
            let master = unlock_key_source(&key, password.as_bytes())
                .with_context(|| format!("failed to unlock {}", key.display()))?;
            encrypt_file(
                &input,
                &output,
                &master,
                EncryptOptions {
                    mode,
                    chunk_size,
                    overwrite: force,
                },
            )
            .with_context(|| format!("failed to encrypt {}", input.display()))?;
            println!("Encrypted: {} [{}]", output.display(), mode.display_name());
        }
        Command::Decrypt {
            input,
            output,
            key,
            force,
        } => {
            let output = output.unwrap_or_else(|| decrypted_output(&input));
            let password = prompt_password("Visual-key passphrase: ")?;
            let master = unlock_key_source(&key, password.as_bytes())
                .with_context(|| format!("failed to unlock {}", key.display()))?;
            let info = decrypt_file(&input, &output, &master, force)
                .with_context(|| format!("failed to decrypt {}", input.display()))?;
            println!(
                "Decrypted: {} [{}]",
                output.display(),
                info.mode.display_name()
            );
        }
        Command::Inspect { input } => {
            let info = inspect_file(&input)
                .with_context(|| format!("failed to inspect {}", input.display()))?;
            println!("Version    : {}", info.version);
            println!("Mode       : {}", info.mode.display_name());
            println!("Chunk size : {}", info.chunk_size);
            println!("File ID    : {}", print_file_id(&info.file_id));
        }
        Command::Keycard { command } => match command {
            KeycardCommand::Export { key, output, force } => {
                let info = export_keycard(&key, &output, force)
                    .with_context(|| format!("failed to create {}", output.display()))?;
                println!("Created: {} ({})", output.display(), info.card_id);
            }
            KeycardCommand::Recovery {
                key,
                output,
                force,
                memory_kib,
                iterations,
                parallelism,
            } => {
                let current = prompt_password("Current visual-key passphrase: ")?;
                let recovery = prompt_new_password()?;
                let info = export_recovery_keycard(
                    &key,
                    current.as_bytes(),
                    recovery.as_bytes(),
                    KeyfileParams {
                        memory_kib,
                        iterations,
                        parallelism,
                    },
                    &output,
                    force,
                )
                .with_context(|| format!("failed to create {}", output.display()))?;
                println!("Created: {} ({})", output.display(), info.card_id);
            }
            KeycardCommand::Import {
                input,
                output,
                force,
            } => {
                let info = import_keycard(&input, &output, force)
                    .with_context(|| format!("failed to restore {}", output.display()))?;
                println!("Restored: {} ({})", output.display(), info.card_id);
            }
        },
    }
    Ok(())
}
