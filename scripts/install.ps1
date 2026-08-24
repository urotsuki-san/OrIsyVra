$ErrorActionPreference = "Stop"

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Error "Rust/Cargo was not found. Install Rust from https://rustup.rs/ and run this script again."
}

cargo install --path crates/orisyvra --force
cargo install --path crates/orisyvra-gui --force
Write-Host "Installed: orisyvra, orisyvra-gui"
