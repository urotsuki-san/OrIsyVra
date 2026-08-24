#!/usr/bin/env sh
set -eu

if ! command -v cargo >/dev/null 2>&1; then
  echo "Rust/Cargo was not found. Install Rust from https://rustup.rs/ and run this script again."
  exit 1
fi

cargo install --path crates/orisyvra --force
cargo install --path crates/orisyvra-gui --force
echo "Installed: orisyvra, orisyvra-gui"
