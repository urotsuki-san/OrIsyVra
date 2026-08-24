#![no_main]

use std::fs;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use orisyvra::{
    create_keyfile, decrypt_file, encrypt_file, inspect_file, unlock_keyfile, EncryptOptions,
    KeyfileParams, MasterKey,
};

fn master_key() -> &'static MasterKey {
    static MASTER: OnceLock<MasterKey> = OnceLock::new();
    MASTER.get_or_init(|| {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("fuzz.orisyvra-key");
        let password = b"orisyvra fuzz passphrase";
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
        .expect("create fuzz key");
        unlock_keyfile(&path, password).expect("unlock fuzz key")
    })
}

fn valid_container() -> &'static [u8] {
    static CONTAINER: OnceLock<Vec<u8>> = OnceLock::new();
    CONTAINER
        .get_or_init(|| {
            let directory = tempfile::tempdir().expect("temp directory");
            let plaintext = directory.path().join("plain.bin");
            let encrypted = directory.path().join("plain.bin.orisyvra");
            fs::write(&plaintext, vec![0x5a; 8192]).expect("write seed plaintext");
            encrypt_file(
                &plaintext,
                &encrypted,
                master_key(),
                EncryptOptions {
                    chunk_size: 4096,
                    ..EncryptOptions::default()
                },
            )
            .expect("create seed container");
            fs::read(encrypted).expect("read seed container")
        })
        .as_slice()
}

fuzz_target!(|data: &[u8]| {
    let directory = tempfile::tempdir().expect("temp directory");
    let input = directory.path().join("input.orisyvra");
    let output = directory.path().join("output.bin");
    let candidate = if data.is_empty() {
        valid_container().to_vec()
    } else {
        data.to_vec()
    };
    fs::write(&input, candidate).expect("write fuzz input");
    let _ = inspect_file(&input);
    let result = decrypt_file(&input, &output, master_key(), false);
    if result.is_err() {
        assert!(!output.exists(), "failed decryption persisted plaintext output");
    }
});
