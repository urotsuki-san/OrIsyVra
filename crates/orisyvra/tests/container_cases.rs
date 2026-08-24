use std::fs;

use orisyvra::{
    create_keyfile, decrypt_file, encrypt_file, unlock_keyfile, EncryptOptions, KeyfileParams, Mode,
};

fn params() -> KeyfileParams {
    KeyfileParams {
        memory_kib: 8 * 1024,
        iterations: 1,
        parallelism: 1,
    }
}

fn data(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| ((index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 17) as u8)
        .collect()
}

#[test]
fn guarded_round_trips_boundaries() {
    let directory = tempfile::tempdir().expect("temp directory");
    let key_path = directory.path().join("test.orisyvra-key");
    create_keyfile(&key_path, b"boundary test passphrase", params(), false).expect("create key");
    let key = unlock_keyfile(&key_path, b"boundary test passphrase").expect("unlock key");

    for size in [0, 1, 31, 32, 33, 4095, 4096, 4097, 65_535, 65_536, 65_537] {
        let input = directory.path().join(format!("input-{size}"));
        let encrypted = directory.path().join(format!("input-{size}.orisyvra"));
        let output = directory.path().join(format!("output-{size}"));
        let source = data(size);
        fs::write(&input, &source).expect("write input");
        encrypt_file(
            &input,
            &encrypted,
            &key,
            EncryptOptions {
                mode: Mode::Guarded,
                chunk_size: 4096,
                overwrite: false,
            },
        )
        .expect("encrypt");
        decrypt_file(&encrypted, &output, &key, false).expect("decrypt");
        assert_eq!(fs::read(output).expect("read output"), source);
    }
}

#[test]
fn truncation_and_trailing_data_fail_closed() {
    let directory = tempfile::tempdir().expect("temp directory");
    let key_path = directory.path().join("test.orisyvra-key");
    create_keyfile(&key_path, b"integrity test passphrase", params(), false).expect("create key");
    let key = unlock_keyfile(&key_path, b"integrity test passphrase").expect("unlock key");
    let input = directory.path().join("input");
    let encrypted = directory.path().join("input.orisyvra");
    fs::write(&input, data(90_000)).expect("write input");
    encrypt_file(&input, &encrypted, &key, EncryptOptions::default()).expect("encrypt");
    let original = fs::read(&encrypted).expect("read encrypted");

    let truncated = directory.path().join("truncated.orisyvra");
    fs::write(&truncated, &original[..original.len() - 1]).expect("write truncated");
    let output = directory.path().join("truncated.out");
    assert!(decrypt_file(&truncated, &output, &key, false).is_err());
    assert!(!output.exists());

    let trailing = directory.path().join("trailing.orisyvra");
    let mut modified = original;
    modified.extend_from_slice(b"trailing");
    fs::write(&trailing, modified).expect("write trailing");
    let output = directory.path().join("trailing.out");
    assert!(decrypt_file(&trailing, &output, &key, false).is_err());
    assert!(!output.exists());
}
