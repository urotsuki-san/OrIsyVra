use std::path::Path;

use crate::container::{self, EncryptOptions, FileInfo};
use crate::error::{Error, Result};
use crate::keyfile::MasterKey;

fn contextualize_io(
    operation: &'static str,
    input_path: &Path,
    output_path: &Path,
    error: Error,
) -> Error {
    match error {
        Error::Io(source) => Error::FileIo {
            operation,
            input: input_path.display().to_string(),
            output: output_path.display().to_string(),
            source,
        },
        other => other,
    }
}

pub fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    master_key: &MasterKey,
    options: EncryptOptions,
) -> Result<()> {
    container::encrypt_file(input_path, output_path, master_key, options)
        .map_err(|error| contextualize_io("encryption", input_path, output_path, error))
}

pub fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    master_key: &MasterKey,
    overwrite: bool,
) -> Result<FileInfo> {
    container::decrypt_file(input_path, output_path, master_key, overwrite)
        .map_err(|error| contextualize_io("decryption", input_path, output_path, error))
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::Path;

    use super::contextualize_io;
    use crate::error::Error;

    #[test]
    fn io_errors_include_input_and_output_paths() {
        let error = contextualize_io(
            "encryption",
            Path::new("missing-input.bin"),
            Path::new("output.bin.orisyvra"),
            Error::Io(io::Error::new(io::ErrorKind::NotFound, "missing")),
        );
        let message = error.to_string();
        assert!(message.contains("missing-input.bin"));
        assert!(message.contains("output.bin.orisyvra"));
        assert!(message.contains("missing"));
    }

    #[test]
    fn semantic_errors_are_not_wrapped() {
        let error = contextualize_io(
            "decryption",
            Path::new("input.orisyvra"),
            Path::new("output.bin"),
            Error::AuthenticationFailed,
        );
        assert!(matches!(error, Error::AuthenticationFailed));
    }
}
