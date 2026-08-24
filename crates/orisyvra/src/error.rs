use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("I/O error during {operation}; input: {input}; output: {output}: {source}")]
    FileIo {
        operation: &'static str,
        input: String,
        output: String,
        #[source]
        source: io::Error,
    },
    #[error("invalid OrIsyVra format: {0}")]
    InvalidFormat(&'static str),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("authentication failed: wrong passphrase/key or modified data")]
    AuthenticationFailed,
    #[error("cryptographic operation failed: {0}")]
    Crypto(&'static str),
    #[error("image operation failed: {0}")]
    Image(String),
    #[error("key card could not be decoded")]
    KeyCardDecode,
    #[error("output already exists: {0}")]
    OutputExists(String),
    #[error("configured resource limit exceeded: {0}")]
    LimitExceeded(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;
