//! Custom error handling for Cordyceps.
//!
//! This module defines the central `AppError` enum, which unifies various
//! error types from different parts of the program, such as I/O,
//! cryptography, and CLI parsing. It provides a consistent way to
//! represent and handle all potential errors.
//!
//! The `thiserror` crate is used to simplify the implementation of the
//! `std::error::Error` and `std::fmt::Display` traits for the `AppError` enum.
//! By using declarative macros, `thiserror` automatically generates the
//! necessary boilerplate, allowing one to focus on defining the error variants
//! and their associated messages. This approach reduces code duplication and
//! makes error handling more maintainable and less prone to errors.

use std::io;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Failed to generate random bytes: {0}")]
    Random(#[from] rand_core::Error),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Authentication tag mismatch. Data may be corrupted or the key is incorrect.")]
    AuthenticationTag,

    #[error("Base64 decoding failed: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Invalid key length: expected 32 bytes.")]
    InvalidKeyLength,

    #[error("Key derivation function (KDF) error.")]
    KdfError,

    #[error("Invalid file format: {0}")]
    InvalidFileFormat(String),

    #[error("Key verification failed after generation.")]
    KeyVerification,
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Cryptographic operation failed: {0}")]
    Crypto(#[from] CryptoError),

    #[error("I/O operation failed: {0}")]
    Io(#[from] io::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("One or more files failed to process.")]
    PartialFailure,
}
