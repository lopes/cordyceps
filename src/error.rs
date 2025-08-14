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

use rand_core;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("File I/O error during crypto operation: {0}")]
    Io(#[from] io::Error),

    #[error("Failed to generate random bytes: {0}")]
    RandomGenError(#[from] rand_core::Error),

    #[error("Symmetric key encryption failed: {0}")]
    SymmetricEncryptError(String),

    #[error("Key derivation function (KDF) error.")]
    KdfError,

    #[error("Invalid private key length: expected 32 bytes.")]
    InvalidPrivateKey,

    #[error("Invalid zombie file format: {0}")]
    InvalidZombieFile(String),

    #[error("Symmetric key decryption failed: {0}")]
    SymmetricDecryptError(String),

    #[error(
        "Authentication tag mismatch during decryption. Data might be tampered or key is incorrect."
    )]
    AuthenticationTagMismatch,
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("CLI error: {0}")]
    Cli(#[from] clap::Error),
}
