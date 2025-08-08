//! Cryptographic operations for file encryption and decryption.
//!
//! This module contains the core logic for encrypting and decrypting files,
//! as used by the CLI interface. It defines the encryption and decryption
//! routines, and is responsible for handling cryptographic workflows,
//! such as file processing, key usage, and optional exfiltration.

use std::path::{Path, PathBuf};

use crate::error::CryptoError;

/// Encrypted files extension.
pub const EXTENSION: &'static str = "zombie";

/// Encrypts a file using AES-GCM and ECIES for key encapsulation.
/// Returns the encrypted file (`.zombie`) path or a CryptoError.
pub fn encrypt(path: &Path) -> Result<PathBuf, CryptoError> {
    // TODO
    println!("Will encrypt: {:?}", path);
    Ok(path.to_path_buf())
}

/// Decrypts a `.zombie` file.
/// Requires the corresponding private key to the master public key.
pub fn decrypt(path: &Path, key: &Path) -> Result<PathBuf, CryptoError> {
    // TODO
    println!("Will decrypt: {:?} with key {:?}", path, key);
    Ok(path.to_path_buf())
}
