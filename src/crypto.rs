//! Cryptographic operations for file encryption and decryption.
//!
//! This module contains the core logic for encrypting and decrypting files,
//! as used by the CLI interface. It defines the encryption and decryption
//! routines, and is responsible for handling cryptographic workflows,
//! such as file processing, key usage, and optional exfiltration.

use log::info;
use std::error::Error;
use std::path::PathBuf;

pub fn encrypt(
    path: PathBuf,
    no_delete: bool,
    server: String,
    target_folder: Option<String>,
) -> Result<(), Box<dyn Error>> {
    info!(
        "Encryption started: Path: {}, Keep files? {}, Server: {}, Folder: {}",
        path.display(),
        no_delete,
        server,
        target_folder.unwrap_or("/".to_string())
    );

    if !path.exists() {
        return Err(format!("Path '{}' does not exist", path.display()).into());
    }

    // magic
    info!("Encryption finished successfully");
    Ok(())
}

pub fn decrypt(path: PathBuf, key: PathBuf) -> Result<(), Box<dyn Error>> {
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
