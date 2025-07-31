//! CLI parsing and mode dispatch logic.
//!
//! This module handles all command-line interface logic, including argument
//! parsing and delegation to encryption or decryption routines.

use clap::{Parser, ValueEnum};
use log::info;
use std::error::Error;
use std::fmt;
use std::path::PathBuf;

// Custom error type for a more explicit and descriptive error handling
#[derive(Debug)]
pub struct CliError(String);

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CLI Error: {}", self.0)
    }
}

// CliError can be used as a generic error type via Box<dyn Error> in run()
impl Error for CliError {}

#[derive(ValueEnum, Debug, Clone)]
enum Mode {
    Encrypt,
    Decrypt,
}

/// Command-line arguments
#[derive(Parser, Debug)]
#[command(
    author = "Joe Lopes <lopes.id>",
    version = "0.2.0",
    about = "Rust ransomware, for learning not looting",
    long_about = "Cordyceps is an educational ransomware designed for academic and research purposes."
)]
enum Cli {
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
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

/// Parses CLI arguments and executes the appropriate application mode
/// (encrypt or decrypt).
///
/// This function serves as the entry point for command-line interaction.
/// It determines the mode selected by the user and delegates to the
/// corresponding logic.
pub fn run() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    // Call the appropriate function based on the mode
    // The ? operator is used to propagate errors from encrypt or decrypt
    // up to the caller--main()
    match args {
        Cli::Encrypt(args) => {
            info!("Starting the encryption module...");
            encrypt(args.path, args.no_delete, args.server, args.target_folder)
        }
        Cli::Decrypt(args) => {
            info!("Starting the decryption module...");
            decrypt(args.path, args.key)
        }
    }
}

fn encrypt(
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
    // additional tests, like path exists? server is reachable?
    // magic
    info!("Encryption finished successfully");
    Ok(())
}

fn decrypt(path: PathBuf, key: PathBuf) -> Result<(), Box<dyn Error>> {
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
