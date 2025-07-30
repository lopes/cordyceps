use clap::{Parser, ValueEnum};
use log::info;
use std::path::PathBuf;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, ValueEnum)]
enum Mode {
    Encrypt,
    Decrypt,
}

/// Command-line arguments
#[derive(Parser, Debug)]
#[command(
    author = "Joe Lopes <lopes.id>",
    version = "0.1.0",
    about = "Rust ransomware, for learning not looting",
    long_about = "Cordyceps is an educational ransomware designed for academic and research purposes."
)]
struct Args {
    /// Mode: encrypt or decrypt
    #[arg(short = 'm', long, default_value = "encrypt")]
    mode: Mode,

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

    /// Path to the server private key--decryption mode only
    #[arg(short = 'k', long, default_value = "server_ed25519_private.key")]
    key: PathBuf,
}

fn main() {
    env_logger::init();
    let args = Args::parse();

    match args.mode {
        Mode::Encrypt => {
            info!(
                "call ENCRYPTION module: path: {}, keep..? {}, server: {}, folder: {}",
                args.path.display(),
                args.no_delete,
                args.server,
                args.target_folder.unwrap_or("/".to_string()),
            );
        }
        Mode::Decrypt => info!(
            "call DECRYPTION module: path..: {} key...: {}",
            args.path.display(),
            args.key.display(),
        ),
    }
}
