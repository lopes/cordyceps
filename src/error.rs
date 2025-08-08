//! Custom error handling for Cordyceps.
//!
//! This module defines the central `AppError` enum, which unifies various
//! error types from different parts of the program, such as I/O,
//! cryptography, and CLI parsing. It provides a consistent way to
//! represent and handle all potential errors.
//!
//! The `thiserror` crate is used to simplify the implementation of the
//! `std::error::Error` and `std::fmt::Display` traits for the `AppError` enum.
//! By using declarative macros, `thiserror` automatically generates the
//! necessary boilerplate, allowing one to focus on defining the error variants
//! and their associated messages. This approach reduces code duplication and
//! makes error handling more maintainable and less prone to errors.

use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {}

#[derive(Error, Debug)]
pub enum AppError {
    // Implements `From<CryptoError>` and displays the inner message.
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    // Handles `io::Error`. Message is customized to provide more context.
    // The `#[from]` makes the `?` operator work seamlessly.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    // The `#[from]` attribute here handles the `clap::Error` conversion.
    #[error("CLI error: {0}")]
    Cli(#[from] clap::Error),
}
