//! File uploading functionality for Cordyceps.
//!
//! This module provides the core logic for uploading files to a remote server,
//! encapsulated in the asynchronous `upload_file` function. It handles reading
//! the file from the local filesystem, sanitizing its name for compatibility,
//! constructing the multipart form, and sending the HTTP POST request.
//!
//! The `reqwest` crate is used to manage HTTP communication, including
//! multipart form uploads. For asynchronous file I/O, the module relies on
//! `tokio::fs`, ensuring non-blocking performance in a Tokio runtime.
//!
//! Errors encountered during file reading, request creation, or network
//! communication are unified under the central `AppError` type. This provides
//! consistent and streamlined error handling throughout the application.
//!
//! This abstraction simplifies integration of file upload capabilities and
//! reduces boilerplate, while promoting reliable and maintainable network I/O.

use log::info;
use reqwest::{Client, multipart};
use std::{io, path::Path};
use tokio::fs;

use crate::error::AppError;

/// Uploads a single file to the server.
///
/// # Arguments
/// - `client`: An HTTP client instance.
/// - `base_url`: The server's base address (e.g., `http://127.0.0.1:2673`).
/// - `local_path`: The full path to the local file to upload.
///
/// # Returns
/// Returns the HTTP status code on success or an `AppError` on failure.
pub async fn upload_file(
    client: &Client,
    base_url: &str,
    local_path: &Path,
) -> Result<u16, AppError> {
    let file_name = local_path
        .file_name()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("File name not found for path: {:?}", local_path),
            )
        })?
        .to_string_lossy();

    let url = format!("{}/upload", base_url.trim_end_matches('/'));

    // ASCII-only filename for maximum compatibility
    let sanitized_file_name = file_name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .collect::<String>();

    let final_file_name = if sanitized_file_name.is_empty() {
        "upload".to_string()
    } else {
        sanitized_file_name
    };

    info!("Uploading {:?} -> {}", local_path, url);

    // Read the entire file into memory. For large files, a streaming
    // solution would be preferable.
    let file_content = fs::read(local_path).await?;

    let file_part = multipart::Part::bytes(file_content)
        .file_name(final_file_name)
        .mime_str("application/octet-stream")?;
    let form = multipart::Form::new().part("files", file_part);

    let response = client.post(&url).multipart(form).send().await?;

    let status = response.status();
    response.error_for_status()?;

    Ok(status.as_u16())
}
