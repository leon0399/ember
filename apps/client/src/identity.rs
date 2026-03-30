//! Identity management: loading, creating, and password-protected identities.
//!
//! Extracted from the TUI module so that both the interactive TUI and CLI
//! subcommands (import, export) can share identity loading logic.

use ember_identity::{
    is_encrypted, load_identity, save_identity, EncryptedIdentityError, Identity,
};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use zeroize::Zeroizing;

/// Load an existing identity or create a new one interactively.
///
/// Used by the TUI on startup. If the file doesn't exist, prompts the user
/// to create a new identity with optional password protection.
pub fn load_or_create(identity_path: &Path) -> Result<Identity, Box<dyn std::error::Error>> {
    if !identity_path.exists() {
        return create_new(identity_path);
    }
    load_existing(identity_path)
}

/// Load an existing identity file, prompting for password if encrypted.
///
/// Returns an error if the identity file doesn't exist or can't be read.
/// Used by CLI subcommands (import, etc.) that require an identity but
/// should not create one.
pub fn load_existing(identity_path: &Path) -> Result<Identity, Box<dyn std::error::Error>> {
    let data = fs::read(identity_path)?;

    if !is_encrypted(&data) {
        return load_identity(&data, None)
            .map_err(|e| format!("Failed to load identity: {e}").into());
    }

    // Encrypted - prompt for password
    println!();
    println!("========================================");
    println!("  Identity file is password-protected");
    println!("========================================");
    println!();
    io::stdout().flush()?;

    loop {
        let password = Zeroizing::new(prompt_for_password("Enter password: ")?);
        match load_identity(&data, Some(password.as_bytes())) {
            Ok(identity) => {
                println!();
                return Ok(identity);
            }
            Err(EncryptedIdentityError::DecryptionFailed) => {
                println!("Wrong password. Try again (or press Ctrl+C to exit).");
                println!();
            }
            Err(e) => {
                return Err(format!("Failed to load identity: {e}").into());
            }
        }
    }
}

/// Prompt for a password without echoing characters.
///
/// Returns the password string (may be empty if user just pressed Enter).
fn prompt_for_password(prompt: &str) -> io::Result<String> {
    rpassword::prompt_password(prompt)
}

/// Create a new identity interactively with optional password protection.
fn create_new(identity_path: &Path) -> Result<Identity, Box<dyn std::error::Error>> {
    println!();
    println!("========================================");
    println!("       Creating new identity");
    println!("========================================");
    println!();
    println!("Would you like to protect your identity with a password?");
    println!("(Type password and press Enter, or just press Enter to skip)");
    println!();
    io::stdout().flush()?;

    let password = Zeroizing::new(prompt_for_password("Password (optional): ")?);

    let key = if password.is_empty() {
        println!();
        println!("No password set. Identity will be stored in plaintext.");
        None
    } else {
        confirm_password(&password)?;
        println!();
        println!("Password set. Identity will be encrypted.");
        Some(password)
    };

    let identity = Identity::generate();
    let data = save_identity(&identity, key.as_ref().map(|p| p.as_bytes()))
        .map_err(|e| format!("Failed to save identity: {e}"))?;
    fs::write(identity_path, data)?;

    println!();
    Ok(identity)
}

/// Prompt for password confirmation, retrying until passwords match.
fn confirm_password(password: &str) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        println!();
        let confirm = Zeroizing::new(prompt_for_password("Confirm password: ")?);
        if *confirm == *password {
            return Ok(());
        }
        println!();
        println!("Passwords do not match. Please try again.");
    }
}
