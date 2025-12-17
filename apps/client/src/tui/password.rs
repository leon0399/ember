//! Password prompt for encrypted identity.
//!
//! Uses rpassword for cross-platform hidden password input.

use std::io;

/// Prompt for a password without echoing characters.
///
/// Returns the password string (may be empty if user just pressed Enter).
pub fn prompt_for_password(prompt: &str) -> io::Result<String> {
    rpassword::prompt_password(prompt)
}
