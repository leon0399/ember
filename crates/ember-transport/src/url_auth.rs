//! URL credential parsing helper.
//!
//! Extracts HTTP Basic Auth credentials from URL userinfo and strips them
//! from the URL for security (prevents credentials from being logged or
//! sent in the URL path).
//!
//! Credentials are percent-decoded so they can be used directly with HTTP clients.
//!
//! Uses the well-established Servo `url` crate for WHATWG-compliant URL parsing.

use percent_encoding::percent_decode_str;
use url::Url;

/// Sanitize a URL for safe logging by removing any credentials.
///
/// Returns the URL with username and password stripped. If parsing fails,
/// returns a redacted placeholder to avoid exposing credentials.
///
/// # Example
///
/// ```
/// use ember_transport::url_auth::sanitize_url_for_logging;
///
/// assert_eq!(
///     sanitize_url_for_logging("http://user:pass@example.com:3000/api"),
///     "http://example.com:3000/api"
/// );
/// assert_eq!(
///     sanitize_url_for_logging("http://example.com:3000/api"),
///     "http://example.com:3000/api"
/// );
/// ```
pub fn sanitize_url_for_logging(url_str: &str) -> String {
    match parse_url_with_auth(url_str) {
        Ok(parsed) => parsed.url,
        // If we can't parse the URL, return a redacted version to avoid
        // accidentally exposing credentials in malformed URLs
        Err(_) => "[invalid URL redacted]".to_string(),
    }
}

/// Parsed URL with optional credentials extracted.
///
/// The `url` crate handles all the parsing - we just extract and strip credentials.
#[derive(Debug, Clone)]
pub struct ParsedUrl {
    /// URL without credentials (safe for logging/requests)
    pub url: String,
    /// Optional (username, password) extracted from URL
    pub auth: Option<(String, String)>,
}

/// Parse a URL and extract embedded credentials.
///
/// Uses the Servo `url` crate for WHATWG-compliant parsing.
///
/// # Example
///
/// ```
/// use ember_transport::url_auth::parse_url_with_auth;
///
/// let parsed = parse_url_with_auth("http://user:pass@example.com:3000/api").unwrap();
/// assert_eq!(parsed.url, "http://example.com:3000/api");
/// assert_eq!(parsed.auth, Some(("user".to_string(), "pass".to_string())));
///
/// // URL without credentials
/// let parsed = parse_url_with_auth("http://example.com:3000/api").unwrap();
/// assert_eq!(parsed.url, "http://example.com:3000/api");
/// assert_eq!(parsed.auth, None);
/// ```
pub fn parse_url_with_auth(url_str: &str) -> Result<ParsedUrl, url::ParseError> {
    let mut url = Url::parse(url_str)?;

    // Check for username OR password - URLs like "http://:pass@host" have empty username but password
    let has_credentials = !url.username().is_empty() || url.password().is_some();

    let auth = if has_credentials {
        // URL crate returns percent-encoded credentials; decode them for use with HTTP clients
        let username = percent_decode_str(url.username())
            .decode_utf8_lossy()
            .into_owned();
        let password = url
            .password()
            .map(|p| percent_decode_str(p).decode_utf8_lossy().into_owned())
            .unwrap_or_default();
        // Clear credentials from URL for security
        url.set_username("").ok();
        url.set_password(None).ok();
        Some((username, password))
    } else {
        None
    };

    Ok(ParsedUrl {
        url: url.to_string(),
        auth,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_with_credentials() {
        let parsed = parse_url_with_auth("http://user:pass@example.com:3000/api").unwrap();
        assert_eq!(parsed.url, "http://example.com:3000/api");
        assert_eq!(parsed.auth, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_url_without_credentials() {
        let parsed = parse_url_with_auth("http://example.com:3000/api").unwrap();
        assert_eq!(parsed.url, "http://example.com:3000/api");
        assert_eq!(parsed.auth, None);
    }

    #[test]
    fn test_url_with_username_only() {
        let parsed = parse_url_with_auth("http://user@example.com:3000").unwrap();
        assert_eq!(parsed.url, "http://example.com:3000/");
        assert_eq!(parsed.auth, Some(("user".to_string(), String::new())));
    }

    #[test]
    fn test_https_url() {
        let parsed = parse_url_with_auth("https://admin:secret@secure.example.com").unwrap();
        assert_eq!(parsed.url, "https://secure.example.com/");
        assert_eq!(
            parsed.auth,
            Some(("admin".to_string(), "secret".to_string()))
        );
    }

    #[test]
    fn test_url_with_path_and_query() {
        let parsed =
            parse_url_with_auth("http://u:p@example.com:8080/path/to/api?key=value").unwrap();
        assert_eq!(parsed.url, "http://example.com:8080/path/to/api?key=value");
        assert_eq!(parsed.auth, Some(("u".to_string(), "p".to_string())));
    }

    #[test]
    fn test_special_characters_in_password() {
        // Special characters in password should be percent-decoded
        let parsed = parse_url_with_auth("http://user:p%40ss%3Aword@example.com").unwrap();
        assert_eq!(parsed.url, "http://example.com/");
        assert_eq!(
            parsed.auth,
            Some(("user".to_string(), "p@ss:word".to_string()))
        );
    }

    #[test]
    fn test_invalid_url() {
        assert!(parse_url_with_auth("not a valid url").is_err());
    }

    #[test]
    fn test_url_with_password_only() {
        // Edge case: empty username but password present - must still strip credentials
        let parsed = parse_url_with_auth("http://:secret@example.com:3000").unwrap();
        assert_eq!(parsed.url, "http://example.com:3000/");
        assert_eq!(parsed.auth, Some((String::new(), "secret".to_string())));
    }

    #[test]
    fn test_sanitize_url_with_credentials() {
        assert_eq!(
            sanitize_url_for_logging("http://user:pass@example.com:3000/api"),
            "http://example.com:3000/api"
        );
    }

    #[test]
    fn test_sanitize_url_without_credentials() {
        assert_eq!(
            sanitize_url_for_logging("https://example.com:8443/path"),
            "https://example.com:8443/path"
        );
    }

    #[test]
    fn test_sanitize_invalid_url() {
        // Invalid URLs should be redacted to prevent accidental credential exposure
        assert_eq!(
            sanitize_url_for_logging("not a valid url with user:pass"),
            "[invalid URL redacted]"
        );
    }
}
