//! Slash command parser.

use thiserror::Error;

/// Parsed form of a slash command input string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommand<'a> {
    /// Command name without the leading `/`.
    pub name: &'a str,
    /// Everything after the first whitespace. Commands parse their own args.
    pub args: &'a str,
}

impl ParsedCommand<'_> {
    #[must_use]
    pub fn into_owned(self) -> ParsedCommandOwned {
        ParsedCommandOwned {
            name: self.name.to_string(),
            args: self.args.to_string(),
        }
    }
}

/// Owned variant of [`ParsedCommand`] that doesn't borrow from the input.
/// Carried by [`super::CompletionOutcome::Dispatch`] so the parsed command
/// can outlive the textarea state it was parsed from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommandOwned {
    pub name: String,
    pub args: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("empty command")]
    Empty,
    #[error("invalid command syntax")]
    Invalid,
}

/// Parse a slash command input into `(name, args)`.
///
/// Rejects: empty/whitespace-only text, missing leading `/`, leading
/// whitespace before the `/`, and names that don't start with an ASCII
/// alphanumeric byte.
pub fn parse(text: &str) -> Result<ParsedCommand<'_>, ParseError> {
    if text.trim().is_empty() {
        return Err(ParseError::Empty);
    }
    let Some(rest) = text.strip_prefix('/') else {
        return Err(ParseError::Invalid);
    };

    let (name, args) = match rest.find(char::is_whitespace) {
        Some(idx) => {
            let (name, tail) = rest.split_at(idx);
            (name, tail.trim_start())
        }
        None => (rest, ""),
    };

    if name.is_empty()
        || !name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        return Err(ParseError::Invalid);
    }

    Ok(ParsedCommand { name, args })
}

/// Return true iff the input is a single line starting with `/` (and not `//`).
///
/// Used by the TUI to decide whether the completion popup should be active.
/// Multiline input and the `//` escape sequence both deactivate command mode.
#[must_use]
pub fn is_command_mode(text: &str) -> bool {
    if text.contains('\n') {
        return false;
    }
    if text.starts_with("//") {
        return false;
    }
    text.starts_with('/')
}

/// If `text` starts with `//`, return the text with one leading `/` removed.
/// Otherwise return the input unchanged. Called by the send path so that
/// `//foo` gets sent as the literal message `/foo`.
#[must_use]
pub fn strip_escape(text: &str) -> &str {
    if text.starts_with("//") {
        &text[1..]
    } else {
        text
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_name_only() {
        let parsed = parse("/tableflip").unwrap();
        assert_eq!(parsed.name, "tableflip");
        assert_eq!(parsed.args, "");
    }

    #[test]
    fn parse_name_and_args() {
        let parsed = parse("/shrug hello world").unwrap();
        assert_eq!(parsed.name, "shrug");
        assert_eq!(parsed.args, "hello world");
    }

    #[test]
    fn parse_preserves_rest_of_line_for_me() {
        let parsed = parse("/me waves at bob").unwrap();
        assert_eq!(parsed.name, "me");
        assert_eq!(parsed.args, "waves at bob");
    }

    #[test]
    fn parse_collapses_multiple_spaces_between_name_and_args() {
        let parsed = parse("/me    waves   at   bob").unwrap();
        assert_eq!(parsed.name, "me");
        assert_eq!(parsed.args, "waves   at   bob");
    }

    #[test]
    fn parse_empty_returns_empty_error() {
        assert_eq!(parse("").unwrap_err(), ParseError::Empty);
    }

    #[test]
    fn parse_whitespace_returns_empty_error() {
        assert_eq!(parse("   ").unwrap_err(), ParseError::Empty);
    }

    #[test]
    fn parse_just_slash_returns_invalid_error() {
        assert_eq!(parse("/").unwrap_err(), ParseError::Invalid);
    }

    #[test]
    fn parse_slash_space_returns_invalid_error() {
        assert_eq!(parse("/ foo").unwrap_err(), ParseError::Invalid);
    }

    #[test]
    fn parse_missing_leading_slash_returns_invalid() {
        assert_eq!(parse("tableflip").unwrap_err(), ParseError::Invalid);
    }

    #[test]
    fn parse_leading_whitespace_not_allowed() {
        assert_eq!(parse(" /tableflip").unwrap_err(), ParseError::Invalid);
    }

    #[test]
    fn parse_name_is_lowercase_alphanumeric() {
        let parsed = parse("/help2 arg").unwrap();
        assert_eq!(parsed.name, "help2");
        assert_eq!(parsed.args, "arg");
    }

    #[test]
    fn parse_trailing_whitespace_in_args_preserved() {
        let parsed = parse("/me hi   ").unwrap();
        assert_eq!(parsed.name, "me");
        assert_eq!(parsed.args, "hi   ");
    }

    #[test]
    fn command_mode_active_for_single_line_starting_with_slash() {
        assert!(is_command_mode("/tableflip"));
        assert!(is_command_mode("/me waves"));
        assert!(is_command_mode("/"));
    }

    #[test]
    fn command_mode_inactive_for_escape_sequence() {
        assert!(!is_command_mode("//foo"));
        assert!(!is_command_mode("//"));
    }

    #[test]
    fn command_mode_inactive_for_plain_text() {
        assert!(!is_command_mode("hello"));
        assert!(!is_command_mode(""));
        assert!(!is_command_mode(" /tableflip"));
    }

    #[test]
    fn command_mode_inactive_for_multiline_input() {
        assert!(!is_command_mode("/tableflip\nmore"));
        assert!(!is_command_mode("/me\n"));
    }

    #[test]
    fn strip_escape_removes_leading_slash_from_double_slash() {
        assert_eq!(strip_escape("//foo"), "/foo");
        assert_eq!(strip_escape("//"), "/");
        assert_eq!(strip_escape("//tableflip text"), "/tableflip text");
    }

    #[test]
    fn strip_escape_leaves_other_text_unchanged() {
        assert_eq!(strip_escape("/foo"), "/foo");
        assert_eq!(strip_escape("hello"), "hello");
        assert_eq!(strip_escape(""), "");
        assert_eq!(strip_escape("/"), "/");
    }

    #[test]
    fn into_owned_round_trips() {
        let parsed = parse("/tableflip hello").unwrap();
        let owned = parsed.into_owned();
        assert_eq!(owned.name, "tableflip");
        assert_eq!(owned.args, "hello");
    }
}
