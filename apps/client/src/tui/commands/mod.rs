//! Chat slash commands: framework + cosmetic commands.

pub mod builtin;
pub mod complete;
pub mod parser;
pub mod popup;

pub use parser::{is_command_mode, parse, strip_escape, ParsedCommandOwned};
pub use popup::{CommandCompletionState, CompletionOutcome};

/// A single slash command, e.g. `/tableflip`.
pub trait Command: Send + Sync {
    fn name(&self) -> &'static str;
    fn aliases(&self) -> &'static [&'static str] {
        &[]
    }
    fn help(&self) -> &'static str;
    fn usage(&self) -> &'static str;
    fn execute(&self, ctx: &CommandContext<'_>, args: &str) -> Vec<CommandAction>;

    /// Candidates for the next argument, given what's typed so far.
    /// Default: no arg completion. Commands that want argument completion
    /// (e.g. a future `/p2p tor|iroh|<ip>`) override this.
    fn complete_args(&self, _args_so_far: &str) -> Vec<CompletionEntry> {
        Vec::new()
    }
}

/// Context passed to `Command::execute`. Empty in v1; grows in follow-up PRs
/// to carry selected-contact info and a `BackendHandle` reference (#232).
#[derive(Debug, Default)]
pub struct CommandContext<'a> {
    _lifetime: std::marker::PhantomData<&'a ()>,
}

impl<'a> CommandContext<'a> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            _lifetime: std::marker::PhantomData,
        }
    }
}

/// Side effects a command can request. `App::apply_command_action` is the
/// interpreter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandAction {
    /// Replace the textarea contents with the given string. Does not send.
    ReplaceInput(String),
    /// Clear the visible scrollback (and the cache entry for the selected
    /// contact). Does NOT touch persistent storage or bump the epoch.
    ClearScrollback,
    /// Exit the client, same as Ctrl+Q.
    Quit,
    /// Write a one-line message to the status bar.
    Status(String),
    // Future variants reserved for follow-up PRs:
    //   SendText(String),
    //   BackendCall(BackendRequest),
    //   StartEphemeralSession(TransportKind),
    //   ShowPopup(PopupKind),
}

/// One entry in the completion popup. `insert` is what Tab writes into the
/// textarea; `label` is what the popup displays (usually the same);
/// `help` is the dimmed help column on the right.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionEntry {
    pub insert: String,
    pub label: String,
    pub help: String,
}

/// Registry of all known commands. Cheap to construct — six `Box<dyn Command>`
/// allocations — so callers that need a temporary (e.g. `App::dispatch_command`)
/// can build a fresh one instead of threading a borrow.
pub struct Registry {
    commands: Vec<Box<dyn Command>>,
}

impl Registry {
    #[must_use]
    pub fn builtin() -> Self {
        Self {
            commands: vec![
                Box::new(builtin::Help),
                Box::new(builtin::TableFlip),
                Box::new(builtin::Shrug),
                Box::new(builtin::Me),
                Box::new(builtin::Clear),
                Box::new(builtin::Quit),
            ],
        }
    }

    /// Find a command by name or alias. A leading `/` is tolerated.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&dyn Command> {
        let name = name.strip_prefix('/').unwrap_or(name);
        self.commands.iter().find_map(|cmd| {
            if cmd.name() == name || cmd.aliases().contains(&name) {
                Some(cmd.as_ref())
            } else {
                None
            }
        })
    }

    /// Return candidates whose name starts with `prefix`, sorted alphabetically.
    /// An empty prefix returns all commands. A leading `/` on the prefix is
    /// tolerated.
    #[must_use]
    pub fn complete(&self, prefix: &str) -> Vec<CompletionEntry> {
        complete::complete_name(&self.commands, prefix)
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::builtin()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn builtin_registry_has_all_six_commands() {
        let r = Registry::builtin();
        assert!(r.find("help").is_some());
        assert!(r.find("tableflip").is_some());
        assert!(r.find("shrug").is_some());
        assert!(r.find("me").is_some());
        assert!(r.find("clear").is_some());
        assert!(r.find("quit").is_some());
    }

    #[test]
    fn builtin_registry_unknown_is_none() {
        let r = Registry::builtin();
        assert!(r.find("nonsense").is_none());
    }

    #[test]
    fn builtin_registry_strips_leading_slash() {
        let r = Registry::builtin();
        assert!(r.find("/tableflip").is_some());
    }

    #[test]
    fn builtin_registry_resolves_shrug_alias() {
        let r = Registry::builtin();
        assert_eq!(r.find("sh").unwrap().name(), "shrug");
    }

    #[test]
    fn complete_empty_prefix_returns_all_sorted() {
        let r = Registry::builtin();
        let entries = r.complete("");
        assert_eq!(entries.len(), 6);
        let names: Vec<&str> = entries.iter().map(|e| e.label.as_str()).collect();
        assert_eq!(
            names,
            vec!["/clear", "/help", "/me", "/quit", "/shrug", "/tableflip"]
        );
    }

    #[test]
    fn complete_prefix_filters() {
        let r = Registry::builtin();
        let entries = r.complete("ta");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].label, "/tableflip");
        assert_eq!(entries[0].insert, "/tableflip");
    }

    #[test]
    fn complete_prefix_with_leading_slash_works() {
        let r = Registry::builtin();
        let entries = r.complete("/sh");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].label, "/shrug");
    }

    #[test]
    fn complete_unknown_prefix_returns_empty() {
        let r = Registry::builtin();
        assert!(r.complete("xyz").is_empty());
    }

    #[test]
    fn complete_includes_help_column_from_command() {
        let r = Registry::builtin();
        let entries = r.complete("ta");
        assert_eq!(entries[0].help, "Flip the table");
    }
}
