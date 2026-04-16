//! Completion engine: name-prefix matching and per-command arg completion.

use super::{Command, CompletionEntry};

/// Return all registered commands whose name or aliases start with `prefix`,
/// sorted alphabetically by display label. A leading `/` on the prefix is
/// tolerated and stripped. Deduplicates: if a command matches on both name
/// and alias, it appears once (by canonical name).
pub(super) fn complete_name(commands: &[Box<dyn Command>], prefix: &str) -> Vec<CompletionEntry> {
    let prefix = prefix.strip_prefix('/').unwrap_or(prefix);

    let mut entries: Vec<CompletionEntry> = commands
        .iter()
        .filter(|cmd| {
            cmd.name().starts_with(prefix) || cmd.aliases().iter().any(|a| a.starts_with(prefix))
        })
        .map(|cmd| CompletionEntry {
            insert: format!("/{}", cmd.name()),
            label: format!("/{}", cmd.name()),
            help: cmd.help().to_string(),
        })
        .collect();

    entries.sort_by(|a, b| a.label.cmp(&b.label));
    entries
}
