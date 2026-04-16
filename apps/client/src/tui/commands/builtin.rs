//! Built-in slash command implementations for v1.
//!
//! All six commands are client-local: no wire traffic, no `BackendHandle`.
//! Each `execute` is pure — takes a `CommandContext` and args, returns
//! a list of `CommandAction`s for `App` to apply.

use super::{Command, CommandAction, CommandContext, CompletionEntry};

// ── /tableflip ──────────────────────────────────────────────────────

pub struct TableFlip;

impl Command for TableFlip {
    fn name(&self) -> &'static str {
        "tableflip"
    }
    fn help(&self) -> &'static str {
        "Flip the table"
    }
    fn usage(&self) -> &'static str {
        "/tableflip [text]"
    }
    fn execute(&self, _ctx: &CommandContext<'_>, args: &str) -> Vec<CommandAction> {
        let body = if args.is_empty() {
            "(╯°□°)╯︵ ┻━┻".to_string()
        } else {
            format!("{args} (╯°□°)╯︵ ┻━┻")
        };
        vec![CommandAction::ReplaceInput(body)]
    }
}

// ── /shrug ──────────────────────────────────────────────────────────

pub struct Shrug;

impl Command for Shrug {
    fn name(&self) -> &'static str {
        "shrug"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["sh"]
    }
    fn help(&self) -> &'static str {
        r"¯\_(ツ)_/¯"
    }
    fn usage(&self) -> &'static str {
        "/shrug [text]"
    }
    fn execute(&self, _ctx: &CommandContext<'_>, args: &str) -> Vec<CommandAction> {
        let body = if args.is_empty() {
            r"¯\_(ツ)_/¯".to_string()
        } else {
            format!(r"{args} ¯\_(ツ)_/¯")
        };
        vec![CommandAction::ReplaceInput(body)]
    }
}

// ── /me ─────────────────────────────────────────────────────────────

pub struct Me;

impl Command for Me {
    fn name(&self) -> &'static str {
        "me"
    }
    fn help(&self) -> &'static str {
        "IRC-style action message"
    }
    fn usage(&self) -> &'static str {
        "/me <action>"
    }
    fn execute(&self, _ctx: &CommandContext<'_>, args: &str) -> Vec<CommandAction> {
        if args.is_empty() {
            vec![CommandAction::Status("usage: /me <action>".to_string())]
        } else {
            vec![CommandAction::ReplaceInput(format!("* {args}"))]
        }
    }
}

// ── /clear ──────────────────────────────────────────────────────────

pub struct Clear;

impl Command for Clear {
    fn name(&self) -> &'static str {
        "clear"
    }
    fn help(&self) -> &'static str {
        "Clear visible scrollback (does not touch storage)"
    }
    fn usage(&self) -> &'static str {
        "/clear"
    }
    fn execute(&self, _ctx: &CommandContext<'_>, _args: &str) -> Vec<CommandAction> {
        vec![CommandAction::ClearScrollback]
    }
}

// ── /quit ───────────────────────────────────────────────────────────

pub struct Quit;

impl Command for Quit {
    fn name(&self) -> &'static str {
        "quit"
    }
    fn help(&self) -> &'static str {
        "Exit the client"
    }
    fn usage(&self) -> &'static str {
        "/quit"
    }
    fn execute(&self, _ctx: &CommandContext<'_>, _args: &str) -> Vec<CommandAction> {
        vec![CommandAction::Quit]
    }
}

// ── /help ───────────────────────────────────────────────────────────

pub struct Help;

impl Command for Help {
    fn name(&self) -> &'static str {
        "help"
    }
    fn help(&self) -> &'static str {
        "Show command help"
    }
    fn usage(&self) -> &'static str {
        "/help [command]"
    }
    fn execute(&self, _ctx: &CommandContext<'_>, _args: &str) -> Vec<CommandAction> {
        // Always list-only. The `/help <name>` case is intercepted in
        // `App::dispatch_command` (see Task 16) because `execute` can't
        // see the registry to resolve target-command usage + help.
        vec![CommandAction::Status(
            "/help /tableflip /shrug /me /clear /quit".to_string(),
        )]
    }

    fn complete_args(&self, _args_so_far: &str) -> Vec<CompletionEntry> {
        // Could complete to other command names, but v1 doesn't invest
        // in nested completion. Status one-liner is enough.
        Vec::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ctx() -> CommandContext<'static> {
        CommandContext::new()
    }

    #[test]
    fn tableflip_no_args() {
        let actions = TableFlip.execute(&ctx(), "");
        assert_eq!(
            actions,
            vec![CommandAction::ReplaceInput("(╯°□°)╯︵ ┻━┻".to_string())]
        );
    }

    #[test]
    fn tableflip_with_args() {
        let actions = TableFlip.execute(&ctx(), "hello world");
        assert_eq!(
            actions,
            vec![CommandAction::ReplaceInput(
                "hello world (╯°□°)╯︵ ┻━┻".to_string()
            )]
        );
    }

    #[test]
    fn shrug_no_args() {
        let actions = Shrug.execute(&ctx(), "");
        assert_eq!(
            actions,
            vec![CommandAction::ReplaceInput(r"¯\_(ツ)_/¯".to_string())]
        );
    }

    #[test]
    fn shrug_with_args() {
        let actions = Shrug.execute(&ctx(), "whatever");
        assert_eq!(
            actions,
            vec![CommandAction::ReplaceInput(
                r"whatever ¯\_(ツ)_/¯".to_string()
            )]
        );
    }

    #[test]
    fn shrug_has_sh_alias() {
        assert_eq!(Shrug.aliases(), &["sh"]);
    }

    #[test]
    fn me_with_args() {
        let actions = Me.execute(&ctx(), "waves at bob");
        assert_eq!(
            actions,
            vec![CommandAction::ReplaceInput("* waves at bob".to_string())]
        );
    }

    #[test]
    fn me_without_args_returns_usage_status() {
        let actions = Me.execute(&ctx(), "");
        assert_eq!(
            actions,
            vec![CommandAction::Status("usage: /me <action>".to_string())]
        );
    }

    #[test]
    fn clear_returns_clear_scrollback() {
        let actions = Clear.execute(&ctx(), "");
        assert_eq!(actions, vec![CommandAction::ClearScrollback]);
    }

    #[test]
    fn clear_ignores_args() {
        let actions = Clear.execute(&ctx(), "anything");
        assert_eq!(actions, vec![CommandAction::ClearScrollback]);
    }

    #[test]
    fn quit_returns_quit_action() {
        let actions = Quit.execute(&ctx(), "");
        assert_eq!(actions, vec![CommandAction::Quit]);
    }

    #[test]
    fn help_lists_all_commands_in_status() {
        let actions = Help.execute(&ctx(), "");
        let status = match actions.as_slice() {
            [CommandAction::Status(s)] => s.clone(),
            _ => panic!("expected Status action"),
        };
        assert!(status.contains("/help"));
        assert!(status.contains("/tableflip"));
        assert!(status.contains("/shrug"));
        assert!(status.contains("/me"));
        assert!(status.contains("/clear"));
        assert!(status.contains("/quit"));
    }
}
