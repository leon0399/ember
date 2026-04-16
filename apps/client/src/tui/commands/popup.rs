//! Command completion popup: state machine + rendering.
//!
//! `CommandCompletionState` is self-contained: `App` owns it as a field and
//! interacts only through the narrow interface (`is_active`, `handle_key`,
//! `update_from_input`, `suppress`, `reset`, `tab_insertion`, `render`,
//! `render_ghost_text`). All command-mode logic lives inside this module.
//! When the `Component` trait (#172) lands this struct becomes a
//! straightforward `impl Component` with near-zero migration.

use super::{CompletionEntry, ParsedCommand, Registry};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState},
    Frame,
};

/// What the app should do after a key has been offered to the popup.
#[derive(Debug)]
pub enum CompletionOutcome {
    /// The textarea should handle this key (e.g. a character or backspace).
    PassThrough,
    /// The popup handled the key, no further processing needed.
    Consumed,
    /// The user pressed Enter on a parseable command; app should dispatch it.
    Dispatch(ParsedCommand<'static>),
    /// The user pressed Esc; app should call `suppress()`.
    Exit,
}

pub struct CommandCompletionState {
    registry: Registry,
    active: bool,
    /// Set by `suppress()` (called when the user presses Esc). Blocks
    /// `update_from_input` from re-activating the popup as long as the
    /// current input still starts with `/`. Cleared automatically once
    /// the user deletes the leading slash or empties the input.
    suppressed: bool,
    current_line: String,
    candidates: Vec<CompletionEntry>,
    selected: usize,
}

impl CommandCompletionState {
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(registry: Registry) -> Self {
        Self {
            registry,
            active: false,
            suppressed: false,
            current_line: String::new(),
            candidates: Vec::new(),
            selected: 0,
        }
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Re-filter the candidate list from the first textarea line. Called
    /// after every keystroke that reaches the textarea.
    pub fn update_from_input(&mut self, line: &str) {
        self.current_line = line.to_string();

        // Clear suppression once the user deletes back past the '/' or
        // the line stops starting with '/'. Typing '/' again from an
        // unsuppressed state re-activates normally.
        if self.suppressed && !line.starts_with('/') {
            self.suppressed = false;
        }

        if self.suppressed {
            self.active = false;
            self.candidates.clear();
            self.selected = 0;
            return;
        }

        let was_active = self.active;
        self.active = super::parser::is_command_mode(line);

        if !self.active {
            self.candidates.clear();
            self.selected = 0;
            return;
        }

        let (before_space, after_space) = match line.find(char::is_whitespace) {
            Some(idx) => (&line[..idx], Some(&line[idx + 1..])),
            None => (line, None),
        };

        self.candidates = if let Some(args_so_far) = after_space {
            let name = before_space.strip_prefix('/').unwrap_or(before_space);
            self.registry
                .find(name)
                .map(|cmd| cmd.complete_args(args_so_far))
                .unwrap_or_default()
        } else {
            self.registry.complete(before_space)
        };

        if !was_active || self.selected >= self.candidates.len() {
            self.selected = 0;
        }
    }

    /// Exit command mode but preserve textarea content. Called by the app
    /// when the user presses Esc. Blocks re-activation until the user
    /// deletes the leading `/` — see `update_from_input`.
    pub fn suppress(&mut self) {
        self.active = false;
        self.suppressed = true;
        self.candidates.clear();
        self.selected = 0;
    }

    /// Clear all completion state. Called when the textarea is replaced
    /// wholesale (e.g. after a successful command dispatch).
    pub fn reset(&mut self) {
        self.active = false;
        self.suppressed = false;
        self.current_line.clear();
        self.candidates.clear();
        self.selected = 0;
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn candidates(&self) -> &[CompletionEntry] {
        &self.candidates
    }

    #[must_use]
    #[allow(dead_code)]
    pub const fn selected_index(&self) -> usize {
        self.selected
    }

    #[must_use]
    pub fn selected_entry(&self) -> Option<&CompletionEntry> {
        self.candidates.get(self.selected)
    }

    /// What Tab should insert into the textarea. Trailing space lets the
    /// user immediately start typing arguments. Returns `None` when
    /// inactive or no candidates.
    #[must_use]
    pub fn tab_insertion(&self) -> Option<String> {
        if !self.active {
            return None;
        }
        let entry = self.candidates.get(self.selected)?;
        Some(format!("{} ", entry.insert))
    }

    /// Offer a key event to the popup. Consumers: arrow keys drive
    /// selection, Tab signals "caller should read `tab_insertion`",
    /// Enter parses current line and returns `Dispatch`, Esc returns
    /// `Exit`, everything else passes through.
    pub fn handle_key(&mut self, key: KeyEvent) -> CompletionOutcome {
        if !self.active {
            return CompletionOutcome::PassThrough;
        }

        match key.code {
            KeyCode::Down => {
                if !self.candidates.is_empty() {
                    self.selected = (self.selected + 1) % self.candidates.len();
                }
                CompletionOutcome::Consumed
            }
            KeyCode::Up => {
                if !self.candidates.is_empty() {
                    self.selected = if self.selected == 0 {
                        self.candidates.len() - 1
                    } else {
                        self.selected - 1
                    };
                }
                CompletionOutcome::Consumed
            }
            KeyCode::Tab => CompletionOutcome::Consumed,
            KeyCode::Enter => match super::parser::parse(&self.current_line) {
                Ok(parsed) => CompletionOutcome::Dispatch(parsed.into_owned()),
                Err(_) => CompletionOutcome::Consumed,
            },
            KeyCode::Esc => CompletionOutcome::Exit,
            KeyCode::Backspace
            | KeyCode::Left
            | KeyCode::Right
            | KeyCode::Home
            | KeyCode::End
            | KeyCode::PageUp
            | KeyCode::PageDown
            | KeyCode::BackTab
            | KeyCode::Delete
            | KeyCode::Insert
            | KeyCode::Null
            | KeyCode::CapsLock
            | KeyCode::ScrollLock
            | KeyCode::NumLock
            | KeyCode::PrintScreen
            | KeyCode::Pause
            | KeyCode::Menu
            | KeyCode::KeypadBegin
            | KeyCode::F(_)
            | KeyCode::Char(_)
            | KeyCode::Media(_)
            | KeyCode::Modifier(_) => CompletionOutcome::PassThrough,
        }
    }

    /// Render the completion popup above the given input area. No-op when
    /// inactive, empty, or the popup would not fit above `input_area`.
    pub fn render(&self, frame: &mut Frame, input_area: Rect) {
        if !self.active || self.candidates.is_empty() {
            return;
        }

        let row_count = u16::try_from(self.candidates.len().min(6)).unwrap_or(6);
        let popup_height = row_count.saturating_add(2); // borders
        if popup_height > input_area.y {
            return; // not enough room above the input
        }
        let popup_width = input_area.width.min(60);
        let popup_area = Rect {
            x: input_area.x,
            y: input_area.y - popup_height,
            width: popup_width,
            height: popup_height,
        };

        frame.render_widget(Clear, popup_area);

        let items: Vec<ListItem> = self
            .candidates
            .iter()
            .map(|entry| {
                let label = format!("{:<18}", entry.label);
                ListItem::new(Line::from(vec![
                    Span::styled(label, Style::default().fg(Color::Cyan)),
                    Span::styled(entry.help.clone(), Style::default().fg(Color::DarkGray)),
                ]))
            })
            .collect();

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray))
                    .title(" Commands "),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::White)
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            );

        let mut list_state = ListState::default();
        list_state.select(Some(self.selected));
        frame.render_stateful_widget(list, popup_area, &mut list_state);
    }

    /// Render dimmed ghost-text suffix of the selected candidate at the
    /// given cursor cell. No-op when the typed text doesn't prefix the
    /// selected candidate, or the cell is out of bounds.
    pub fn render_ghost_text(&self, frame: &mut Frame, cursor_cell: (u16, u16)) {
        if !self.active {
            return;
        }
        let Some(entry) = self.selected_entry() else {
            return;
        };
        let Some(suffix) = entry.insert.strip_prefix(self.current_line.as_str()) else {
            return;
        };
        if suffix.is_empty() {
            return;
        }

        let (x, y) = cursor_cell;
        let area = frame.area();
        if x >= area.width || y >= area.height {
            return;
        }

        let available_width = area.width.saturating_sub(x) as usize;
        let truncated: String = suffix.chars().take(available_width).collect();

        frame
            .buffer_mut()
            .set_string(x, y, &truncated, Style::default().fg(Color::DarkGray));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    fn state() -> CommandCompletionState {
        CommandCompletionState::new(Registry::builtin())
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    // ── core state ──────────────────────────────────────────────

    #[test]
    fn inactive_for_empty_input() {
        let mut s = state();
        s.update_from_input("");
        assert!(!s.is_active());
        assert!(s.candidates().is_empty());
    }

    #[test]
    fn active_when_line_starts_with_slash() {
        let mut s = state();
        s.update_from_input("/");
        assert!(s.is_active());
        assert_eq!(s.candidates().len(), 6);
    }

    #[test]
    fn filters_candidates_on_prefix() {
        let mut s = state();
        s.update_from_input("/ta");
        assert!(s.is_active());
        assert_eq!(s.candidates().len(), 1);
        assert_eq!(s.candidates()[0].label, "/tableflip");
    }

    #[test]
    fn inactive_for_escape_sequence() {
        let mut s = state();
        s.update_from_input("//foo");
        assert!(!s.is_active());
    }

    #[test]
    fn inactive_for_plain_text() {
        let mut s = state();
        s.update_from_input("hello world");
        assert!(!s.is_active());
    }

    #[test]
    fn deactivate_clears_state() {
        let mut s = state();
        s.update_from_input("/tab");
        assert!(s.is_active());
        s.update_from_input("hello");
        assert!(!s.is_active());
        assert!(s.candidates().is_empty());
        assert_eq!(s.selected_index(), 0);
    }

    #[test]
    fn reset_clears_everything() {
        let mut s = state();
        s.update_from_input("/");
        s.reset();
        assert!(!s.is_active());
        assert!(s.candidates().is_empty());
        assert_eq!(s.selected_index(), 0);
    }

    #[test]
    fn selected_clamps_when_candidates_shrink() {
        let mut s = state();
        s.update_from_input("/");
        s.update_from_input("/tab"); // one candidate
        assert!(s.selected_index() < s.candidates().len());
    }

    // ── suppression ─────────────────────────────────────────────

    #[test]
    fn suppress_disables_activation_while_line_still_starts_with_slash() {
        let mut s = state();
        s.update_from_input("/ta");
        assert!(s.is_active());

        s.suppress();
        assert!(!s.is_active());
        assert!(s.candidates().is_empty());

        s.update_from_input("/tab");
        assert!(!s.is_active(), "still suppressed while '/' remains");
        s.update_from_input("/table");
        assert!(!s.is_active());
    }

    #[test]
    fn suppress_clears_once_input_loses_leading_slash() {
        let mut s = state();
        s.update_from_input("/ta");
        s.suppress();

        s.update_from_input("");
        assert!(!s.is_active());

        s.update_from_input("/");
        assert!(s.is_active());
    }

    #[test]
    fn suppress_clears_when_input_becomes_plain_text() {
        let mut s = state();
        s.update_from_input("/ta");
        s.suppress();

        s.update_from_input("hello");
        assert!(!s.is_active());
        s.update_from_input("hello /world");
        assert!(!s.is_active());
    }

    // ── handle_key ──────────────────────────────────────────────

    #[test]
    fn passes_through_when_inactive() {
        let mut s = state();
        let outcome = s.handle_key(key(KeyCode::Char('a')));
        assert!(matches!(outcome, CompletionOutcome::PassThrough));
    }

    #[test]
    fn down_advances_selection() {
        let mut s = state();
        s.update_from_input("/");
        assert_eq!(s.selected_index(), 0);
        let _ = s.handle_key(key(KeyCode::Down));
        assert_eq!(s.selected_index(), 1);
    }

    #[test]
    fn down_wraps_at_end() {
        let mut s = state();
        s.update_from_input("/");
        let last = s.candidates().len() - 1;
        for _ in 0..last {
            let _ = s.handle_key(key(KeyCode::Down));
        }
        assert_eq!(s.selected_index(), last);
        let _ = s.handle_key(key(KeyCode::Down));
        assert_eq!(s.selected_index(), 0);
    }

    #[test]
    fn up_retreats_with_wrap() {
        let mut s = state();
        s.update_from_input("/");
        let last = s.candidates().len() - 1;
        let _ = s.handle_key(key(KeyCode::Up));
        assert_eq!(s.selected_index(), last);
    }

    #[test]
    fn arrow_is_consumed_when_active() {
        let mut s = state();
        s.update_from_input("/");
        let outcome = s.handle_key(key(KeyCode::Down));
        assert!(matches!(outcome, CompletionOutcome::Consumed));
    }

    #[test]
    fn tab_returns_consumed_without_dispatching() {
        let mut s = state();
        s.update_from_input("/ta");
        let outcome = s.handle_key(key(KeyCode::Tab));
        assert!(matches!(outcome, CompletionOutcome::Consumed));
    }

    #[test]
    fn enter_returns_dispatch_with_parsed_command() {
        let mut s = state();
        s.update_from_input("/tableflip hi");
        let outcome = s.handle_key(key(KeyCode::Enter));
        match outcome {
            CompletionOutcome::Dispatch(parsed) => {
                assert_eq!(parsed.name, "tableflip");
                assert_eq!(parsed.args, "hi");
            }
            other @ (CompletionOutcome::PassThrough
            | CompletionOutcome::Consumed
            | CompletionOutcome::Exit) => panic!("expected Dispatch, got {other:?}"),
        }
    }

    #[test]
    fn enter_on_unknown_command_still_dispatches() {
        let mut s = state();
        s.update_from_input("/nonsense");
        let outcome = s.handle_key(key(KeyCode::Enter));
        assert!(matches!(outcome, CompletionOutcome::Dispatch(_)));
    }

    #[test]
    fn esc_returns_exit() {
        let mut s = state();
        s.update_from_input("/ta");
        let outcome = s.handle_key(key(KeyCode::Esc));
        assert!(matches!(outcome, CompletionOutcome::Exit));
    }

    #[test]
    fn passthrough_for_character_keys_when_active() {
        let mut s = state();
        s.update_from_input("/");
        let outcome = s.handle_key(key(KeyCode::Char('a')));
        assert!(matches!(outcome, CompletionOutcome::PassThrough));
    }

    #[test]
    fn passthrough_for_backspace_when_active() {
        let mut s = state();
        s.update_from_input("/ta");
        let outcome = s.handle_key(key(KeyCode::Backspace));
        assert!(matches!(outcome, CompletionOutcome::PassThrough));
    }

    // ── tab_insertion ───────────────────────────────────────────

    #[test]
    fn tab_insertion_returns_selected_entry_with_trailing_space() {
        let mut s = state();
        s.update_from_input("/ta");
        assert_eq!(s.tab_insertion(), Some("/tableflip ".to_string()));
    }

    #[test]
    fn tab_insertion_uses_selected_index() {
        let mut s = state();
        s.update_from_input("/");
        // First candidate alphabetically is /clear.
        assert_eq!(s.tab_insertion(), Some("/clear ".to_string()));
    }

    #[test]
    fn tab_insertion_empty_when_inactive() {
        let s = state();
        assert_eq!(s.tab_insertion(), None);
    }

    #[test]
    fn tab_insertion_empty_when_no_candidates() {
        let mut s = state();
        s.update_from_input("/xyz");
        assert_eq!(s.tab_insertion(), None);
    }

    // ── ghost text ──────────────────────────────────────────────

    #[test]
    fn ghost_suffix_is_selected_entry_minus_current_input() {
        let mut s = state();
        s.update_from_input("/ta");
        let entry = s.selected_entry().unwrap();
        let suffix = entry.insert.strip_prefix("/ta").unwrap();
        assert_eq!(suffix, "bleflip");
    }

    #[test]
    fn ghost_suffix_empty_when_full_command_typed() {
        let mut s = state();
        s.update_from_input("/tableflip");
        let entry = s.selected_entry().unwrap();
        let suffix = entry.insert.strip_prefix("/tableflip").unwrap();
        assert_eq!(suffix, "");
    }
}
