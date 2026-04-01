//! Conversation list component with `ListState`-backed selection.
//!
//! Manages a sorted list of conversations with two display modes (two-line
//! and compact), relative-time formatting, trust-level icons, and
//! selection-follows-conversation behaviour on re-sort.

use crate::config::DisplayMode;
use ember_identity::PublicID;
use ember_storage::TrustLevel;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, ListState},
};

// ---------------------------------------------------------------------------
// Conversation
// ---------------------------------------------------------------------------

/// A conversation entry shown in the sidebar.
///
/// Owns the data needed to render a single row in the conversation sidebar.
#[derive(Debug, Clone)]
pub struct Conversation {
    pub id: i64,
    pub public_id: PublicID,
    pub name: String,
    pub last_message: Option<String>,
    pub last_message_time: Option<i64>,
    pub unread_count: u32,
    pub trust_level: TrustLevel,
}

// ---------------------------------------------------------------------------
// ConversationList
// ---------------------------------------------------------------------------

/// State-backed conversation list with display mode toggling.
pub struct ConversationList {
    conversations: Vec<Conversation>,
    state: ListState,
    display_mode: DisplayMode,
}

impl ConversationList {
    /// Create an empty list with the given display mode.
    pub fn new(display_mode: DisplayMode) -> Self {
        Self {
            conversations: Vec::new(),
            state: ListState::default(),
            display_mode,
        }
    }

    /// Replace all conversations, preserving the current selection by `PublicID`.
    pub fn set_conversations(&mut self, conversations: Vec<Conversation>) {
        let selected_id = self.selected().map(|c| c.public_id);
        self.conversations = conversations;

        let new_index = selected_id.and_then(|pid| self.find_by_public_id(&pid)).or(
            if self.conversations.is_empty() {
                None
            } else {
                Some(0)
            },
        );
        self.state.select(new_index);
    }

    /// Sort conversations by `last_message_time` descending (`None` goes last).
    /// Preserves the current selection by `PublicID`.
    pub fn sort_by_recent(&mut self) {
        let selected_id = self.selected().map(|c| c.public_id);

        self.conversations.sort_by(|a, b| {
            let time_ord = match (&a.last_message_time, &b.last_message_time) {
                (Some(at), Some(bt)) => bt.cmp(at),             // descending
                (Some(_), None) => std::cmp::Ordering::Less,    // a (has time) before b (no time)
                (None, Some(_)) => std::cmp::Ordering::Greater, // b (has time) before a (no time)
                (None, None) => std::cmp::Ordering::Equal,
            };
            time_ord.then_with(|| a.name.cmp(&b.name))
        });

        if let Some(pid) = selected_id {
            self.state.select(self.find_by_public_id(&pid));
        }
    }

    /// Move selection to the previous conversation (wraps to bottom).
    pub fn select_previous(&mut self) {
        if self.conversations.is_empty() {
            return;
        }
        let i = match self.state.selected() {
            Some(0) | None => self.conversations.len() - 1,
            Some(i) => i - 1,
        };
        self.state.select(Some(i));
    }

    /// Move selection to the next conversation (wraps to top).
    pub fn select_next(&mut self) {
        if self.conversations.is_empty() {
            return;
        }
        let i = match self.state.selected() {
            Some(i) if i >= self.conversations.len() - 1 => 0,
            Some(i) => i + 1,
            None => 0,
        };
        self.state.select(Some(i));
    }

    /// Returns a reference to the currently selected conversation.
    pub fn selected(&self) -> Option<&Conversation> {
        self.state
            .selected()
            .and_then(|i| self.conversations.get(i))
    }

    /// Returns a mutable reference to the currently selected conversation.
    pub fn selected_mut(&mut self) -> Option<&mut Conversation> {
        self.state
            .selected()
            .and_then(|i| self.conversations.get_mut(i))
    }

    /// Returns the index of the currently selected conversation.
    pub const fn selected_index(&self) -> Option<usize> {
        self.state.selected()
    }

    /// Returns a reference to the conversation at `index`.
    pub fn get(&self, index: usize) -> Option<&Conversation> {
        self.conversations.get(index)
    }

    /// Returns a mutable reference to the conversation at `index`.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Conversation> {
        self.conversations.get_mut(index)
    }

    /// Find the index of a conversation by its `PublicID`.
    pub fn find_by_public_id(&self, public_id: &PublicID) -> Option<usize> {
        self.conversations
            .iter()
            .position(|c| c.public_id == *public_id)
    }

    /// Push a conversation onto the list. Returns its index.
    /// Auto-selects the first item if nothing was previously selected.
    pub fn push(&mut self, conversation: Conversation) -> usize {
        self.conversations.push(conversation);
        let idx = self.conversations.len() - 1;
        if self.state.selected().is_none() {
            self.state.select(Some(0));
        }
        idx
    }

    /// Select a conversation by index.
    pub fn select(&mut self, index: usize) {
        if index < self.conversations.len() {
            self.state.select(Some(index));
        }
    }

    /// Number of conversations in the list.
    #[allow(dead_code)] // Public API for component consumers
    pub fn len(&self) -> usize {
        self.conversations.len()
    }

    /// Whether the list is empty.
    #[allow(dead_code)] // Public API for component consumers
    pub fn is_empty(&self) -> bool {
        self.conversations.is_empty()
    }

    /// Toggle between `TwoLine` and `Compact` display modes.
    pub fn toggle_display_mode(&mut self) {
        self.display_mode = match self.display_mode {
            DisplayMode::TwoLine => DisplayMode::Compact,
            DisplayMode::Compact => DisplayMode::TwoLine,
        };
    }

    /// Current display mode.
    pub const fn display_mode(&self) -> DisplayMode {
        self.display_mode
    }

    /// Iterate over conversations.
    #[allow(dead_code)] // Public API for component consumers
    pub fn iter(&self) -> std::slice::Iter<'_, Conversation> {
        self.conversations.iter()
    }

    // -- Rendering ----------------------------------------------------------

    /// Render the conversation list into `area`.
    pub fn render(&mut self, frame: &mut Frame, area: Rect, is_focused: bool) {
        let border_style = if is_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        // Available width inside the block borders (2) minus highlight_symbol (2)
        let inner_width = area.width.saturating_sub(4);
        let now = unix_now();

        let items: Vec<ListItem> = self
            .conversations
            .iter()
            .map(|c| self.render_item(c, inner_width, now))
            .collect();

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(border_style)
                    .title(format!(" Conversations ({}) ", self.conversations.len())),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");

        frame.render_stateful_widget(list, area, &mut self.state);
    }

    /// Dispatch to two-line or compact rendering.
    fn render_item(&self, conv: &Conversation, width: u16, now: i64) -> ListItem<'static> {
        match self.display_mode {
            DisplayMode::TwoLine => Self::render_two_line(conv, width, now),
            DisplayMode::Compact => Self::render_compact(conv, width, now),
        }
    }

    /// Two-line mode:
    /// ```text
    /// ✓ Alice                        2m
    ///   Hey, are you coming t...    (3)
    /// ```
    fn render_two_line(conv: &Conversation, width: u16, now: i64) -> ListItem<'static> {
        let w = width as usize;
        let line1 = Self::build_name_line(conv, w, now);
        let line2 = Self::build_preview_line(conv, w);

        ListItem::new(vec![line1, line2])
    }

    /// Compact mode: `✓ Alice                  2m  (3)`
    fn render_compact(conv: &Conversation, width: u16, now: i64) -> ListItem<'static> {
        let w = width as usize;
        let (icon, icon_color) = trust_icon(conv.trust_level);

        // Build right side: timestamp + optional unread
        let time_str = conv
            .last_message_time
            .map(|ts| format_relative_time(ts, now))
            .unwrap_or_default();
        let unread_str = if conv.unread_count > 0 {
            format!("  ({})", conv.unread_count)
        } else {
            String::new()
        };
        let right = format!("{time_str}{unread_str}");
        let right_len = right.chars().count();

        // Truncate name if it would clip the right side
        let icon_prefix = format!("{icon} ");
        let icon_len = icon_prefix.chars().count();
        let max_name = w.saturating_sub(icon_len + right_len + 1);
        let name = truncate_str(&conv.name, max_name);
        let name_len = name.chars().count();

        let pad = w.saturating_sub(icon_len + name_len + right_len);

        let mut spans = vec![
            Span::styled(icon_prefix, Style::default().fg(icon_color)),
            Span::styled(name, Style::default().fg(Color::White)),
            Span::raw(" ".repeat(pad)),
        ];

        if !time_str.is_empty() {
            spans.push(Span::styled(time_str, Style::default().fg(Color::Gray)));
        }
        if conv.unread_count > 0 {
            spans.push(Span::styled(
                format!("  ({})", conv.unread_count),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ));
        }

        ListItem::new(Line::from(spans))
    }

    /// Line 1: `✓ Alice                        2m`
    ///
    /// Trust icon + name on the left, timestamp right-pinned.
    fn build_name_line(conv: &Conversation, width: usize, now: i64) -> Line<'static> {
        let (icon, icon_color) = trust_icon(conv.trust_level);

        // Build right side first to know how much space the name gets
        let right = conv
            .last_message_time
            .map(|ts| format_relative_time(ts, now))
            .unwrap_or_default();
        let right_len = right.chars().count();

        // Left side: "✓ Name" — truncate name if it would clip timestamp
        let icon_prefix = format!("{icon} ");
        let icon_len = icon_prefix.chars().count();
        let max_name = width.saturating_sub(icon_len + right_len + 1);
        let name = truncate_str(&conv.name, max_name);
        let name_len = name.chars().count();

        let pad = width.saturating_sub(icon_len + name_len + right_len);

        let mut spans = vec![
            Span::styled(icon_prefix, Style::default().fg(icon_color)),
            Span::styled(name, Style::default().fg(Color::White)),
            Span::raw(" ".repeat(pad)),
        ];

        if !right.is_empty() {
            spans.push(Span::styled(right, Style::default().fg(Color::Gray)));
        }

        Line::from(spans)
    }

    /// Line 2: `  Hey, are you coming t...    (3)`
    ///
    /// Message preview on the left, unread badge right-pinned.
    fn build_preview_line(conv: &Conversation, width: usize) -> Line<'static> {
        // Right side: unread badge
        let right = if conv.unread_count > 0 {
            format!("({})", conv.unread_count)
        } else {
            String::new()
        };
        let right_len = right.chars().count();

        // Left side: "  preview..." — reserve space for right + 1 gap
        let prefix = "  ";
        let max_preview = width
            .saturating_sub(prefix.len())
            .saturating_sub(right_len)
            .saturating_sub(1); // gap between preview and badge

        let (preview, preview_style) = if let Some(msg) = &conv.last_message {
            (
                truncate_str(msg, max_preview),
                Style::default().fg(Color::White),
            )
        } else {
            (
                "<no messages>".to_string(),
                Style::default()
                    .fg(Color::Gray)
                    .add_modifier(Modifier::ITALIC),
            )
        };

        let left = format!("{prefix}{preview}");
        let left_len = left.chars().count();
        let pad = width.saturating_sub(left_len + right_len);

        let mut spans = vec![
            Span::styled(left, preview_style),
            Span::raw(" ".repeat(pad)),
        ];

        if !right.is_empty() {
            spans.push(Span::styled(
                right,
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ));
        }

        Line::from(spans)
    }
}

// ---------------------------------------------------------------------------
// Helpers (module-level, private)
// ---------------------------------------------------------------------------

/// Current wall-clock time as Unix seconds.
fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    #[allow(clippy::cast_possible_wrap)]
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Map a `TrustLevel` to a display icon and colour.
const fn trust_icon(level: TrustLevel) -> (&'static str, Color) {
    match level {
        TrustLevel::Stranger => ("?", Color::Yellow),
        TrustLevel::Known => ("\u{25CB}", Color::Gray), // ○
        TrustLevel::Verified => ("\u{2713}", Color::Green), // ✓
        TrustLevel::Trusted => ("\u{25CF}", Color::Cyan), // ●
    }
}

/// Format a Unix timestamp (seconds) as a relative-time string.
fn format_relative_time(timestamp_secs: i64, now_secs: i64) -> String {
    // Clamp to 0 so future timestamps (clock skew, imported messages) show "now"
    #[allow(clippy::cast_sign_loss)]
    let diff = now_secs.saturating_sub(timestamp_secs).max(0) as u64;

    if diff < 60 {
        return "now".to_string();
    }
    if diff < 3600 {
        return format!("{}m", diff / 60);
    }
    if diff < 86400 {
        return format!("{}h", diff / 3600);
    }
    if diff < 604_800 {
        return format!("{}d", diff / 86400);
    }

    // Fall back to "Mon DD" using Howard Hinnant's civil-date algorithm.
    let (m, d) = civil_month_day(timestamp_secs);
    let month_name = match m {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        12 => "Dec",
        _ => "???",
    };
    format!("{month_name} {d}")
}

/// Extract (month 1..=12, day 1..=31) from a Unix timestamp using
/// Howard Hinnant's civil-date algorithm (no chrono dependency).
const fn civil_month_day(timestamp_secs: i64) -> (u32, u32) {
    let days = timestamp_secs.div_euclid(86400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    // doe is guaranteed in [0, 146096] by the algorithm.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let doe = (z - era * 146_097) as u32; // day-of-era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day-of-year [0, 365]
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (m, d)
}

/// Truncate a string to `max_len` characters, appending "..." if truncated.
fn truncate_str(s: &str, max_len: usize) -> String {
    let char_count = s.chars().count();
    if char_count <= max_len {
        return s.to_string();
    }
    if max_len <= 3 {
        return ".".repeat(max_len);
    }
    let end = max_len - 3;
    let truncated: String = s.chars().take(end).collect();
    format!("{truncated}...")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ember_identity::Identity;

    fn make_conv(name: &str, ts: Option<i64>, unread: u32) -> Conversation {
        let id = Identity::generate();
        Conversation {
            id: 0,
            public_id: *id.public_id(),
            name: name.to_string(),
            last_message: Some("hello".to_string()),
            last_message_time: ts,
            unread_count: unread,
            trust_level: TrustLevel::Known,
        }
    }

    #[test]
    fn sort_by_recent_puts_none_last() {
        let mut list = ConversationList::new(DisplayMode::TwoLine);
        list.push(make_conv("no-ts", None, 0));
        list.push(make_conv("old", Some(100), 0));
        list.push(make_conv("new", Some(200), 0));

        list.sort_by_recent();

        assert_eq!(list.get(0).map(|c| c.name.as_str()), Some("new"));
        assert_eq!(list.get(1).map(|c| c.name.as_str()), Some("old"));
        assert_eq!(list.get(2).map(|c| c.name.as_str()), Some("no-ts"));
    }

    #[test]
    fn selection_preserved_across_sort() {
        let mut list = ConversationList::new(DisplayMode::TwoLine);
        list.push(make_conv("a", Some(100), 0));
        list.push(make_conv("b", Some(300), 0));
        list.push(make_conv("c", Some(200), 0));

        // Select "a"
        list.state.select(Some(0));
        let a_pid = list.selected().map(|c| c.public_id);

        list.sort_by_recent();

        // "a" should still be selected even though it moved to index 2
        assert_eq!(list.selected().map(|c| c.public_id), a_pid);
        assert_eq!(list.selected().map(|c| c.name.as_str()), Some("a"));
    }

    #[test]
    fn select_next_wraps() {
        let mut list = ConversationList::new(DisplayMode::Compact);
        list.push(make_conv("a", None, 0));
        list.push(make_conv("b", None, 0));

        assert_eq!(list.selected_index(), Some(0));
        list.select_next();
        assert_eq!(list.selected_index(), Some(1));
        list.select_next();
        assert_eq!(list.selected_index(), Some(0));
    }

    #[test]
    fn select_previous_wraps() {
        let mut list = ConversationList::new(DisplayMode::Compact);
        list.push(make_conv("a", None, 0));
        list.push(make_conv("b", None, 0));

        assert_eq!(list.selected_index(), Some(0));
        list.select_previous();
        assert_eq!(list.selected_index(), Some(1));
    }

    #[test]
    fn truncate_str_short() {
        assert_eq!(truncate_str("hello", 10), "hello");
    }

    #[test]
    fn truncate_str_exact() {
        assert_eq!(truncate_str("hello", 5), "hello");
    }

    #[test]
    fn truncate_str_long() {
        assert_eq!(truncate_str("hello world!", 8), "hello...");
    }

    #[test]
    fn toggle_display_mode_cycles() {
        let mut list = ConversationList::new(DisplayMode::TwoLine);
        list.toggle_display_mode();
        assert!(matches!(list.display_mode(), DisplayMode::Compact));
        list.toggle_display_mode();
        assert!(matches!(list.display_mode(), DisplayMode::TwoLine));
    }

    #[test]
    fn civil_month_day_epoch() {
        // 1970-01-01
        let (m, d) = civil_month_day(0);
        assert_eq!((m, d), (1, 1));
    }

    #[test]
    fn civil_month_day_known_date() {
        // 2026-03-28 00:00:00 UTC = 1743120000
        let (m, d) = civil_month_day(1_743_120_000);
        assert_eq!((m, d), (3, 28));
    }

    #[test]
    fn push_auto_selects_first() {
        let mut list = ConversationList::new(DisplayMode::TwoLine);
        assert!(list.selected().is_none());
        list.push(make_conv("a", None, 0));
        assert_eq!(list.selected_index(), Some(0));
    }

    #[test]
    fn find_by_public_id_found_and_missing() {
        let mut list = ConversationList::new(DisplayMode::TwoLine);
        let conv = make_conv("a", None, 0);
        let pid = conv.public_id;
        list.push(conv);

        assert_eq!(list.find_by_public_id(&pid), Some(0));

        let other_id = Identity::generate();
        let other = other_id.public_id();
        assert_eq!(list.find_by_public_id(other), None);
    }
}
