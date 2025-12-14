//! UI rendering for the TUI
//!
//! Provides the visual layout with:
//! - Conversation list on the left (1/3 width)
//! - Message view on the right (2/3 width)
//! - Input area at the bottom

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};

use super::app::{App, Focus};

/// Render the entire UI
pub fn render(frame: &mut Frame, app: &App) {
    // Main layout: conversations (1/3) | messages (2/3)
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 3), Constraint::Ratio(2, 3)])
        .split(frame.area());

    // Left panel: conversations
    render_conversations(frame, app, main_chunks[0]);

    // Right panel: messages + input
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(main_chunks[1]);

    render_messages(frame, app, right_chunks[0]);
    render_input(frame, app, right_chunks[1]);

    // Status bar at the very bottom (overlay)
    render_status(frame, app);
}

/// Render the conversation list
fn render_conversations(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.focus == Focus::Conversations;

    let items: Vec<ListItem> = app
        .conversations
        .iter()
        .enumerate()
        .map(|(i, conv)| {
            let style = if i == app.selected_conversation {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            // Show unread indicator
            let unread = if conv.unread_count > 0 {
                format!(" ({})", conv.unread_count)
            } else {
                String::new()
            };

            let content = Line::from(vec![
                Span::styled(&conv.name, style),
                Span::styled(unread, Style::default().fg(Color::Red)),
            ]);

            ListItem::new(content)
        })
        .collect();

    let border_style = if is_focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let title = format!(" Conversations ({}) ", app.conversations.len());
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(border_style)
                .title(title),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    // We need to render with state for highlighting
    frame.render_widget(list, area);
}

/// Render the message view
fn render_messages(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.focus == Focus::Messages;

    let border_style = if is_focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    // Get conversation name for title
    let title = if let Some(conv) = app.conversations.get(app.selected_conversation) {
        format!(" {} ", conv.name)
    } else {
        " Messages ".to_string()
    };

    // Build message lines
    let mut lines: Vec<Line> = Vec::new();

    if app.messages.is_empty() {
        lines.push(Line::from(Span::styled(
            "No messages yet. Press Enter to start chatting!",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        for msg in &app.messages {
            // Sender line
            let sender_style = if msg.from_me {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(Color::Blue)
                    .add_modifier(Modifier::BOLD)
            };

            lines.push(Line::from(vec![
                Span::styled(&msg.sender_name, sender_style),
                Span::styled(
                    format!("  {}", msg.timestamp),
                    Style::default().fg(Color::DarkGray),
                ),
            ]));

            // Message content
            let content_style = Style::default().fg(Color::White);
            lines.push(Line::from(Span::styled(&msg.content, content_style)));

            // Empty line between messages
            lines.push(Line::from(""));
        }
    }

    let messages = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(border_style)
                .title(title),
        )
        .wrap(Wrap { trim: false })
        .scroll((app.message_scroll, 0));

    frame.render_widget(messages, area);
}

/// Render the input area
fn render_input(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.focus == Focus::Input;

    let border_style = if is_focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    // Create a block for the input
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(" Message ");

    // Calculate inner area for textarea
    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Render the textarea widget
    frame.render_widget(&app.input, inner);
}

/// Render the status bar
fn render_status(frame: &mut Frame, app: &App) {
    let area = frame.area();

    // Status bar at bottom
    let status_area = Rect {
        x: 0,
        y: area.height.saturating_sub(1),
        width: area.width,
        height: 1,
    };

    // Build status line
    let id_display = app.my_short_id();
    let status_text = format!(" [{}] {} ", id_display, app.status);

    let status = Paragraph::new(status_text)
        .style(Style::default().bg(Color::DarkGray).fg(Color::White));

    frame.render_widget(Clear, status_area);
    frame.render_widget(status, status_area);
}
