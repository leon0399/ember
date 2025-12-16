//! UI rendering for the TUI
//!
//! Provides the visual layout with:
//! - Conversation list on the left (1/3 width)
//! - Message view on the right (2/3 width)
//! - Input area at the bottom

use ratatui::{
    layout::{Alignment, Constraint, Direction, Flex, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};

use super::app::{AddContactField, App, Focus};

/// Render the entire UI
pub fn render(frame: &mut Frame, app: &App) {
    let area = frame.area();

    // Reserve bottom row for status bar
    let main_area = Rect {
        x: area.x,
        y: area.y,
        width: area.width,
        height: area.height.saturating_sub(1),
    };

    // Main layout: conversations (1/3) | messages (2/3)
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 3), Constraint::Ratio(2, 3)])
        .split(main_area);

    // Left panel: conversations
    render_conversations(frame, app, main_chunks[0]);

    // Right panel: messages + input
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(main_chunks[1]);

    render_messages(frame, app, right_chunks[0]);
    render_input(frame, app, right_chunks[1]);

    // Status bar at the very bottom
    render_status(frame, app);

    // Render popup on top if visible (covers status bar too)
    if app.show_add_contact_popup {
        render_add_contact_popup(frame, app);
    }
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

/// Calculate centered popup area
fn popup_area(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
    let vertical = Layout::vertical([Constraint::Percentage(percent_y)]).flex(Flex::Center);
    let horizontal = Layout::horizontal([Constraint::Percentage(percent_x)]).flex(Flex::Center);
    let [area] = vertical.areas(area);
    let [area] = horizontal.areas(area);
    area
}

/// Render the add contact popup
fn render_add_contact_popup(frame: &mut Frame, app: &App) {
    // Calculate popup area (60% width, 50% height, centered)
    let area = popup_area(frame.area(), 60, 50);

    // Clear the background
    frame.render_widget(Clear, area);

    // Popup container block
    let popup_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Add Contact ");

    let inner = popup_block.inner(area);
    frame.render_widget(popup_block, area);

    // Layout inside popup: instructions, public_id field, name field, error, buttons
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(2), // Instructions
            Constraint::Length(3), // Public ID label + input
            Constraint::Length(3), // Name label + input
            Constraint::Length(2), // Error message area
            Constraint::Length(1), // Button hints
        ])
        .split(inner);

    // Instructions
    let instructions =
        Paragraph::new("Enter contact's Public ID (64-char hex) and optional display name")
            .style(Style::default().fg(Color::DarkGray))
            .wrap(Wrap { trim: true });
    frame.render_widget(instructions, chunks[0]);

    // Public ID field
    let public_id_focused = app.add_contact_popup.focused_field == AddContactField::PublicId;
    let public_id_border_style = if public_id_focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let public_id_block = Block::default()
        .borders(Borders::ALL)
        .border_style(public_id_border_style)
        .title(" Public ID (required) ");
    let public_id_inner = public_id_block.inner(chunks[1]);
    frame.render_widget(public_id_block, chunks[1]);
    frame.render_widget(&app.add_contact_popup.public_id_input, public_id_inner);

    // Name field
    let name_focused = app.add_contact_popup.focused_field == AddContactField::Name;
    let name_border_style = if name_focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let name_block = Block::default()
        .borders(Borders::ALL)
        .border_style(name_border_style)
        .title(" Name (optional) ");
    let name_inner = name_block.inner(chunks[2]);
    frame.render_widget(name_block, chunks[2]);
    frame.render_widget(&app.add_contact_popup.name_input, name_inner);

    // Error message
    if let Some(ref error) = app.add_contact_popup.error {
        let error_text = Paragraph::new(error.as_str())
            .style(Style::default().fg(Color::Red))
            .wrap(Wrap { trim: true });
        frame.render_widget(error_text, chunks[3]);
    }

    // Button hints
    let hints = Paragraph::new("Tab: switch field | Enter: confirm | Esc: cancel")
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);
    frame.render_widget(hints, chunks[4]);
}
