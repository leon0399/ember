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

use super::app::{AddContactField, AddUpstreamField, App, Focus, UpstreamSource, UpstreamType};

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

    // Render popups on top if visible (covers status bar too)
    if app.show_add_contact_popup {
        render_add_contact_popup(frame, app);
    }
    if app.show_my_id_popup {
        render_my_id_popup(frame, app);
    }
    if app.show_add_upstream_popup {
        render_add_upstream_popup(frame, app);
    }
    if app.show_upstreams_popup {
        render_upstreams_popup(frame, app);
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

/// Calculate centered popup area with fixed height
fn popup_area_fixed(area: Rect, percent_x: u16, min_height: u16) -> Rect {
    // Use fixed height, capped to available space
    let height = min_height.min(area.height);
    let vertical = Layout::vertical([Constraint::Length(height)]).flex(Flex::Center);
    let horizontal = Layout::horizontal([Constraint::Percentage(percent_x)]).flex(Flex::Center);
    let [area] = vertical.areas(area);
    let [area] = horizontal.areas(area);
    area
}

/// Render the add contact popup
fn render_add_contact_popup(frame: &mut Frame, app: &App) {
    // Fixed height: border(2) + margin(2) + instructions(1) + public_id(3) + name(3) + error(1) + hints(1) = 13
    let area = popup_area_fixed(frame.area(), 60, 13);

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
            Constraint::Length(1), // Instructions
            Constraint::Length(3), // Public ID label + input
            Constraint::Length(3), // Name label + input
            Constraint::Length(1), // Error message area
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

/// Render the "My Identity" popup
fn render_my_id_popup(frame: &mut Frame, app: &App) {
    // Fixed height: border(2) + margin(2) + label(1) + id_box(3) + hints(1) = 9
    let area = popup_area_fixed(frame.area(), 70, 9);

    // Clear the background
    frame.render_widget(Clear, area);

    // Popup container block
    let popup_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" My Identity ");

    let inner = popup_block.inner(area);
    frame.render_widget(popup_block, area);

    // Layout inside popup
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(1), // Label
            Constraint::Length(3), // Public ID (with border)
            Constraint::Length(1), // Hints
        ])
        .split(inner);

    // Label
    let label = Paragraph::new("Your Public ID (share with others):")
        .style(Style::default().fg(Color::White));
    frame.render_widget(label, chunks[0]);

    // Full Public ID in a bordered box for easy copying
    let full_id = app.my_full_id();
    let id_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));
    let id_inner = id_block.inner(chunks[1]);
    frame.render_widget(id_block, chunks[1]);

    let id_text = Paragraph::new(full_id)
        .style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center);
    frame.render_widget(id_text, id_inner);

    // Hints
    let hints = Paragraph::new("Esc to close")
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);
    frame.render_widget(hints, chunks[2]);
}

/// Render the add upstream popup
fn render_add_upstream_popup(frame: &mut Frame, app: &App) {
    // Fixed height: border(2) + margin(2) + instructions(1) + type(3) + url(3) + error(1) + hints(1) = 13
    let area = popup_area_fixed(frame.area(), 60, 13);

    // Clear the background
    frame.render_widget(Clear, area);

    // Popup container block
    let popup_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Add Upstream ");

    let inner = popup_block.inner(area);
    frame.render_widget(popup_block, area);

    // Layout inside popup: instructions, type selector, URL field, error, buttons
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(1), // Instructions
            Constraint::Length(3), // Type selector
            Constraint::Length(3), // URL input
            Constraint::Length(1), // Error message area
            Constraint::Length(1), // Button hints
        ])
        .split(inner);

    // Instructions
    let instructions =
        Paragraph::new("Add HTTP or MQTT upstream for this session")
            .style(Style::default().fg(Color::DarkGray))
            .wrap(Wrap { trim: true });
    frame.render_widget(instructions, chunks[0]);

    // Type selector
    let type_focused = app.add_upstream_popup.focused_field == AddUpstreamField::Type;
    let type_border_style = if type_focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let http_style = if app.add_upstream_popup.transport_type == UpstreamType::Http {
        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let mqtt_style = if app.add_upstream_popup.transport_type == UpstreamType::Mqtt {
        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let type_line = Line::from(vec![
        Span::styled("[", Style::default().fg(Color::DarkGray)),
        Span::styled(" HTTP ", http_style),
        Span::styled("]", Style::default().fg(Color::DarkGray)),
        Span::raw("  "),
        Span::styled("[", Style::default().fg(Color::DarkGray)),
        Span::styled(" MQTT ", mqtt_style),
        Span::styled("]", Style::default().fg(Color::DarkGray)),
    ]);

    let type_block = Block::default()
        .borders(Borders::ALL)
        .border_style(type_border_style)
        .title(" Type (←/→ to switch) ");
    let type_inner = type_block.inner(chunks[1]);
    frame.render_widget(type_block, chunks[1]);

    let type_selector = Paragraph::new(type_line).alignment(Alignment::Center);
    frame.render_widget(type_selector, type_inner);

    // URL field
    let url_focused = app.add_upstream_popup.focused_field == AddUpstreamField::Url;
    let url_border_style = if url_focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let url_block = Block::default()
        .borders(Borders::ALL)
        .border_style(url_border_style)
        .title(" URL ");
    let url_inner = url_block.inner(chunks[2]);
    frame.render_widget(url_block, chunks[2]);
    frame.render_widget(&app.add_upstream_popup.url_input, url_inner);

    // Error message
    if let Some(ref error) = app.add_upstream_popup.error {
        let error_text = Paragraph::new(error.as_str())
            .style(Style::default().fg(Color::Red))
            .wrap(Wrap { trim: true });
        frame.render_widget(error_text, chunks[3]);
    }

    // Button hints
    let hints = Paragraph::new("Tab: switch | ←/→: type | Enter: add | Esc: cancel")
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);
    frame.render_widget(hints, chunks[4]);
}

/// Render the view upstreams popup
fn render_upstreams_popup(frame: &mut Frame, app: &App) {
    // Calculate height based on number of upstreams (min 5, max 15 rows for list)
    let list_height = (app.upstreams.len() as u16).clamp(1, 12);
    // Total: border(2) + margin(2) + title_row(1) + list + hints(1) = 6 + list_height
    let total_height = 6 + list_height;
    let area = popup_area_fixed(frame.area(), 70, total_height);

    // Clear the background
    frame.render_widget(Clear, area);

    // Popup container block
    let popup_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Configured Upstreams ");

    let inner = popup_block.inner(area);
    frame.render_widget(popup_block, area);

    // Layout inside popup
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Min(1),    // Upstream list
            Constraint::Length(1), // Hints
        ])
        .split(inner);

    // Build upstream list
    if app.upstreams.is_empty() {
        let empty_text = Paragraph::new("No upstreams configured")
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Center);
        frame.render_widget(empty_text, chunks[0]);
    } else {
        let items: Vec<ListItem> = app
            .upstreams
            .iter()
            .map(|upstream| {
                let type_str = match upstream.transport_type {
                    UpstreamType::Http => "HTTP",
                    UpstreamType::Mqtt => "MQTT",
                };
                let source_str = match upstream.source {
                    UpstreamSource::Config => "config",
                    UpstreamSource::Ephemeral => "session",
                };
                let type_style = match upstream.transport_type {
                    UpstreamType::Http => Style::default().fg(Color::Blue),
                    UpstreamType::Mqtt => Style::default().fg(Color::Magenta),
                };
                let source_style = match upstream.source {
                    UpstreamSource::Config => Style::default().fg(Color::Green),
                    UpstreamSource::Ephemeral => Style::default().fg(Color::Yellow),
                };

                let label_part = if let Some(ref label) = upstream.label {
                    format!(" ({})", label)
                } else {
                    String::new()
                };

                let line = Line::from(vec![
                    Span::styled(format!("[{}]", type_str), type_style),
                    Span::raw(" "),
                    Span::styled(&upstream.url, Style::default().fg(Color::White)),
                    Span::styled(label_part, Style::default().fg(Color::DarkGray)),
                    Span::raw(" "),
                    Span::styled(format!("[{}]", source_str), source_style),
                ]);

                ListItem::new(line)
            })
            .collect();

        let list = List::new(items);
        frame.render_widget(list, chunks[0]);
    }

    // Hints
    let hints = Paragraph::new("Esc to close")
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);
    frame.render_widget(hints, chunks[1]);
}
