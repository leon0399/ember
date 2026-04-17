//! UI rendering for the TUI
//!
//! Provides the visual layout with:
//! - Conversation list on the left (1/3 width)
//! - Message view on the right (2/3 width)
//! - Input area at the bottom

use ratatui::{
    layout::{Alignment, Constraint, Flex, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};
use ratatui_macros::{horizontal, vertical};

use super::app::{
    AddContactField, AddUpstreamField, App, DeliveryStatus, Focus, PopupKind, UpstreamType,
};
use ember_transport::DeliveryTier;

/// Render the entire UI
pub fn render(frame: &mut Frame, app: &mut App) {
    let area = frame.area();

    // Reserve bottom row for status bar
    let main_area = Rect {
        x: area.x,
        y: area.y,
        width: area.width,
        height: area.height.saturating_sub(1),
    };

    // Main layout: conversations (1/3) | messages (2/3)
    let [conversations_area, right_area] = horizontal![==1/3, ==2/3].areas(main_area);
    render_conversations(frame, app, conversations_area);

    // Right panel: messages + input
    let [messages_area, input_area] = vertical![>=3, ==3].areas(right_area);
    render_messages(frame, app, messages_area);
    render_input(frame, app, input_area);

    // Status bar at the very bottom
    render_status(frame, app);

    // Render popups on top if visible (covers status bar too)
    if let Some(ref popup) = app.active_popup {
        match popup {
            PopupKind::AddContact(_) => render_add_contact_popup(frame, app),
            PopupKind::MyIdentity => render_my_id_popup(frame, app),
            PopupKind::AddUpstream(_) => render_add_upstream_popup(frame, app),
            PopupKind::ViewUpstreams => render_upstreams_popup(frame, app),
        }
    }
}

/// Render the conversation list (delegates to `ConversationList::render`)
fn render_conversations(frame: &mut Frame, app: &mut App, area: Rect) {
    let is_focused = app.focus == Focus::Conversations;
    app.conversation_list.render(frame, area, is_focused);
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
    let title = if let Some(conv) = app.conversation_list.selected() {
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

            // Delivery status indicator (sent messages only)
            if msg.from_me {
                match &msg.status {
                    DeliveryStatus::None => {}
                    DeliveryStatus::Sending => {
                        lines.push(Line::from(Span::styled(
                            "  sending...",
                            Style::default()
                                .fg(Color::DarkGray)
                                .add_modifier(Modifier::ITALIC),
                        )));
                    }
                    DeliveryStatus::Sent(phase) => {
                        lines.push(Line::from(Span::styled(
                            format!("  \u{2713} {phase}"),
                            Style::default().fg(Color::DarkGray),
                        )));
                    }
                    DeliveryStatus::Failed(err) => {
                        lines.push(Line::from(Span::styled(
                            format!("  ! Failed: {err}"),
                            Style::default().fg(Color::Red),
                        )));
                    }
                }
            }

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

    // Slash command completion popup (rendered above the input area).
    app.command_completion.render(frame, area);

    // Ghost text overlay: dimmed suffix of the selected completion candidate.
    let (row, col) = app.input.cursor();
    if row == 0 {
        let cursor_x = inner
            .x
            .saturating_add(u16::try_from(col).unwrap_or(u16::MAX));
        let cursor_y = inner.y;
        app.command_completion
            .render_ghost_text(frame, (cursor_x, cursor_y));
    }
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

    // Build status line with optional LAN peer count
    let id_display = app.my_short_id();
    let lan_indicator = if app.lan_discovery_enabled {
        let count = app.lan_peer_count();
        format!(" LAN:{count}")
    } else {
        String::new()
    };
    let status_text = format!(" [{}]{} {} ", id_display, lan_indicator, app.status);

    let status =
        Paragraph::new(status_text).style(Style::default().bg(Color::DarkGray).fg(Color::White));

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
    let Some(PopupKind::AddContact(ref popup)) = app.active_popup else {
        return;
    };

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
    let [instructions_area, public_id_area, name_area, error_area, hints_area] =
        vertical![==1, ==3, ==3, ==1, ==1].margin(1).areas(inner);

    // Instructions
    let instructions =
        Paragraph::new("Enter contact's Public ID (64-char hex) and optional display name")
            .style(Style::default().fg(Color::DarkGray))
            .wrap(Wrap { trim: true });
    frame.render_widget(instructions, instructions_area);

    // Public ID field
    let public_id_focused = popup.focused_field == AddContactField::PublicId;
    let public_id_border_style = if public_id_focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let public_id_block = Block::default()
        .borders(Borders::ALL)
        .border_style(public_id_border_style)
        .title(" Public ID (required) ");
    let public_id_inner = public_id_block.inner(public_id_area);
    frame.render_widget(public_id_block, public_id_area);
    frame.render_widget(&popup.public_id_input, public_id_inner);

    // Name field
    let name_focused = popup.focused_field == AddContactField::Name;
    let name_border_style = if name_focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let name_block = Block::default()
        .borders(Borders::ALL)
        .border_style(name_border_style)
        .title(" Name (optional) ");
    let name_inner = name_block.inner(name_area);
    frame.render_widget(name_block, name_area);
    frame.render_widget(&popup.name_input, name_inner);

    // Error message
    if let Some(ref error) = popup.error {
        let error_text = Paragraph::new(error.as_str())
            .style(Style::default().fg(Color::Red))
            .wrap(Wrap { trim: true });
        frame.render_widget(error_text, error_area);
    }

    // Button hints
    let hints = Paragraph::new("Tab: switch field | Enter: confirm | Esc: cancel")
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);
    frame.render_widget(hints, hints_area);
}

/// Render the "My Identity" popup
fn render_my_id_popup(frame: &mut Frame, app: &App) {
    if !matches!(app.active_popup, Some(PopupKind::MyIdentity)) {
        return;
    }

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
    let [label_area, id_area, hints_area] = vertical![==1, ==3, ==1].margin(1).areas(inner);

    // Label
    let label = Paragraph::new("Your Public ID (share with others):")
        .style(Style::default().fg(Color::White));
    frame.render_widget(label, label_area);

    // Full Public ID in a bordered box for easy copying
    let full_id = app.my_full_id();
    let id_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));
    let id_inner = id_block.inner(id_area);
    frame.render_widget(id_block, id_area);

    let id_text = Paragraph::new(full_id)
        .style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center);
    frame.render_widget(id_text, id_inner);

    // Hints
    let hints = Paragraph::new("Esc to close")
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);
    frame.render_widget(hints, hints_area);
}

/// Render the add upstream popup
#[expect(
    clippy::too_many_lines,
    reason = "popup layout is easier to follow when rendered in one place"
)]
fn render_add_upstream_popup(frame: &mut Frame, app: &App) {
    let Some(PopupKind::AddUpstream(ref popup)) = app.active_popup else {
        return;
    };

    // Fixed height: border(2) + margin(2) + instructions(1) + type(3) + tier(3) + url(3) + error(1) + hints(1) = 16
    let area = popup_area_fixed(frame.area(), 60, 16);

    // Clear the background
    frame.render_widget(Clear, area);

    // Popup container block
    let popup_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Add Upstream ");

    let inner = popup_block.inner(area);
    frame.render_widget(popup_block, area);

    // Layout inside popup: instructions, type selector, tier selector, URL field, error, buttons
    let [instructions_area, type_area, tier_area, url_area, error_area, hints_area] =
        vertical![==1, ==3, ==3, ==3, ==1, ==1]
            .margin(1)
            .areas(inner);

    // Instructions
    let instructions = Paragraph::new("Add HTTP or MQTT upstream for this session")
        .style(Style::default().fg(Color::DarkGray))
        .wrap(Wrap { trim: true });
    frame.render_widget(instructions, instructions_area);

    // Type selector
    let type_focused = popup.focused_field == AddUpstreamField::Type;
    let type_border_style = if type_focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let http_style = if popup.transport_type == UpstreamType::Http {
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let mqtt_style = if popup.transport_type == UpstreamType::Mqtt {
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD)
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
    let type_inner = type_block.inner(type_area);
    frame.render_widget(type_block, type_area);

    let type_selector = Paragraph::new(type_line).alignment(Alignment::Center);
    frame.render_widget(type_selector, type_inner);

    // Tier selector
    let tier_focused = popup.focused_field == AddUpstreamField::Tier;
    let tier_border_style = if tier_focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let direct_style = if popup.tier == DeliveryTier::Direct {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let quorum_style = if popup.tier == DeliveryTier::Quorum {
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let besteffort_style = if popup.tier == DeliveryTier::BestEffort {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let tier_line = Line::from(vec![
        Span::styled("[", Style::default().fg(Color::DarkGray)),
        Span::styled(" Direct ", direct_style),
        Span::styled("]", Style::default().fg(Color::DarkGray)),
        Span::raw(" "),
        Span::styled("[", Style::default().fg(Color::DarkGray)),
        Span::styled(" Quorum ", quorum_style),
        Span::styled("]", Style::default().fg(Color::DarkGray)),
        Span::raw(" "),
        Span::styled("[", Style::default().fg(Color::DarkGray)),
        Span::styled(" Best-Effort ", besteffort_style),
        Span::styled("]", Style::default().fg(Color::DarkGray)),
    ]);

    let tier_block = Block::default()
        .borders(Borders::ALL)
        .border_style(tier_border_style)
        .title(" Tier (←/→ to switch) ");
    let tier_inner = tier_block.inner(tier_area);
    frame.render_widget(tier_block, tier_area);

    let tier_selector = Paragraph::new(tier_line).alignment(Alignment::Center);
    frame.render_widget(tier_selector, tier_inner);

    // URL field
    let url_focused = popup.focused_field == AddUpstreamField::Url;
    let url_border_style = if url_focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let url_block = Block::default()
        .borders(Borders::ALL)
        .border_style(url_border_style)
        .title(" URL ");
    let url_inner = url_block.inner(url_area);
    frame.render_widget(url_block, url_area);
    frame.render_widget(&popup.url_input, url_inner);

    // Error message
    if let Some(ref error) = popup.error {
        let error_text = Paragraph::new(error.as_str())
            .style(Style::default().fg(Color::Red))
            .wrap(Wrap { trim: true });
        frame.render_widget(error_text, error_area);
    }

    // Button hints
    let hints = Paragraph::new("Tab: switch | ←/→: select | Enter: add | Esc: cancel")
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);
    frame.render_widget(hints, hints_area);
}

/// Render the view upstreams popup
#[expect(
    clippy::too_many_lines,
    reason = "upstream list rendering is easier to audit as one layout pass"
)]
fn render_upstreams_popup(frame: &mut Frame, app: &App) {
    use ember_transport::HealthState;

    if !matches!(app.active_popup, Some(PopupKind::ViewUpstreams)) {
        return;
    }

    // Query the registry for current targets
    let targets = app.registry.list_all_targets();

    // Calculate height based on number of upstreams (clamp to 1-12 rows)
    #[allow(clippy::cast_possible_truncation)] // List clamped to max 12 items
    let list_height = (targets.len() as u16).clamp(1, 12);
    // Total: border(2) + margin(2) + list + legend(2) + hints(1) + padding(1) = 8 + list_height
    let total_height = 8 + list_height;
    let area = popup_area_fixed(frame.area(), 80, total_height);

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
    let [list_area, legend_area, hints_area] = vertical![>=1, ==2, ==1].margin(1).areas(inner);

    // Build upstream list
    if targets.is_empty() {
        let empty_text = Paragraph::new("No upstreams configured")
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Center);
        frame.render_widget(empty_text, list_area);
    } else {
        let items: Vec<ListItem> = targets
            .iter()
            .map(|enriched| {
                // Derive transport type from target ID prefix
                let transport_type = enriched.snapshot.transport_type();
                let type_str = transport_type.to_uppercase();

                // Health status indicator
                let (health_icon, health_style) = match enriched.snapshot.health {
                    HealthState::Healthy => ("●", Style::default().fg(Color::Green)),
                    HealthState::Degraded => ("◐", Style::default().fg(Color::Yellow)),
                    HealthState::Unhealthy => ("○", Style::default().fg(Color::Red)),
                    HealthState::Unknown => ("?", Style::default().fg(Color::DarkGray)),
                };

                let tier_str = match enriched.tier {
                    DeliveryTier::Quorum => "Q",
                    DeliveryTier::Direct => "D",
                    DeliveryTier::BestEffort => "B",
                };
                let type_style = match transport_type {
                    "http" => Style::default().fg(Color::Blue),
                    "mqtt" => Style::default().fg(Color::Magenta),
                    "embedded" => Style::default().fg(Color::Yellow),
                    _ => Style::default().fg(Color::White),
                };
                let tier_style = match enriched.tier {
                    DeliveryTier::Quorum => Style::default().fg(Color::Green),
                    DeliveryTier::Direct => Style::default().fg(Color::Cyan),
                    DeliveryTier::BestEffort => Style::default().fg(Color::Yellow),
                };
                // Add asterisk for ephemeral (runtime-added) upstreams
                let ephemeral_marker = if enriched.ephemeral { "*" } else { "" };

                // Use display_label which prefers custom_label over snapshot label
                let display_label = enriched.display_label();
                let address = enriched.snapshot.address();

                // Show label if different from address
                let label_part = if display_label == address {
                    String::new()
                } else {
                    format!(" ({display_label})")
                };

                // Latency info (if available)
                let latency_str = if enriched.snapshot.avg_latency_ms > 0 {
                    format!(" {}ms", enriched.snapshot.avg_latency_ms)
                } else {
                    String::new()
                };

                // Failure count (if any)
                let failure_str = if enriched.snapshot.consecutive_failures > 0 {
                    format!(" {}x", enriched.snapshot.consecutive_failures)
                } else {
                    String::new()
                };

                let line = Line::from(vec![
                    Span::styled(health_icon, health_style),
                    Span::raw(" "),
                    Span::styled(format!("[{type_str}]"), type_style),
                    Span::raw(" "),
                    Span::styled(address, Style::default().fg(Color::White)),
                    Span::styled(label_part, Style::default().fg(Color::DarkGray)),
                    Span::styled(latency_str, Style::default().fg(Color::DarkGray)),
                    Span::styled(failure_str, Style::default().fg(Color::Red)),
                    Span::raw(" "),
                    Span::styled(format!("[{tier_str}{ephemeral_marker}]"), tier_style),
                ]);

                ListItem::new(line)
            })
            .collect();

        let list = List::new(items);
        frame.render_widget(list, list_area);
    }

    // Legend: health + tier explanations (2 lines)
    let legend_lines = vec![
        Line::from(vec![
            Span::styled("●", Style::default().fg(Color::Green)),
            Span::raw("=healthy "),
            Span::styled("◐", Style::default().fg(Color::Yellow)),
            Span::raw("=degraded "),
            Span::styled("○", Style::default().fg(Color::Red)),
            Span::raw("=unhealthy  "),
            Span::raw("*"),
            Span::raw("=runtime"),
        ]),
        Line::from(vec![
            Span::styled("D", Style::default().fg(Color::Cyan)),
            Span::raw("=direct "),
            Span::styled("Q", Style::default().fg(Color::Green)),
            Span::raw("=quorum "),
            Span::styled("B", Style::default().fg(Color::Yellow)),
            Span::raw("=best-effort"),
        ]),
    ];
    let legend_para = Paragraph::new(legend_lines).alignment(Alignment::Center);
    frame.render_widget(legend_para, legend_area);

    // Hints
    let hints = Paragraph::new("Esc to close")
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);
    frame.render_widget(hints, hints_area);
}
