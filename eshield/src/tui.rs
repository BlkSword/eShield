#![allow(dead_code)]

use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Terminal,
};
use std::io;
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[derive(Debug, Clone, serde::Deserialize)]
pub struct StatsSnapshot {
    pub total_dropped: u64,
    pub top_attackers: Vec<Attacker>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Attacker {
    pub ip: String,
    pub count: u64,
}

pub async fn run(endpoint: String) -> anyhow::Result<()> {
    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    crossterm::execute!(
        stdout,
        crossterm::terminal::EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let client = reqwest::blocking::Client::new();
    let mut last_draw = Instant::now();

    let stats_url = format!("{}/api/stats", endpoint.trim_end_matches('/'));
    let mut snapshot = client
        .get(&stats_url)
        .send()
        .ok()
        .and_then(|r| r.json().ok());
    terminal.draw(|f| draw(f, snapshot.as_ref()))?;

    loop {
        if last_draw.elapsed() >= Duration::from_millis(500) {
            snapshot = client
                .get(&stats_url)
                .send()
                .ok()
                .and_then(|r| r.json().ok());
            terminal.draw(|f| draw(f, snapshot.as_ref()))?;
            last_draw = Instant::now();
        }

        if crossterm::event::poll(Duration::from_millis(50))? {
            if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
                if key.code == crossterm::event::KeyCode::Char('q') {
                    break;
                }
            }
        }

        sleep(Duration::from_millis(16)).await;
    }

    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn draw(f: &mut ratatui::Frame, snapshot: Option<&StatsSnapshot>) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(f.area());

    let title = Paragraph::new("eShield // Host-Level CC Defense")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    let total_dropped = snapshot.map(|s| s.total_dropped).unwrap_or(0);
    let stats_text = format!(
        "Endpoint: {}\nDropped: {}\nTop Attackers: {}",
        "local eShield",
        total_dropped,
        snapshot.map(|s| s.top_attackers.len()).unwrap_or(0)
    );
    let stats_widget = Paragraph::new(stats_text)
        .block(Block::default().title("Statistics").borders(Borders::ALL));
    f.render_widget(stats_widget, chunks[1]);

    let mut top: Vec<(String, u64)> = snapshot
        .iter()
        .flat_map(|s| s.top_attackers.iter())
        .map(|a| (a.ip.clone(), a.count))
        .collect();
    top.sort_by_key(|item| std::cmp::Reverse(item.1));
    top.truncate(10);

    let rows: Vec<Row> = top
        .iter()
        .map(|(ip, count)| Row::new(vec![Cell::from(ip.clone()), Cell::from(count.to_string())]))
        .collect();

    let table = Table::new(
        rows,
        [Constraint::Percentage(50), Constraint::Percentage(50)],
    )
    .header(
        Row::new(vec!["Source IP", "Dropped Packets"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .title("Top Attackers")
            .borders(Borders::ALL),
    );
    f.render_widget(table, chunks[2]);

    let help = Paragraph::new("[q] Quit").block(Block::default().borders(Borders::ALL));
    f.render_widget(help, chunks[3]);
}
