use std::io;
use std::time::{Duration, Instant};
use std::sync::mpsc;

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

pub struct IdsState {
    pub packet_count: u64,
    pub alert_count: u64,
    pub alerts: Vec<String>,
    pub last_packet_info: String,
}

pub enum IdsMessage {
    PacketProcessed,
    Alert(String),
    #[allow(dead_code)] // Silencia aviso se não usarmos Info por enquanto
    Info(String),
}

pub fn run_tui(rx: mpsc::Receiver<IdsMessage>) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = IdsState {
        packet_count: 0,
        alert_count: 0,
        alerts: Vec::new(),
        last_packet_info: String::from("Aguardando tráfego..."),
    };

    let tick_rate = Duration::from_millis(100);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| ui(f, &state))?;

        while let Ok(msg) = rx.try_recv() {
            match msg {
                IdsMessage::PacketProcessed => state.packet_count += 1,
                IdsMessage::Alert(s) => {
                    state.alert_count += 1;
                    if state.alerts.len() >= 20 {
                        state.alerts.remove(0);
                    }
                    state.alerts.push(s);
                }
                IdsMessage::Info(s) => state.last_packet_info = s,
            }
        }

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if let KeyCode::Char('q') = key.code {
                    break;
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}

fn ui(f: &mut Frame, state: &IdsState) {
    // CORREÇÃO: f.size() -> f.area()
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Min(10),
        ])
        .split(f.area()); 

    let title = Paragraph::new("🔥 CYBERKIT IDS MONITOR - [Pressione 'q' para sair]")
        .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    let stats_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    let pkt_info = Paragraph::new(format!("Pacotes Analisados: {}", state.packet_count))
        .block(Block::default().title("Tráfego Total").borders(Borders::ALL));
    f.render_widget(pkt_info, stats_chunks[0]);

    let alert_info = Paragraph::new(format!("Ameaças Detectadas: {}", state.alert_count))
        .style(Style::default().fg(if state.alert_count > 0 { Color::Red } else { Color::Green }))
        .block(Block::default().title("Status de Segurança").borders(Borders::ALL));
    f.render_widget(alert_info, stats_chunks[1]);

    let alerts: Vec<ListItem> = state.alerts
        .iter()
        .map(|m| ListItem::new(Line::from(vec![Span::raw("🚨 "), Span::styled(m, Style::default().fg(Color::Yellow))])))
        .collect();

    let alerts_list = List::new(alerts)
        .block(Block::default().title("Log de Alertas em Tempo Real").borders(Borders::ALL))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));
    
    f.render_widget(alerts_list, chunks[2]);
}