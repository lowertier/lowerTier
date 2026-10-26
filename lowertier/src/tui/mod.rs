//! `lowertier top`: a read-only live dashboard.

use std::time::Duration;

use crate::cli::{
    client::Client,
    error::{CliError, Result},
};

#[cfg(feature = "tui")]
mod data;
#[cfg(feature = "tui")]
mod state;
#[cfg(feature = "tui")]
mod ui;

#[cfg(feature = "tui")]
fn key(event: ratatui::crossterm::event::KeyEvent) -> Option<state::Key> {
    use ratatui::crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
    if event.kind == KeyEventKind::Release {
        return None;
    }
    Some(match event.code {
        KeyCode::Char('c') if event.modifiers.contains(KeyModifiers::CONTROL) => {
            state::Key::Interrupt
        }
        KeyCode::Char(character) => state::Key::Char(character),
        KeyCode::Up => state::Key::Up,
        KeyCode::Down => state::Key::Down,
        KeyCode::Home => state::Key::Home,
        KeyCode::End => state::Key::End,
        KeyCode::Tab => state::Key::Tab,
        KeyCode::BackTab => state::Key::BackTab,
        KeyCode::Enter => state::Key::Enter,
        KeyCode::Esc => state::Key::Esc,
        KeyCode::Backspace => state::Key::Backspace,
        _ => return None,
    })
}

#[cfg(feature = "tui")]
pub async fn run(client: Client, interval: Duration) -> Result<()> {
    use ratatui::crossterm::event;
    use state::{App, Event, reduce};
    use tokio::sync::mpsc;

    let terminal_error = |error: std::io::Error| {
        CliError::new(
            "internal",
            format!("Cannot use the terminal: {error}"),
            "top",
        )
    };
    // try_init enters the alternate screen and restores the terminal on panic.
    let mut terminal = ratatui::try_init().map_err(terminal_error)?;
    let (events, mut received) = mpsc::channel::<Event>(64);
    let poller = tokio::spawn(data::poll(client, interval, events.clone()));
    // crossterm reads keys with blocking calls, so they get their own thread.
    let keys = events.clone();
    std::thread::spawn(move || {
        while !keys.is_closed() {
            match event::poll(Duration::from_millis(200)) {
                Ok(true) => {
                    if let Ok(event::Event::Key(pressed)) = event::read()
                        && let Some(key) = key(pressed)
                        && keys.blocking_send(Event::Key(key)).is_err()
                    {
                        return;
                    }
                }
                Ok(false) => {}
                Err(_) => return,
            }
        }
    });
    drop(events);

    let mut app = App::default();
    let mut redraw = tokio::time::interval(Duration::from_millis(250));
    let result = loop {
        if let Err(error) = terminal.draw(|frame| ui::draw(frame, &app)) {
            break Err(terminal_error(error));
        }
        tokio::select! {
            event = received.recv() => match event {
                Some(event) => reduce(&mut app, event),
                None => break Ok(()),
            },
            _ = redraw.tick() => {}
        }
        while let Ok(event) = received.try_recv() {
            reduce(&mut app, event);
        }
        if app.quit {
            break Ok(());
        }
    };
    poller.abort();
    drop(received);
    ratatui::restore();
    result
}

#[cfg(not(feature = "tui"))]
pub async fn run(_: Client, _: Duration) -> Result<()> {
    Err(CliError::new(
        "invalid_argument",
        "This build has no dashboard. Rebuild with the tui feature.",
        "top",
    ))
}
