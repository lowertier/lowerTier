use std::{
    io,
    os::fd::{AsRawFd, FromRawFd},
    sync::Arc,
};

use nix::libc;
use russh::{ChannelMsg, client};
use tokio::io::{AsyncWriteExt, DuplexStream};

struct PinnedHost(russh::keys::PublicKey);
impl client::Handler for PinnedHost {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(key.certificate().is_none() && key.public_key() == self.0)
    }
}

pub(super) async fn run(
    stream: DuplexStream,
    host: &str,
    user: &str,
    tty: bool,
    command: &[String],
) -> anyhow::Result<u8> {
    let host = russh::keys::PublicKey::from_openssh(host)?;
    let config = Arc::new(client::Config {
        window_size: 128 * 1024,
        maximum_packet_size: 32 * 1024,
        ..Default::default()
    });
    let mut session = client::connect_stream(config, stream, PinnedHost(host)).await?;
    anyhow::ensure!(
        session.authenticate_none(user).await?.success(),
        "The SSH account was rejected"
    );
    let mut channel = session.channel_open_session().await?;
    let mut input = TerminalInput::new(tty)?;
    if tty {
        let (columns, rows) = terminal_size();
        channel
            .request_pty(
                true,
                &std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into()),
                columns,
                rows,
                0,
                0,
                &[],
            )
            .await?;
    }
    if command.is_empty() {
        channel.request_shell(true).await?;
    } else {
        channel.exec(true, command.join(" ")).await?;
    }
    let mut resize = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())?;
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let mut bytes = [0; 16384];
    let mut eof = false;
    let mut code = 255;
    loop {
        tokio::select! {
            result = input.read(&mut bytes), if !eof => {
                let count = result?;
                if count == 0 { eof = true; channel.eof().await?; }
                else { channel.data(&bytes[..count]).await?; }
            }
            _ = resize.recv(), if tty => {
                let (columns, rows) = terminal_size();
                channel.window_change(columns, rows, 0, 0).await?;
            }
            message = channel.wait() => match message {
                Some(ChannelMsg::Data { data }) => { stdout.write_all(&data).await?; stdout.flush().await?; }
                Some(ChannelMsg::ExtendedData { data, ext: 1 }) => { stderr.write_all(&data).await?; stderr.flush().await?; }
                Some(ChannelMsg::ExitStatus { exit_status }) => { code = exit_status.min(255) as u8; }
                Some(ChannelMsg::Failure) => anyhow::bail!("The SSH request was rejected"),
                Some(ChannelMsg::Close) | None => break,
                _ => {}
            }
        }
    }
    let _ = session
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await;
    Ok(code)
}

fn terminal_size() -> (u32, u32) {
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(0, libc::TIOCGWINSZ as _, &mut size) } == 0 {
        (u32::from(size.ws_col.max(1)), u32::from(size.ws_row.max(1)))
    } else {
        (80, 24)
    }
}

// A duplicated descriptor shares file flags. Restore those flags before the CLI returns.
struct TerminalInput {
    file: std::fs::File,
    ready: Option<tokio::io::unix::AsyncFd<std::fs::File>>,
    flags: libc::c_int,
    term: Option<libc::termios>,
}
impl TerminalInput {
    fn new(raw: bool) -> io::Result<Self> {
        let descriptor = unsafe { libc::dup(0) };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { std::fs::File::from_raw_fd(descriptor) };
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut input = Self {
            file,
            ready: None,
            flags,
            term: None,
        };
        if raw && unsafe { libc::isatty(descriptor) } == 1 {
            let mut term = unsafe { std::mem::zeroed() };
            if unsafe { libc::tcgetattr(descriptor, &mut term) } != 0 {
                return Err(io::Error::last_os_error());
            }
            input.term = Some(term);
            unsafe {
                libc::cfmakeraw(&mut term);
            }
            if unsafe { libc::tcsetattr(descriptor, libc::TCSANOW, &term) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let metadata = input.file.metadata()?;
        let null = metadata.file_type().is_char_device()
            && std::fs::metadata("/dev/null").is_ok_and(|device| device.rdev() == metadata.rdev());
        if !metadata.is_file() && !null {
            match tokio::io::unix::AsyncFd::new(input.file.try_clone()?) {
                Ok(ready) => input.ready = Some(ready),
                Err(error) if error.raw_os_error() == Some(libc::EPERM) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(input)
    }
    async fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if let Some(ready) = &self.ready {
            loop {
                let mut guard = ready.readable().await?;
                match guard.try_io(|inner| std::io::Read::read(&mut inner.get_ref(), bytes)) {
                    Ok(result) => return result,
                    Err(_) => continue,
                }
            }
        }
        std::io::Read::read(&mut self.file, bytes)
    }
}
impl Drop for TerminalInput {
    fn drop(&mut self) {
        unsafe {
            libc::fcntl(self.file.as_raw_fd(), libc::F_SETFL, self.flags);
            if let Some(term) = &self.term {
                libc::tcsetattr(self.file.as_raw_fd(), libc::TCSANOW, term);
            }
        }
    }
}
