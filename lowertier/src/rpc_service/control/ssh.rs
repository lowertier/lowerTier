use std::{collections::BTreeMap, io, os::fd::AsRawFd, process::Stdio, sync::Arc, time::Duration};

use anyhow::{Context, ensure};
use base64::{Engine, prelude::BASE64_STANDARD};
use nix::{
    libc,
    pty::{OpenptyResult, Winsize, openpty},
    unistd::User,
};
use russh::{
    Channel, ChannelId, Pty,
    server::{self, ChannelOpenHandle, Msg, Session},
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    process::Command,
    task::JoinSet,
};
use tokio_util::task::AbortOnDropHandle;

use super::{
    failure,
    remote::{Operation, ServerSession},
};
use crate::{common::config::ControlConfig, instance_manager::NetworkInstanceManager};

pub(super) struct SshStream {
    pub user: String,
    pub(super) full: bool,
    stream: DuplexStream,
    _task: AbortOnDropHandle<()>,
}

pub(super) async fn dispatch(
    _manager: &Arc<NetworkInstanceManager>,
    _instance: uuid::Uuid,
    session: &mut ServerSession,
    policy: &ControlConfig,
    secret: bool,
    operation: &Operation,
) -> anyhow::Result<Value> {
    let key = session.key.context("The SSH caller has no identity")?;
    let user = if operation.method == "SshOpen" {
        operation
            .payload
            .get("user")
            .and_then(Value::as_str)
            .context("An SSH account is required")?
            .to_owned()
    } else {
        session
            .ssh
            .as_ref()
            .context("The SSH stream is not open")?
            .user
            .clone()
    };
    if !policy.permits(
        &key,
        session.network_member,
        secret,
        "ssh",
        None,
        Some(&user),
        session.created.elapsed().as_secs(),
    ) {
        session.ssh = None;
        return Err(failure(
            "PERMISSION_DENIED",
            "The control policy denies this SSH account.",
            "control.grant.ssh_users",
        ));
    }
    let full = policy.permits(
        &key,
        session.network_member,
        secret,
        "admin",
        None,
        None,
        session.created.elapsed().as_secs(),
    );
    if session.ssh.as_ref().is_some_and(|ssh| ssh.full && !full) {
        session.ssh = None;
        return Err(failure(
            "PERMISSION_DENIED",
            "The SSH forwarding permission was revoked.",
            "control.allow",
        ));
    }
    match operation.method.as_str() {
        "SshOpen" => {
            ensure!(session.ssh.is_none(), "The SSH stream is already open");
            let account = User::from_name(&user)?.context("The SSH account does not exist")?;
            ensure!(
                nix::unistd::geteuid().is_root() || account.uid == nix::unistd::geteuid(),
                "The daemon cannot assume this SSH account"
            );
            let seed: [u8; 32] = rand::random();
            let host_key = russh::keys::PrivateKey::from(
                russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&seed),
            );
            let public = host_key.public_key().to_openssh()?;
            // This host key is delivered inside the pinned, authenticated Noise session.
            let config = Arc::new(server::Config {
                keys: vec![host_key],
                inactivity_timeout: Some(Duration::from_secs(120)),
                window_size: 128 * 1024,
                maximum_packet_size: 32 * 1024,
                channel_buffer_size: 4,
                event_buffer_size: 16,
                auth_rejection_time: Duration::from_secs(1),
                ..Default::default()
            });
            let (stream, server_stream) = tokio::io::duplex(128 * 1024);
            // Eight channel windows, packet queues, crypto scratch space, and duplex buffers fit this charge.
            let memory = crate::common::global_ctx::global_process_memory_governor()
                .try_reserve_owned(4 * 1024 * 1024)
                .context("The process memory budget cannot admit an SSH session")?;
            let handler = ShellHandler {
                _memory: memory,
                user: account,
                channels: BTreeMap::new(),
                tasks: JoinSet::new(),
                full,
            };
            let task = AbortOnDropHandle::new(tokio::spawn(async move {
                match server::run_stream(config, server_stream, handler).await {
                    Ok(session) => {
                        let _ = session.await;
                    }
                    Err(error) => tracing::debug!(%error, "SSH stream ended"),
                }
            }));
            session.ssh = Some(SshStream {
                user,
                full,
                stream,
                _task: task,
            });
            Ok(json!({ "host_key": public }))
        }
        "SshIo" => {
            let ssh = session.ssh.as_mut().unwrap();
            let data = operation
                .payload
                .get("data")
                .and_then(Value::as_str)
                .unwrap_or("");
            ensure!(data.len() <= 88 * 1024, "SSH input exceeds its limit");
            let data = BASE64_STANDARD.decode(data)?;
            if !data.is_empty() {
                tokio::time::timeout(Duration::from_secs(5), ssh.stream.write_all(&data)).await??;
            }
            if operation.payload.get("eof").and_then(Value::as_bool) == Some(true) {
                ssh.stream.shutdown().await?;
            }
            let mut output = vec![0; 64 * 1024];
            let count =
                match tokio::time::timeout(Duration::from_millis(50), ssh.stream.read(&mut output))
                    .await
                {
                    Ok(result) => Some(result?),
                    Err(_) => None,
                };
            Ok(
                json!({ "data": BASE64_STANDARD.encode(&output[..count.unwrap_or(0)]), "eof": count == Some(0) }),
            )
        }
        "SshClose" => {
            session.ssh = None;
            Ok(json!({}))
        }
        _ => Err(failure(
            "INVALID_ARGUMENT",
            "Unknown SSH operation.",
            "method",
        )),
    }
}

struct ShellChannel {
    channel: Option<Channel<Msg>>,
    pty: Option<OpenptyResult>,
    master: Option<Arc<std::fs::File>>,
    term: String,
    job: Option<tokio::task::AbortHandle>,
}

struct ShellHandler {
    _memory: crate::common::global_ctx::ProcessMemoryPermit,
    user: User,
    channels: BTreeMap<ChannelId, ShellChannel>,
    tasks: JoinSet<()>,
    full: bool,
}

struct ProcessGroup(i32);
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        // The shell and its descendants must stop when the authenticated session closes.
        unsafe {
            libc::kill(-self.0, libc::SIGKILL);
        }
    }
}

impl ShellHandler {
    fn start(
        &mut self,
        id: ChannelId,
        command: Option<&[u8]>,
        session: &mut Session,
    ) -> anyhow::Result<()> {
        let state = self
            .channels
            .get_mut(&id)
            .context("The SSH channel is not open")?;
        let channel = state
            .channel
            .take()
            .context("The SSH channel already has a process")?;
        let shell = if self.user.shell.as_os_str().is_empty() {
            std::path::Path::new("/bin/sh")
        } else {
            &self.user.shell
        };
        let mut process = Command::new(shell);
        if let Some(command) = command {
            process.arg("-c").arg(std::str::from_utf8(command)?);
        } else {
            process.arg("-l");
        }
        process
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
            .env("HOME", &self.user.dir)
            .env("USER", &self.user.name)
            .env("LOGNAME", &self.user.name)
            .env("SHELL", shell)
            .env("TERM", &state.term)
            .current_dir(&self.user.dir)
            .kill_on_drop(true);
        let uid = self.user.uid.as_raw();
        let gid = self.user.gid.as_raw();
        let groups = supplementary_groups(&self.user)?;
        let pty = state.pty.take();
        let is_pty = pty.is_some();
        let master = if let Some(pty) = pty {
            let master = Arc::new(std::fs::File::from(pty.master));
            let slave = std::fs::File::from(pty.slave);
            process
                .stdin(Stdio::from(slave.try_clone()?))
                .stdout(Stdio::from(slave.try_clone()?))
                .stderr(Stdio::from(slave));
            state.master = Some(master.clone());
            Some(master)
        } else {
            process
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            None
        };
        let root = nix::unistd::geteuid().is_root();
        unsafe {
            process.pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                if is_pty && libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if root {
                    if libc::setgroups(groups.len() as _, groups.as_ptr()) != 0
                        || libc::setgid(gid) != 0
                        || libc::setuid(uid) != 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut child = process.spawn()?;
        let pid = child.id().context("The SSH child has no process ID")? as i32;
        let group = ProcessGroup(pid);
        let handle = session.handle();
        while self.tasks.try_join_next().is_some() {}
        state.job = Some(self.tasks.spawn(async move {
            let _group = group;
            let id = channel.id();
            let mut channel = channel;
            let mut writer = channel.make_writer();
            let mut stderr = channel.make_writer_ext(Some(1));
            let mut reader = channel.make_reader();
            let io = async {
                if let Some(master) = master {
                    let read = master.try_clone()?;
                    let write = master.try_clone()?;
                    let read = AsyncPty::new(read)?;
                    let write = AsyncPty::new(write)?;
                    let (mut read, _) = tokio::io::split(read);
                    let (_, mut write) = tokio::io::split(write);
                    let input = tokio::io::copy(&mut reader, &mut write);
                    let output = async {
                        match tokio::io::copy(&mut read, &mut writer).await {
                            Err(error) if error.raw_os_error() != Some(libc::EIO) => Err(error),
                            _ => Ok(()),
                        }
                    };
                    tokio::pin!(input, output);
                    tokio::select! {
                        result = &mut input => { result?; output.await?; }
                        result = &mut output => { result?; }
                    }
                } else {
                    let mut input = child.stdin.take().unwrap();
                    let mut output = child.stdout.take().unwrap();
                    let mut errors = child.stderr.take().unwrap();
                    let input = async {
                        let result = tokio::io::copy(&mut reader, &mut input).await;
                        drop(input);
                        result
                    };
                    let output = tokio::io::copy(&mut output, &mut writer);
                    let errors = tokio::io::copy(&mut errors, &mut stderr);
                    tokio::pin!(input);
                    let output = async { tokio::try_join!(output, errors) };
                    tokio::pin!(output);
                    tokio::select! {
                        result = &mut input => { result?; output.await?; }
                        result = &mut output => { result?; }
                    }
                }
                Ok::<(), io::Error>(())
            };
            let _ = io.await;
            let status = child.wait().await;
            let code = status.ok().and_then(|status| status.code()).unwrap_or(255) as u32;
            let _ = handle.exit_status_request(id, code).await;
            let _ = handle.eof(id).await;
            let _ = handle.close(id).await;
        }));
        session.channel_success(id)?;
        Ok(())
    }
}

impl server::Handler for ShellHandler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, user: &str) -> anyhow::Result<server::Auth> {
        Ok(if user == self.user.name {
            server::Auth::Accept
        } else {
            server::Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _: &mut Session,
    ) -> anyhow::Result<()> {
        if self.channels.len() >= 8 {
            reply
                .reject(russh::ChannelOpenFailure::ResourceShortage)
                .await;
            return Ok(());
        }
        self.channels.insert(
            channel.id(),
            ShellChannel {
                channel: Some(channel),
                pty: None,
                master: None,
                term: "xterm-256color".into(),
                job: None,
            },
        );
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        id: ChannelId,
        term: &str,
        columns: u32,
        rows: u32,
        _: u32,
        _: u32,
        _: &[(Pty, u32)],
        session: &mut Session,
    ) -> anyhow::Result<()> {
        let state = self
            .channels
            .get_mut(&id)
            .context("The SSH channel is not open")?;
        if state.channel.is_none() || state.pty.is_some() || term.len() > 64 || term.contains('\0')
        {
            session.channel_failure(id)?;
            return Ok(());
        }
        let size = Winsize {
            ws_row: rows.clamp(1, 65535) as u16,
            ws_col: columns.clamp(1, 65535) as u16,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        state.pty = Some(openpty(Some(&size), None)?);
        state.term = term.to_owned();
        session.channel_success(id)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        id: ChannelId,
        command: &[u8],
        session: &mut Session,
    ) -> anyhow::Result<()> {
        if self.start(id, Some(command), session).is_err() {
            session.channel_failure(id)?;
        }
        Ok(())
    }

    async fn shell_request(&mut self, id: ChannelId, session: &mut Session) -> anyhow::Result<()> {
        if self.start(id, None, session).is_err() {
            session.channel_failure(id)?;
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        id: ChannelId,
        columns: u32,
        rows: u32,
        _: u32,
        _: u32,
        _: &mut Session,
    ) -> anyhow::Result<()> {
        if let Some(master) = self
            .channels
            .get(&id)
            .and_then(|state| state.master.as_ref())
        {
            let size = Winsize {
                ws_row: rows.clamp(1, 65535) as u16,
                ws_col: columns.clamp(1, 65535) as u16,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            unsafe {
                libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ as _, &size);
            }
        }
        Ok(())
    }

    async fn channel_close(&mut self, id: ChannelId, _: &mut Session) -> anyhow::Result<()> {
        if let Some(state) = self.channels.remove(&id) {
            if let Some(job) = state.job {
                job.abort();
            }
        }
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _: &str,
        _: u32,
        reply: ChannelOpenHandle,
        _: &mut Session,
    ) -> anyhow::Result<()> {
        while self.tasks.try_join_next().is_some() {}
        if self.channels.len() + self.tasks.len() >= 8 {
            reply
                .reject(russh::ChannelOpenFailure::ResourceShortage)
                .await;
            return Ok(());
        }
        if !self.full || port > 65535 {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        match tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::TcpStream::connect((host, port as u16)),
        )
        .await
        {
            Ok(Ok(mut socket)) => {
                reply.accept().await;
                self.tasks.spawn(async move {
                    let _ = tokio::io::copy_bidirectional(&mut channel.into_stream(), &mut socket)
                        .await;
                });
            }
            _ => {
                reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
            }
        }
        Ok(())
    }
}

#[cfg(target_vendor = "apple")]
fn supplementary_groups(user: &User) -> io::Result<Vec<libc::gid_t>> {
    let name = std::ffi::CString::new(user.name.as_bytes())?;
    let mut groups = vec![0i32; 64];
    let mut count = groups.len() as i32;
    let mut result = unsafe {
        libc::getgrouplist(
            name.as_ptr(),
            user.gid.as_raw() as i32,
            groups.as_mut_ptr(),
            &mut count,
        )
    };
    if result < 0 && (1..=4096).contains(&count) {
        groups.resize(count as usize, 0);
        result = unsafe {
            libc::getgrouplist(
                name.as_ptr(),
                user.gid.as_raw() as i32,
                groups.as_mut_ptr(),
                &mut count,
            )
        };
    }
    if result < 0 || count < 0 || count as usize > groups.len() {
        return Err(io::Error::other("Cannot read the SSH account groups"));
    }
    groups.truncate(count as usize);
    Ok(groups
        .into_iter()
        .map(|group| group as libc::gid_t)
        .collect())
}

#[cfg(not(target_vendor = "apple"))]
fn supplementary_groups(user: &User) -> io::Result<Vec<libc::gid_t>> {
    Ok(
        nix::unistd::getgrouplist(&std::ffi::CString::new(user.name.as_bytes())?, user.gid)?
            .into_iter()
            .map(|group| group.as_raw())
            .collect(),
    )
}

struct AsyncPty(tokio::io::unix::AsyncFd<std::fs::File>);
impl AsyncPty {
    fn new(file: std::fs::File) -> io::Result<Self> {
        use nix::fcntl::{FcntlArg, OFlag, fcntl};
        fcntl(file.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
        Ok(Self(tokio::io::unix::AsyncFd::new(file)?))
    }
}
impl tokio::io::AsyncRead for AsyncPty {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        loop {
            let mut guard = std::task::ready!(self.0.poll_read_ready(cx))?;
            match guard.try_io(|file| {
                std::io::Read::read(&mut file.get_ref(), buffer.initialize_unfilled())
            }) {
                Ok(Ok(size)) => {
                    buffer.advance(size);
                    return std::task::Poll::Ready(Ok(()));
                }
                Ok(Err(error)) => return std::task::Poll::Ready(Err(error)),
                Err(_) => continue,
            }
        }
    }
}
impl tokio::io::AsyncWrite for AsyncPty {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        loop {
            let mut guard = std::task::ready!(self.0.poll_write_ready(cx))?;
            match guard.try_io(|file| std::io::Write::write(&mut file.get_ref(), buffer)) {
                Ok(result) => return std::task::Poll::Ready(result),
                Err(_) => continue,
            }
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Pinned(russh::keys::PublicKey);
    impl russh::client::Handler for Pinned {
        type Error = russh::Error;
        async fn check_server_key(
            &mut self,
            key: &russh::keys::PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(key.certificate().is_none() && key.public_key() == self.0)
        }
    }

    #[tokio::test]
    async fn pty_output_and_exit_status_survive_closed_client_input() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let user = User::from_uid(nix::unistd::geteuid()).unwrap().unwrap();
            let name = user.name.clone();
            let key = russh::keys::PrivateKey::from(
                russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[59; 32]),
            );
            let public = key.public_key().clone();
            let config = Arc::new(server::Config {
                keys: vec![key],
                ..Default::default()
            });
            let memory = crate::common::global_ctx::global_process_memory_governor()
                .try_reserve_owned(4 * 1024 * 1024)
                .unwrap();
            let handler = ShellHandler {
                _memory: memory,
                user,
                channels: BTreeMap::new(),
                tasks: JoinSet::new(),
                full: false,
            };
            let (client, server) = tokio::io::duplex(128 * 1024);
            let _server = AbortOnDropHandle::new(tokio::spawn(async move {
                server::run_stream(config, server, handler)
                    .await
                    .unwrap()
                    .await
                    .unwrap();
            }));
            let mut client = russh::client::connect_stream(
                Arc::new(russh::client::Config::default()),
                client,
                Pinned(public),
            )
            .await
            .unwrap();
            assert!(client.authenticate_none(&name).await.unwrap().success());
            let mut channel = client.channel_open_session().await.unwrap();
            channel
                .request_pty(true, "xterm", 87, 31, 0, 0, &[])
                .await
                .unwrap();
            channel
                .exec(true, "stty size; printf terminal-output; exit 7")
                .await
                .unwrap();
            channel.eof().await.unwrap();
            let mut output = Vec::new();
            let mut code = None;
            while let Some(message) = channel.wait().await {
                match message {
                    russh::ChannelMsg::Data { data } => output.extend_from_slice(&data),
                    russh::ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
                    _ => {}
                }
            }
            assert_eq!(code, Some(7));
            let output = String::from_utf8(output).unwrap();
            assert!(output.contains("31 87"), "{output:?}");
            assert!(output.contains("terminal-output"), "{output:?}");
        })
        .await
        .unwrap();
    }
}
