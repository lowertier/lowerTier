use super::Socks5Command;
use super::new_udp_header;
use super::parse_udp_request;
use super::read_exact;
use super::util::target_addr::{TargetAddr, read_address};
use super::{ReplyError, Result, SocksError, consts};
use anyhow::Context;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use tokio::io::AsyncReadExt;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::task::JoinSet;

use tracing::{debug, error, info, trace};

const CONNECT_TIMEOUT_SECONDS: u64 = 10;

#[async_trait::async_trait]
pub trait ProxyTcpStream: AsyncRead + AsyncWrite + Unpin + Send + Sync + Sized {
    async fn transfer<I>(mut self, inbound: &mut I) -> Result<()>
    where
        I: AsyncRead + AsyncWrite + Unpin + Send,
    {
        match tokio::io::copy_bidirectional(inbound, &mut self).await {
            Ok(result) => info!("transfer closed ({}, {})", result.0, result.1),
            Err(error) => error!("transfer error: {:?}", error),
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl ProxyTcpStream for TcpStream {}

#[async_trait::async_trait]
pub trait AsyncTcpConnector: Send + Sync {
    type S: ProxyTcpStream;

    async fn tcp_connect(&self, addr: SocketAddr, timeout_s: u64) -> Result<Self::S>;

    async fn tcp_connect_target(&self, target: TargetAddr, timeout_s: u64) -> Result<Self::S> {
        let address = match target.resolve_dns().await? {
            TargetAddr::Ip(address) => address,
            TargetAddr::Domain(_, _) => unreachable!("DNS resolution returned a domain"),
        };
        self.tcp_connect(address, timeout_s).await
    }
}

#[async_trait::async_trait]
pub trait AsyncUdpSocket: Send + Sync {
    async fn send(&self, data: &[u8]) -> io::Result<usize>;
    async fn recv(&self, data: &mut [u8]) -> io::Result<usize>;
}

#[async_trait::async_trait]
pub trait AsyncUdpConnector: Send + Sync {
    type S: AsyncUdpSocket + 'static;

    async fn udp_connect(&self, addr: SocketAddr, timeout_s: u64) -> Result<Self::S>;

    async fn udp_connect_target(
        &self,
        target: TargetAddr,
        timeout_s: u64,
    ) -> Result<(Self::S, SocketAddr)> {
        let address = match target.resolve_dns().await? {
            TargetAddr::Ip(address) => address,
            TargetAddr::Domain(_, _) => unreachable!("DNS resolution returned a domain"),
        };
        Ok((self.udp_connect(address, timeout_s).await?, address))
    }
}

/// Serve the unauthenticated local proxy. The connector owns DNS and destination policy.
pub(crate) struct Socks5Socket<
    T: AsyncRead + AsyncWrite + Unpin,
    C: AsyncTcpConnector + AsyncUdpConnector,
> {
    inner: T,

    target_addr: Option<TargetAddr>,
    cmd: Option<Socks5Command>,
    /// Socket address which will be used in the reply message.
    reply_ip: IpAddr,
    tcp_connector: C,
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send, C: AsyncTcpConnector + AsyncUdpConnector>
    Socks5Socket<T, C>
{
    pub(crate) fn new(socket: T, reply_ip: IpAddr, tcp_connector: C) -> Self {
        Socks5Socket {
            inner: socket,
            target_addr: None,
            cmd: None,
            reply_ip,
            tcp_connector,
        }
    }

    pub(crate) async fn serve(mut self) -> Result<()> {
        let methods = self.get_methods().await?;
        self.negotiate_method(methods).await?;

        match self.request().await {
            Ok(_) => {}
            Err(SocksError::ReplyError(e)) => {
                // If a reply error has been returned, we send it to the client
                self.reply_error(&e).await?;
                return Err(e.into()); // propagate the error to end this connection's task
            }
            // if any other errors has been detected, we simply end connection's task
            Err(d) => return Err(d),
        };

        Ok(())
    }

    /// Read the client's offered methods before selecting the local proxy method.
    async fn get_methods(&mut self) -> Result<Vec<u8>> {
        trace!("Socks5Socket: get_methods()");
        // read the first 2 bytes which contains the SOCKS version and the methods len()
        let [version, methods_len] =
            read_exact!(self.inner, [0u8; 2]).context("Can't read methods")?;
        debug!(
            "Handshake headers: [version: {version}, methods len: {len}]",
            version = version,
            len = methods_len,
        );

        if version != consts::SOCKS5_VERSION {
            return Err(SocksError::UnsupportedSocksVersion(version));
        }

        // {METHODS available from the client}
        // eg. (non-auth) {0, 1}
        // eg. (auth)     {0, 1, 2}
        let methods = read_exact!(self.inner, vec![0u8; methods_len as usize])
            .context("Can't get methods.")?;
        debug!("methods supported sent by the client: {:?}", &methods);

        // Return methods available
        Ok(methods)
    }

    async fn negotiate_method(&mut self, client_methods: Vec<u8>) -> Result<()> {
        let accepted = client_methods.contains(&consts::SOCKS5_AUTH_METHOD_NONE);
        let method = if accepted {
            consts::SOCKS5_AUTH_METHOD_NONE
        } else {
            consts::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE
        };
        self.inner
            .write_all(&[consts::SOCKS5_VERSION, method])
            .await
            .context("Cannot send the SOCKS5 method reply")?;
        if !accepted {
            return Err(SocksError::AuthMethodUnacceptable(client_methods));
        }
        Ok(())
    }

    /// Wrapper to principally cover ReplyError types for both functions read & execute request.
    async fn request(&mut self) -> Result<()> {
        self.read_command().await?;

        self.execute_command().await
    }

    /// Reply error to the client with the reply code according to the RFC.
    async fn reply_error(&mut self, error: &ReplyError) -> Result<()> {
        let reply = new_reply(error, "0.0.0.0:0".parse().unwrap());
        debug!("reply error to be written: {:?}", &reply);

        self.inner
            .write(&reply)
            .await
            .context("Can't write the reply!")?;

        self.inner.flush().await.context("Can't flush the reply!")?;

        Ok(())
    }

    /// Decide to whether or not, accept the authentication method.
    /// Don't forget that the methods list sent by the client, contains one or more methods.
    ///
    /// # Request
    /// ```text
    ///          +----+-----+-------+------+----------+----------+
    ///          |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    ///          +----+-----+-------+------+----------+----------+
    ///          | 1  |  1  |   1   |  1   | Variable |    2     |
    ///          +----+-----+-------+------+----------+----------+
    /// ```
    ///
    /// It the request is correct, it should returns a ['SocketAddr'].
    ///
    async fn read_command(&mut self) -> Result<()> {
        let [version, cmd, rsv, address_type] =
            read_exact!(self.inner, [0u8; 4]).context("Malformed request")?;
        debug!(
            "Request: [version: {version}, command: {cmd}, rev: {rsv}, address_type: {address_type}]",
            version = version,
            cmd = cmd,
            rsv = rsv,
            address_type = address_type,
        );

        if version != consts::SOCKS5_VERSION {
            return Err(SocksError::UnsupportedSocksVersion(version));
        }

        match Socks5Command::from_u8(cmd) {
            None => return Err(ReplyError::CommandNotSupported.into()),
            Some(cmd) => match cmd {
                Socks5Command::TCPConnect => {
                    self.cmd = Some(cmd);
                }
                Socks5Command::UDPAssociate => self.cmd = Some(cmd),
                Socks5Command::TCPBind => return Err(ReplyError::CommandNotSupported.into()),
            },
        }

        // Guess address type
        let target_addr = read_address(&mut self.inner, address_type)
            .await
            .map_err(|e| {
                // print explicit error
                error!("{:#}", e);
                // then convert it to a reply
                ReplyError::AddressTypeNotSupported
            })?;

        self.target_addr = Some(target_addr);

        debug!("Request target is {}", self.target_addr.as_ref().unwrap());

        Ok(())
    }

    /// Execute the socks5 command that the client wants.
    async fn execute_command(&mut self) -> Result<()> {
        match &self.cmd {
            None => Err(ReplyError::CommandNotSupported.into()),
            Some(cmd) => match cmd {
                Socks5Command::TCPBind => Err(ReplyError::CommandNotSupported.into()),
                Socks5Command::TCPConnect => return self.execute_command_connect().await,
                Socks5Command::UDPAssociate => self.execute_command_udp_assoc().await,
            },
        }
    }

    /// Connect to the target address that the client wants,
    /// then forward the data between them (client <=> target address).
    async fn execute_command_connect(&mut self) -> Result<()> {
        // async-std's ToSocketAddrs doesn't supports external trait implementation
        // @see https://github.com/async-rs/async-std/issues/539
        let target = self
            .target_addr
            .as_ref()
            .context("target_addr empty")?
            .clone();

        // TCP connect with timeout, to avoid memory leak for connection that takes forever
        let outbound = self
            .tcp_connector
            .tcp_connect_target(target, CONNECT_TIMEOUT_SECONDS)
            .await?;

        debug!("Connected to remote destination");

        self.inner
            .write(&new_reply(
                &ReplyError::Succeeded,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
            ))
            .await
            .context("Can't write successful reply")?;

        self.inner.flush().await.context("Can't flush the reply!")?;

        debug!("Wrote success");

        outbound.transfer(&mut self.inner).await
    }

    /// Bind to a random UDP port, wait for the traffic from
    /// the client, and then forward the data to the remote addr.
    async fn execute_command_udp_assoc(&mut self) -> Result<()> {
        // The DST.ADDR and DST.PORT fields contain the address and port that
        // the client expects to use to send UDP datagrams on for the
        // association. The server MAY use this information to limit access
        // to the association.
        // @see Page 6, https://datatracker.ietf.org/doc/html/rfc1928.
        //
        // We do NOT limit the access from the client currently in this implementation.
        let _not_used = self.target_addr.as_ref();

        // Listen with UDP6 socket, so the client can connect to it with either
        // IPv4 or IPv6.
        let peer_sock = UdpSocket::bind("[::]:0").await?;

        // Respect the pre-populated reply IP address.
        self.inner
            .write(&new_reply(
                &ReplyError::Succeeded,
                SocketAddr::new(self.reply_ip, peer_sock.local_addr()?.port()),
            ))
            .await
            .context("Can't write successful reply")?;

        debug!("Wrote success");

        let connector = &self.tcp_connector;
        let control = &mut self.inner;
        tokio::select! {
            result = transfer_udp(peer_sock, connector, CONNECT_TIMEOUT_SECONDS) => result?,
            result = wait_for_control_close(control) => result?,
        }

        Ok(())
    }
}

const MAX_UDP_ASSOCIATION_TARGETS: usize = 256;

async fn wait_for_control_close<T: AsyncRead + Unpin>(control: &mut T) -> Result<()> {
    let mut buffer = [0_u8; 1024];
    while control.read(&mut buffer).await? != 0 {}
    Ok(())
}

async fn transfer_udp<C: AsyncUdpConnector>(
    inbound: UdpSocket,
    connector: &C,
    timeout_s: u64,
) -> Result<()> {
    let inbound = Arc::new(inbound);
    let client_addr = Arc::new(OnceLock::<SocketAddr>::new());
    let mut targets = HashMap::<TargetAddr, Arc<C::S>>::new();
    let mut response_tasks = JoinSet::new();
    let mut buffer = vec![0_u8; 8192];

    loop {
        let (size, source_addr) = inbound.recv_from(&mut buffer).await?;
        let expected_source = *client_addr.get_or_init(|| source_addr);
        if source_addr != expected_source {
            debug!("Discard a SOCKS5 UDP packet from a second client.");
            continue;
        }

        let (fragment, target, data) = parse_udp_request(&buffer[..size]).await?;
        if fragment != 0 {
            debug!("Discard a fragmented SOCKS5 UDP packet.");
            continue;
        }

        let target_socket = if let Some(socket) = targets.get(&target) {
            socket.clone()
        } else {
            if targets.len() >= MAX_UDP_ASSOCIATION_TARGETS {
                return Err(anyhow::anyhow!("The SOCKS5 UDP target limit was reached.").into());
            }
            let (socket, resolved_target) = connector
                .udp_connect_target(target.clone(), timeout_s)
                .await?;
            let socket = Arc::new(socket);
            targets.insert(target, socket.clone());

            let response_socket = socket.clone();
            let response_inbound = inbound.clone();
            let response_client_addr = client_addr.clone();
            response_tasks.spawn(async move {
                let mut response_buffer = vec![0_u8; 8192];
                loop {
                    let size = response_socket.recv(&mut response_buffer).await?;
                    let mut response = new_udp_header(resolved_target)?;
                    response.extend_from_slice(&response_buffer[..size]);
                    let Some(client_addr) = response_client_addr.get().copied() else {
                        continue;
                    };
                    response_inbound.send_to(&response, client_addr).await?;
                }
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            });
            socket
        };

        target_socket.send(data).await?;
    }
}

/// Generate reply code according to the RFC.
fn new_reply(error: &ReplyError, sock_addr: SocketAddr) -> Vec<u8> {
    let (addr_type, mut ip_oct, mut port) = match sock_addr {
        SocketAddr::V4(sock) => (
            consts::SOCKS5_ADDR_TYPE_IPV4,
            sock.ip().octets().to_vec(),
            sock.port().to_be_bytes().to_vec(),
        ),
        SocketAddr::V6(sock) => (
            consts::SOCKS5_ADDR_TYPE_IPV6,
            sock.ip().octets().to_vec(),
            sock.port().to_be_bytes().to_vec(),
        ),
    };

    let mut reply = vec![
        consts::SOCKS5_VERSION,
        error.as_u8(), // transform the error into byte code
        0x00,          // reserved
        addr_type,     // address type (ipv4, v6, domain)
    ];
    reply.append(&mut ip_oct);
    reply.append(&mut port);

    reply
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::{io::DuplexStream, net::TcpListener, sync::mpsc, time::timeout};

    struct Connector {
        address: SocketAddr,
        targets: mpsc::UnboundedSender<(TargetAddr, u64)>,
    }

    #[async_trait::async_trait]
    impl AsyncTcpConnector for Connector {
        type S = TcpStream;

        async fn tcp_connect(&self, addr: SocketAddr, timeout_s: u64) -> Result<Self::S> {
            assert_eq!(timeout_s, 10);
            Ok(TcpStream::connect(addr).await?)
        }

        async fn tcp_connect_target(&self, target: TargetAddr, timeout_s: u64) -> Result<Self::S> {
            self.targets.send((target, timeout_s)).unwrap();
            self.tcp_connect(self.address, timeout_s).await
        }
    }

    struct Datagram(UdpSocket);

    #[async_trait::async_trait]
    impl AsyncUdpSocket for Datagram {
        async fn send(&self, data: &[u8]) -> io::Result<usize> {
            self.0.send(data).await
        }

        async fn recv(&self, data: &mut [u8]) -> io::Result<usize> {
            self.0.recv(data).await
        }
    }

    #[async_trait::async_trait]
    impl AsyncUdpConnector for Connector {
        type S = Datagram;

        async fn udp_connect(&self, addr: SocketAddr, timeout_s: u64) -> Result<Self::S> {
            assert_eq!(timeout_s, 10);
            let socket = UdpSocket::bind("127.0.0.1:0").await?;
            socket.connect(addr).await?;
            Ok(Datagram(socket))
        }

        async fn udp_connect_target(
            &self,
            target: TargetAddr,
            timeout_s: u64,
        ) -> Result<(Self::S, SocketAddr)> {
            self.targets.send((target, timeout_s)).unwrap();
            Ok((
                self.udp_connect(self.address, timeout_s).await?,
                self.address,
            ))
        }
    }

    async fn negotiate(client: &mut DuplexStream) {
        client.write_all(&[5, 2, 2, 0]).await.unwrap();
        let mut response = [0; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [5, 0]);
    }

    #[tokio::test]
    async fn connect_preserves_domain_policy_and_transfers_both_directions() {
        timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let echo = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut data = [0; 5];
                stream.read_exact(&mut data).await.unwrap();
                assert_eq!(&data, b"probe");
                stream.write_all(b"reply").await.unwrap();
            });
            let (targets, mut received) = mpsc::unbounded_channel();
            let (mut client, server) = tokio::io::duplex(2048);
            let service = tokio::spawn(
                Socks5Socket::new(
                    server,
                    Ipv4Addr::LOCALHOST.into(),
                    Connector { address, targets },
                )
                .serve(),
            );
            negotiate(&mut client).await;
            let target = TargetAddr::Domain("policy.invalid".into(), 443);
            let mut command = vec![5, 1, 0];
            command.extend(target.to_be_bytes().unwrap());
            client.write_all(&command).await.unwrap();
            let mut reply = [0; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply[..4], &[5, 0, 0, 1]);
            assert_eq!(received.recv().await.unwrap(), (target, 10));
            client.write_all(b"probe").await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"reply");
            service.await.unwrap().unwrap();
            echo.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn unsupported_methods_and_bind_never_reach_the_connector() {
        timeout(Duration::from_secs(5), async {
            for greeting in [vec![5, 1, 2], vec![5, 0], vec![5, 1, 0]] {
                let (targets, mut received) = mpsc::unbounded_channel();
                let (mut client, server) = tokio::io::duplex(128);
                let service = tokio::spawn(
                    Socks5Socket::new(
                        server,
                        Ipv4Addr::LOCALHOST.into(),
                        Connector {
                            address: "127.0.0.1:9".parse().unwrap(),
                            targets,
                        },
                    )
                    .serve(),
                );
                client.write_all(&greeting).await.unwrap();
                let mut reply = [0; 2];
                client.read_exact(&mut reply).await.unwrap();
                if greeting == [5, 1, 0] {
                    assert_eq!(reply, [5, 0]);
                    client.write_all(&[5, 2, 0, 1]).await.unwrap();
                    let mut reply = [0; 10];
                    client.read_exact(&mut reply).await.unwrap();
                    assert_eq!(&reply[..4], &[5, 7, 0, 1]);
                    assert!(matches!(
                        service.await.unwrap(),
                        Err(SocksError::ReplyError(ReplyError::CommandNotSupported))
                    ));
                } else {
                    assert_eq!(reply, [5, 255]);
                    assert!(matches!(
                        service.await.unwrap(),
                        Err(SocksError::AuthMethodUnacceptable(_))
                    ));
                }
                assert!(received.recv().await.is_none());
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn udp_associate_preserves_domain_policy_and_ends_with_control_connection() {
        timeout(Duration::from_secs(5), async {
            let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = echo.local_addr().unwrap();
            let (targets, mut received) = mpsc::unbounded_channel();
            let (mut client, server) = tokio::io::duplex(128);
            let service = tokio::spawn(
                Socks5Socket::new(
                    server,
                    Ipv4Addr::LOCALHOST.into(),
                    Connector { address, targets },
                )
                .serve(),
            );
            negotiate(&mut client).await;
            client
                .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut reply = [0; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply[..8], &[5, 0, 0, 1, 127, 0, 0, 1]);
            let port = u16::from_be_bytes([reply[8], reply[9]]);
            let datagram = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target = TargetAddr::Domain("policy.invalid".into(), 53);
            let mut packet = vec![0, 0, 0];
            packet.extend(target.to_be_bytes().unwrap());
            packet.extend_from_slice(b"probe");
            datagram
                .send_to(&packet, ("127.0.0.1", port))
                .await
                .unwrap();
            let mut buffer = [0; 128];
            let (size, source) = echo.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..size], b"probe");
            assert_eq!(received.recv().await.unwrap(), (target, 10));
            echo.send_to(b"reply", source).await.unwrap();
            let size = datagram.recv(&mut buffer).await.unwrap();
            let (fragment, source, payload) = parse_udp_request(&buffer[..size]).await.unwrap();
            assert_eq!(fragment, 0);
            assert_eq!(source, TargetAddr::Ip(address));
            assert_eq!(payload, b"reply");
            drop(client);
            service.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }
}
