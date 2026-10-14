use clap::Parser;
use lowertier_tracker::server::TrackerServer;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Parser)]
#[command(about = "Serve minimal LowTier rendezvous through UDP and HTTP tracker discovery")]
struct Options {
    #[arg(long, value_delimiter = ',', default_value = "0.0.0.0:16969")]
    udp_listen: Vec<SocketAddr>,
    #[arg(long, value_delimiter = ',', default_value = "127.0.0.1:16969")]
    http_listen: Vec<SocketAddr>,
    #[arg(long, default_value_t = 2)]
    interval: u32,
    #[arg(long)]
    trusted_proxy: Vec<cidr::IpCidr>,
    #[arg(long, default_value = "X-Real-IP")]
    client_ip_header: String,
    #[arg(long, value_delimiter = ',')]
    stun_tcp_listen: Vec<SocketAddr>,
    #[arg(long)]
    stun_change_port: bool,
    #[arg(long)]
    passkey_file: Option<std::path::PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let options = Options::parse();
    let passkey = options
        .passkey_file
        .as_ref()
        .map(std::fs::read_to_string)
        .transpose()?;
    let server = TrackerServer::with_passkey(options.interval, passkey.as_deref().map(str::trim))?;
    let mut tasks = tokio::task::JoinSet::new();
    let mut sockets = Vec::new();
    for address in options.udp_listen {
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(address),
            socket2::Type::DGRAM,
            None,
        )?;
        if address.is_ipv6() {
            socket.set_only_v6(true)?;
        }
        socket.set_nonblocking(true)?;
        socket.bind(&address.into())?;
        let udp = tokio::net::UdpSocket::from_std(socket.into())?;
        eprintln!("Rendezvous UDP={}", udp.local_addr()?);
        sockets.push((udp.local_addr()?, Arc::new(udp)));
    }
    for (address, socket) in &sockets {
        let alternate = if options.stun_change_port {
            Some(
                sockets
                    .iter()
                    .find(|(other, _)| other.ip() == address.ip() && other.port() != address.port())
                    .ok_or_else(|| {
                        anyhow::anyhow!("CHANGE-PORT requires two UDP ports on each address")
                    })?
                    .1
                    .clone(),
            )
        } else {
            None
        };
        tasks.spawn(
            server
                .clone()
                .serve_udp_with_alternate(socket.clone(), alternate),
        );
    }
    for address in options.stun_tcp_listen {
        let listener = tcp_listener(address)?;
        eprintln!("Binding TCP={}", listener.local_addr()?);
        tasks.spawn(server.clone().serve_stun_tcp(listener));
    }
    for address in options.http_listen {
        let http = tcp_listener(address)?;
        eprintln!("Rendezvous HTTP={}/announce", http.local_addr()?);
        tasks.spawn(server.clone().serve_http(
            http,
            options.trusted_proxy.clone(),
            options.client_ip_header.clone(),
        ));
    }
    tokio::select! {
        result = tasks.join_next() => result.ok_or_else(|| anyhow::anyhow!("no rendezvous listeners"))??,
        result = tokio::signal::ctrl_c() => { result?; Ok(()) }
    }
}

fn tcp_listener(address: SocketAddr) -> anyhow::Result<tokio::net::TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(address),
        socket2::Type::STREAM,
        None,
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(128)?;
    Ok(tokio::net::TcpListener::from_std(socket.into())?)
}
