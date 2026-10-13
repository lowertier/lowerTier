use clap::Parser;
use lowertier::connector::tracker_discovery::server::TrackerServer;
use std::net::SocketAddr;

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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let options = Options::parse();
    let server = TrackerServer::new(options.interval)?;
    let mut tasks = tokio::task::JoinSet::new();
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
        tasks.spawn(server.clone().serve_udp(udp));
    }
    for address in options.http_listen {
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
        let http = tokio::net::TcpListener::from_std(socket.into())?;
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
