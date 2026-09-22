use clap::Parser;
use lowertier::connector::tracker_discovery::server::TrackerServer;
use std::net::SocketAddr;

#[derive(Parser)]
#[command(about = "Serve bounded UDP and HTTP tracker discovery for LowTier")]
struct Options {
    #[arg(long, default_value = "0.0.0.0:6969")]
    udp_listen: SocketAddr,
    #[arg(long, default_value = "127.0.0.1:6970")]
    http_listen: SocketAddr,
    #[arg(long, default_value_t = 1800)]
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
    let udp = tokio::net::UdpSocket::bind(options.udp_listen).await?;
    let http = tokio::net::TcpListener::bind(options.http_listen).await?;
    eprintln!(
        "Tracker UDP={} HTTP={}/announce",
        udp.local_addr()?,
        http.local_addr()?
    );
    tokio::select! {
        result = server.clone().serve_udp(udp) => result,
        result = server.serve_http(http, options.trusted_proxy, options.client_ip_header) => result,
        result = tokio::signal::ctrl_c() => { result?; Ok(()) }
    }
}
