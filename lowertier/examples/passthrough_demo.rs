//! Local H2/TLS passthrough demo: three verified 512 KiB downloads through a
//! real LowTier TCP listener. No TUN, root access, or external service required.
//! `challenges.cloudflare.com` is SNI only. The in-memory test certificate is
//! trusted explicitly by this client, not installed in the system trust store.

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use lowertier::{
    common::config::gen_default_flags,
    tunnel::{TunnelListener, tcp::TcpTunnelListener},
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::task::AbortOnDropHandle;

const HOST: &str = "challenges.cloudflare.com";
const TRIALS: usize = 3;
const BODY_BYTES: usize = 512 * 1024;
const BURST_SAMPLE_BYTES: usize = 32 * 1024;

async fn serve(socket: TcpStream, acceptor: TlsAcceptor, body: Bytes) -> Result<()> {
    let tls = acceptor.accept(socket).await.context("origin TLS")?;
    let mut connection = h2::server::handshake(tls).await.context("origin H2")?;
    let (request, mut response) = connection.accept().await.context("missing request")??;
    ensure!(request.uri().path() == "/demo", "unexpected request path");
    let headers = http::Response::builder()
        .status(http::StatusCode::OK)
        .header("content-length", body.len())
        .header("content-type", "application/octet-stream")
        .body(())?;
    response
        .send_response(headers, false)?
        .send_data(body, true)?;
    connection.graceful_shutdown();
    // Keep driving the bounded 512 KiB response until the client closes. The
    // client below verifies status, length, and every byte before reporting.
    while connection.accept().await.is_some() {}
    Ok(())
}

async fn download(
    trial: usize,
    public: SocketAddr,
    connector: &TlsConnector,
    expected: &Bytes,
) -> Result<()> {
    let start = Instant::now();
    let socket = TcpStream::connect(public).await?;
    let tls = connector
        .connect(ServerName::try_from(HOST)?, socket)
        .await?;
    ensure!(
        tls.get_ref().1.alpn_protocol() == Some(b"h2"),
        "H2 ALPN missing"
    );
    let handshake = start.elapsed();
    let (mut requests, connection) = h2::client::handshake(tls).await?;
    let _driver = AbortOnDropHandle::new(tokio::spawn(connection));
    let request = http::Request::get(format!("https://{HOST}/demo")).body(())?;
    let (response, _) = requests.send_request(request, true)?;
    let response = response.await?;
    ensure!(
        response.status() == http::StatusCode::OK,
        "unexpected HTTP status"
    );
    ensure!(
        response.headers()["content-length"] == BODY_BYTES.to_string(),
        "wrong content length"
    );
    let mut stream = response.into_body();
    let mut received = Vec::with_capacity(BODY_BYTES);
    let mut first_burst = None;
    while let Some(data) = stream.data().await {
        let data = data?;
        ensure!(
            received.len() + data.len() <= BODY_BYTES,
            "oversized response"
        );
        received.extend_from_slice(&data);
        stream.flow_control().release_capacity(data.len())?;
        if received.len() >= BURST_SAMPLE_BYTES && first_burst.is_none() {
            first_burst = Some((received.len(), start.elapsed()));
        }
    }
    ensure!(
        received.as_slice() == expected.as_ref(),
        "payload mismatch or truncation"
    );
    let elapsed = start.elapsed();
    // The entire TLS flow, not just the application body, shares the 128 KiB/s
    // per-IP bucket with a 64 KiB burst. New TCP connections don't reset it.
    ensure!(
        elapsed >= Duration::from_millis(3500),
        "sustained ceiling exceeded"
    );
    let (burst_bytes, burst_elapsed) = first_burst.context("no burst sample")?;
    println!(
        "H2 trial={trial} status=200 delivered={}/{} TLS_ms={} first_window_bytes={} first_window_ms={} total_ms={} goodput_Mbit_s={:.3} average_KiB_s={:.2}",
        received.len(),
        expected.len(),
        handshake.as_millis(),
        burst_bytes,
        burst_elapsed.as_millis(),
        elapsed.as_millis(),
        received.len() as f64 * 8.0 / elapsed.as_secs_f64() / 1e6,
        received.len() as f64 / 1024.0 / elapsed.as_secs_f64(),
    );
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(90), demo())
        .await
        .context("demo timed out")?
}

async fn demo() -> Result<()> {
    let cert = rcgen::generate_simple_self_signed(vec![HOST.to_owned()])?;
    let certificate = CertificateDer::from(cert.serialize_der()?);
    let key = PrivatePkcs8KeyDer::from(cert.serialize_private_key_der());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key.into())?;
    server_tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_tls));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate)?;
    let mut client_tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(client_tls));
    let payload = Bytes::from((0..BODY_BYTES).map(|n| (n % 251) as u8).collect::<Vec<_>>());

    let origin = TcpListener::bind("127.0.0.1:0").await?;
    let origin_addr = origin.local_addr()?;
    let body = payload.clone();
    let origin_task = AbortOnDropHandle::new(tokio::spawn(async move {
        let mut handlers = tokio::task::JoinSet::new();
        for _ in 0..TRIALS {
            let (socket, _) = origin.accept().await?;
            handlers.spawn(serve(socket, acceptor.clone(), body.clone()));
        }
        while let Some(result) = handlers.join_next().await {
            result??;
        }
        Ok::<_, anyhow::Error>(())
    }));

    let mut flags = gen_default_flags();
    flags.camouflage_config_mut().server_name = HOST.to_owned();
    flags
        .camouflage_config_mut()
        .set_decoy_upstream(origin_addr.to_string());
    flags.camouflage_config_mut().admission_secret = uuid::Uuid::new_v4().to_string();
    let mut listener = TcpTunnelListener::new("tcp://127.0.0.1:0".parse()?);
    listener.set_flags(flags);
    listener.listen().await?;
    let public = SocketAddr::from(([127, 0, 0, 1], listener.local_url().port().unwrap()));
    let _proxy = AbortOnDropHandle::new(tokio::spawn(async move { listener.accept().await }));

    println!(
        "Local demo: client -> {public} (LowTier passthrough) -> {origin_addr} (H2/TLS origin)"
    );
    println!(
        "Global: 1 MiB/s, 256 KiB burst; source IP: 128 KiB/s, 64 KiB burst; both directions combined."
    );
    println!(
        "TLS certificate verification enabled; no external DNS/network; no HTTP response injection."
    );
    for trial in 0..TRIALS {
        tokio::time::timeout(
            Duration::from_secs(25),
            download(trial, public, &connector, &payload),
        )
        .await
        .context("download timed out")??;
    }
    origin_task.await??;
    println!("PASS: all three payloads match. Burst budget persisted across reconnections.");
    println!(
        "TCP kernel retransmission/RTT counters were not sampled; TLS latency is reported above."
    );
    Ok(())
}
