//! Verify two bounded H2/TLS probe sessions and reject a third session.
//! All services use loopback sockets. No TUN or root access is required.
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
const TRIALS: usize = 2;
const BODY_BYTES: usize = 8 * 1024;

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
    // Drive the response until the client verifies all bytes and closes.
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
    while let Some(data) = stream.data().await {
        let data = data?;
        ensure!(
            received.len() + data.len() <= BODY_BYTES,
            "oversized response"
        );
        received.extend_from_slice(&data);
        stream.flow_control().release_capacity(data.len())?;
    }
    ensure!(
        received.as_slice() == expected.as_ref(),
        "payload mismatch or truncation"
    );
    let elapsed = start.elapsed();
    println!(
        "H2 trial={trial} status=200 delivered={}/{} TLS_ms={} total_ms={} goodput_Mbit_s={:.3}",
        received.len(),
        expected.len(),
        handshake.as_millis(),
        elapsed.as_millis(),
        received.len() as f64 * 8.0 / elapsed.as_secs_f64() / 1e6,
    );
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20), demo())
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
        ensure!(
            tokio::time::timeout(Duration::from_secs(1), origin.accept())
                .await
                .is_err(),
            "third session reached the origin"
        );
        Ok::<_, anyhow::Error>(())
    }));

    let mut flags = gen_default_flags();
    flags.camouflage_config_mut().server_name = HOST.to_owned();
    flags
        .camouflage_config_mut()
        .set_decoy_upstream(origin_addr.to_string());
    flags.camouflage_config_mut().admission_secret = uuid::Uuid::new_v4().to_string();
    let mut listener = TcpTunnelListener::new("h2://127.0.0.1:0".parse()?);
    listener.set_flags(flags);
    listener.listen().await?;
    let public = SocketAddr::from(([127, 0, 0, 1], listener.local_url().port().unwrap()));
    let _proxy = AbortOnDropHandle::new(tokio::spawn(async move { listener.accept().await }));

    println!(
        "Local demo: client -> {public} (LowTier passthrough) -> {origin_addr} (H2/TLS origin)"
    );
    println!(
        "Probe policy: two sessions per source per 60 seconds; 64 KiB combined bytes; 5 seconds idle; 10 seconds lifetime."
    );
    println!(
        "TLS certificate verification enabled; no external DNS/network; no HTTP response injection."
    );
    for trial in 0..TRIALS {
        tokio::time::timeout(
            Duration::from_secs(5),
            download(trial, public, &connector, &payload),
        )
        .await
        .context("download timed out")??;
    }
    let third = tokio::time::timeout(
        Duration::from_secs(2),
        download(2, public, &connector, &payload),
    )
    .await;
    ensure!(
        matches!(third, Ok(Err(_))),
        "third probe session was not rejected"
    );
    origin_task.await??;
    println!("PASS: both payloads match. The third session received no upstream connection.");
    println!(
        "TCP kernel retransmission/RTT counters were not sampled; TLS latency is reported above."
    );
    Ok(())
}
