mod multiplex;

use anyhow::Result;
use clap::Parser;
use multiplex::{SessionPool, StreamEvent};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "tundra-client", version)]
struct Cli {
    #[arg(long, default_value_t = 1080)]
    socks_port: u16,
    #[arg(long)]
    server_addr: String,
    #[arg(long, default_value_t = 8443)]
    server_port: u16,
    #[arg(long)]
    socks_auth: Option<String>,
    #[arg(long, env = "TUNDRA_PSK")]
    psk: Option<String>,
    #[arg(long, default_value_t = 600)]
    max_session_age_secs: u64,
    #[arg(long, default_value_t = 200)]
    max_session_bytes_mb: u64,
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    fme: bool,
    #[arg(long, default_value = "browser")]
    fme_profile: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider().install_default().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let socks_addr = format!("127.0.0.1:{}", cli.socks_port);
    let server_addr = format!("{}:{}", cli.server_addr, cli.server_port);

    let psk: Option<[u8; 32]> = match &cli.psk {
        Some(hex) => {
            if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                anyhow::bail!("PSK must be exactly 64 hex characters");
            }
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            Some(bytes.try_into().map_err(|_| anyhow::anyhow!("PSK must be 64 hex chars"))?)
        }
        None => None,
    };

    let tls_config = build_client_tls_config();

    let mut pool = SessionPool::new(
        server_addr.clone(),
        psk,
        tls_config,
        Duration::from_secs(cli.max_session_age_secs),
        cli.max_session_bytes_mb * 1024 * 1024,
        cli.fme,
        cli.fme_profile.clone(),
    );

    let upstream_rx = pool.take_upstream_rx()
        .ok_or_else(|| anyhow::anyhow!("upstream rx already taken"))?;

    let pool = Arc::new(pool);

    info!("SOCKS5 on {} -> {} (psk={}, fme={}, profile={}, max_age={}s, max_bytes={}MB)",
          socks_addr, server_addr, psk.is_some(), cli.fme, cli.fme_profile,
          cli.max_session_age_secs, cli.max_session_bytes_mb);

    let listener = TcpListener::bind(&socks_addr).await?;

    let (downstream_tx, downstream_rx) = mpsc::channel::<(u32, Vec<u8>)>(256);

    let socks_sinks: Arc<tokio::sync::Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let socks_sinks_clone = socks_sinks.clone();

    tokio::spawn(async move {
        if let Err(e) = dispatch_downstream(downstream_rx, socks_sinks_clone).await {
            error!("dispatch error: {}", e);
        }
    });

    tokio::spawn(async move {
        if let Err(e) = dispatch_upstream(upstream_rx, downstream_tx).await {
            error!("upstream dispatch error: {}", e);
        }
    });

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    let mut tasks = tokio::task::JoinSet::new();

     let pool_ref = pool.clone();
     tokio::spawn(async move {
         let mut interval = tokio::time::interval(Duration::from_secs(30));
         loop {
             interval.tick().await;
             if let Ok(session) = pool_ref.get_or_create_session().await {
                 if session.streams.lock().await.is_empty() {
                     if let Err(e) = pool_ref.send_ping(&session).await {
                         error!("keepalive ping failed: {}", e);
                     }
                 }
             }
         }
     });

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (socks, peer) = accept_result?;
                let pool = pool.clone();
                let socks_auth = cli.socks_auth.clone();
                let sinks = socks_sinks.clone();
                tasks.spawn(async move {
                    if let Err(e) = handle_socks5(socks, peer, pool, socks_auth.as_deref(), sinks).await {
                        error!("{} error: {}", peer, e);
                    }
                });
            }
            _ = &mut shutdown => {
                info!("shutting down...");
                pool.shutdown().await;
                break;
            }
        }
    }

    while tasks.join_next().await.is_some() {}
    Ok(())
}

async fn dispatch_upstream(
    mut rx: mpsc::Receiver<StreamEvent>,
    downstream_tx: mpsc::Sender<(u32, Vec<u8>)>,
) -> Result<()> {
    while let Some(event) = rx.recv().await {
        if !event.data.is_empty() {
            downstream_tx.send((event.stream_id, event.data)).await?;
        }
    }
    Ok(())
}

async fn dispatch_downstream(
    mut rx: mpsc::Receiver<(u32, Vec<u8>)>,
    sinks: Arc<tokio::sync::Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
) -> Result<()> {
    while let Some((stream_id, data)) = rx.recv().await {
        let sinks = sinks.lock().await;
        if let Some(tx) = sinks.get(&stream_id) {
            let _ = tx.send(data).await;
        }
    }
    Ok(())
}

async fn handle_socks5(
    socks: TcpStream,
    peer: std::net::SocketAddr,
    pool: Arc<SessionPool>,
    socks_auth: Option<&str>,
    sinks: Arc<tokio::sync::Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
) -> Result<()> {
    let (mut socks_read, mut socks_write) = socks.into_split();
    let mut buf = [0u8; 1024];

    let n = socks_read.read(&mut buf).await?;
    if n < 3 || buf[0] != 0x05 { anyhow::bail!("not SOCKS5"); }

    if socks_auth.is_some() {
        let auth_methods: Vec<u8> = buf[2..n].to_vec();
        if !auth_methods.contains(&0x02) {
            socks_write.write_all(&[0x05, 0xFF]).await?;
            anyhow::bail!("client doesn't support username/password auth");
        }
        socks_write.write_all(&[0x05, 0x02]).await?;

        let n = socks_read.read(&mut buf).await?;
        if n < 3 || buf[0] != 0x01 { anyhow::bail!("bad auth packet"); }
        let ulen = buf[1] as usize;
        if n < 2 + ulen + 1 { anyhow::bail!("truncated auth"); }
        let plen = buf[2 + ulen] as usize;
        if n < 2 + ulen + 1 + plen { anyhow::bail!("truncated auth"); }

        let username = String::from_utf8_lossy(&buf[2..2 + ulen]).to_string();
        let password = String::from_utf8_lossy(&buf[2 + ulen + 1..2 + ulen + 1 + plen]).to_string();

        let expected = socks_auth.unwrap();
        let (exp_user, exp_pass) = expected.split_once(':').unwrap_or((expected, ""));
        if username != exp_user || password != exp_pass {
            socks_write.write_all(&[0x01, 0x01]).await?;
            anyhow::bail!("auth failed for {}", peer);
        }
        socks_write.write_all(&[0x01, 0x00]).await?;
    } else {
        socks_write.write_all(&[0x05, 0x00]).await?;
    }

    let n = socks_read.read(&mut buf).await?;
    if n < 7 || buf[1] != 0x01 { anyhow::bail!("unsupported SOCKS5"); }

    let (target_addr, target_port) = match buf[3] {
        0x01 => {
            if n < 10 { anyhow::bail!("truncated IPv4"); }
            (format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]),
             u16::from_be_bytes([buf[8], buf[9]]))
        }
        0x03 => {
            let dl = buf[4] as usize;
            if n < 5 + dl + 2 { anyhow::bail!("truncated domain"); }
            (String::from_utf8_lossy(&buf[5..5 + dl]).to_string(),
             u16::from_be_bytes([buf[5 + dl], buf[6 + dl]]))
        }
        _ => anyhow::bail!("unsupported addr type"),
    };

    let target = format!("{}:{}", target_addr, target_port);
    info!("{} -> {}", peer, target);

    let (stream_id, session) = pool.open_stream(&target).await?;

    socks_write.write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;

    let (data_tx, mut data_rx) = mpsc::channel::<Vec<u8>>(64);
    sinks.lock().await.insert(stream_id, data_tx);

    let pool_clone = pool.clone();
    let sinks_clone = sinks.clone();
    tokio::spawn(async move {
        while let Some(data) = data_rx.recv().await {
            if socks_write.write_all(&data).await.is_err() {
                break;
            }
        }
    });

    let mut up_buf = vec![0u8; 16384];
    loop {
        let n = match socks_read.read(&mut up_buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        if pool_clone.send_data(&session, stream_id, up_buf[..n].to_vec()).await.is_err() {
            break;
        }
    }

    let _ = pool_clone.close_stream(&session, stream_id).await;
    sinks_clone.lock().await.remove(&stream_id);
    info!("{} stream {} done", peer, stream_id);
    Ok(())
}

fn build_client_tls_config() -> Arc<rustls::ClientConfig> {
    use rustls::crypto::ring;
    let provider = ring::default_provider();

    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[
            &rustls::version::TLS13,
            &rustls::version::TLS12,
        ])
        .expect("tls versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.enable_sni = true;

    Arc::new(config)
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}
