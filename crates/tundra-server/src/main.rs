mod acl;
mod config;
mod fallback;
mod limiter;
mod tls;

use anyhow::{Context, Result};
use clap::Parser;
use config::ServerConfig;
use limiter::ConnectionLimiter;
use rand::SeedableRng;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::{sleep, Duration};
use tundra_core::crypto::{self, Cipher};
use tundra_core::frame::{MuxCommand, Frame};
use tundra_core::kem;
use tundra_fme::library::synthetic_generic_browsing;
use tundra_fme::model::Direction as FmeDirection;
use tundra_fme::morpher::Morpher;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "tundra-server", version)]
struct Cli {
    #[arg(long)]
    config: Option<String>,
    #[arg(long)]
    listen_port: Option<u16>,
    #[arg(long)]
    listen_addr: Option<String>,
    #[arg(long)]
    target_domain: Option<String>,
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

    let mut cfg = match &cli.config {
        Some(path) => ServerConfig::load(std::path::Path::new(path))?,
        None => ServerConfig::load(std::path::Path::new("tundra-server.toml")).unwrap_or_else(|_| {
            let default = ServerConfig {
                listen_addr: cli.listen_addr.clone().unwrap_or_else(|| "0.0.0.0".into()),
                listen_port: cli.listen_port.unwrap_or(8443),
                target_domain: cli.target_domain.clone().unwrap_or_else(|| "www.microsoft.com".into()),
                psk: None,
                max_connections: 1000,
                max_per_ip: 10,
                handshake_timeout_secs: 10,
            };
            warn!("no config file found, using defaults");
            default
        }),
    };

    if let Some(v) = &cli.listen_addr { cfg.listen_addr = v.clone(); }
    if let Some(v) = cli.listen_port { cfg.listen_port = v; }
    if let Some(v) = &cli.target_domain { cfg.target_domain = v.clone(); }

    let psk = cfg.psk_bytes()?;
    if psk.is_none() {
        warn!("no PSK configured — any client can connect");
    }

    let addr = format!("{}:{}", cfg.listen_addr, cfg.listen_port);
    let tls_config = Arc::new(tls::TlsConfig::new(&cfg.target_domain)?);
    let limiter = Arc::new(ConnectionLimiter::new(cfg.max_connections, cfg.max_per_ip));
    let cfg = Arc::new(cfg);
    let psk = Arc::new(psk);

    info!("listening on {} (target={}, psk={})", addr, cfg.target_domain, psk.is_some());

    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind to {}", addr))?;

    let mut tasks: JoinSet<()> = JoinSet::new();
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (socket, peer) = accept_result?;
                let tc = tls_config.clone();
                let target = cfg.target_domain.clone();
                let lim = limiter.clone();
                let psk_ref = psk.clone();
                let cfg_ref = cfg.clone();

                if lim.acquire(peer.ip()).await.is_err() {
                    warn!("{} connection rejected (limit)", peer);
                    continue;
                }

                tasks.spawn(async move {
                    let _guard = ConnectionGuard {
                        limiter: lim.clone(),
                        ip: peer.ip(),
                    };
                    if let Err(e) = handle_connection(socket, peer, tc, target, psk_ref, cfg_ref).await {
                        error!("{} error: {}", peer, e);
                    }
                });
            }
            _ = &mut shutdown => {
                info!("shutting down, waiting for {} active connections...", tasks.len());
                break;
            }
        }
    }

    while tasks.join_next().await.is_some() {}
    info!("all connections drained");
    Ok(())
}

struct ConnectionGuard {
    limiter: Arc<ConnectionLimiter>,
    ip: std::net::IpAddr,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.limiter.release(self.ip);
    }
}

const AUTH_TTL_SECS: u64 = 30;

fn parse_auth(frame: &Frame, psk: &Option<[u8; 32]>) -> Result<[u8; kem::KEM_PK_SIZE]> {
    if frame.header.command != MuxCommand::Auth {
        anyhow::bail!("expected Auth");
    }
    let expected_len = 8 + 32 + kem::KEM_PK_SIZE;
    if frame.payload.len() != expected_len {
        anyhow::bail!("bad auth payload len: {} expected {}", frame.payload.len(), expected_len);
    }
    let client_ts = u64::from_le_bytes(frame.payload[..8].try_into().unwrap());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let diff = now.abs_diff(client_ts);
    if diff > AUTH_TTL_SECS {
        anyhow::bail!("auth expired: ts={} now={} diff={}", client_ts, now, diff);
    }

    let kem_pk = &frame.payload[40..40 + kem::KEM_PK_SIZE];

    if let Some(psk_bytes) = psk {
        let mut msg = Vec::with_capacity(8 + kem::KEM_PK_SIZE);
        msg.extend_from_slice(&frame.payload[..8]);
        msg.extend_from_slice(kem_pk);
        let expected_hmac = blake3::keyed_hash(psk_bytes, &msg);
        let received_hmac = &frame.payload[8..40];
        if expected_hmac.as_bytes() != received_hmac {
            anyhow::bail!("auth HMAC mismatch");
        }
    }

    let pk: [u8; kem::KEM_PK_SIZE] = kem_pk.try_into()
        .map_err(|_| anyhow::anyhow!("bad pk size"))?;
    Ok(pk)
}

async fn handle_connection(
    socket: TcpStream,
    peer: std::net::SocketAddr,
    tls_config: Arc<tls::TlsConfig>,
    target_domain: String,
    psk: Arc<Option<[u8; 32]>>,
    cfg: Arc<ServerConfig>,
) -> Result<()> {
    let acceptor = tls_config.acceptor();
    let tls_stream = tokio::time::timeout(
        Duration::from_secs(cfg.handshake_timeout_secs),
        acceptor.accept(socket),
    )
        .await
        .with_context(|| format!("tls handshake timeout for {}", peer))?
        .with_context(|| format!("tls handshake failed for {}", peer))?;

    info!("{} tls ok", peer);

    let (mut tls_read, tls_write) = tokio::io::split(tls_stream);

    let mut tmp = vec![0u8; 4096];
    let n = match tls_read.read(&mut tmp).await {
        Ok(n) => n,
        Err(_) => return Ok(()),
    };

    if n < 4 {
        return Ok(());
    }

    let magic = u32::from_be_bytes([tmp[0], tmp[1], tmp[2], tmp[3]]);
    if magic != tundra_core::MAGIC {
        info!("{} non-tundra traffic -> fallback to target", peer);
        let initial_data = tmp[..n].to_vec();
        return fallback::fallback_to_target(tls_read, tls_write, &target_domain, initial_data).await;
    }

    let auth_frame = Frame::decode(&tmp[..n])?;
    let kem_pk = parse_auth(&auth_frame, &psk)?;

    let enc = kem::encapsulate(&kem_pk)
        .map_err(|e| anyhow::anyhow!("KEM encapsulate failed: {:?}", e))?;

    let server_enc_key = crypto::derive_key(&enc.shared_secret, b"server-enc");
    let client_enc_key = crypto::derive_key(&enc.shared_secret, b"client-enc");
    let server_cipher = Arc::new(tokio::sync::Mutex::new(Cipher::new(&server_enc_key)));
    let client_cipher = Cipher::new(&client_enc_key);

    let ack = Frame::new(MuxCommand::AuthAck, 0, enc.ciphertext.to_vec());
    let mut tls_write = tls_write;
    tls_write.write_all(&ack.encode()).await?;
    info!("{} auth ok", peer);

    run_protocol_tls(tls_read, tls_write, peer, client_cipher, server_cipher).await
}

macro_rules! run_protocol_body {
    ($client_read:expr, $client_write:expr, $peer:expr, $client_cipher:expr, $server_cipher:expr) => {{
        let client_write = Arc::new(tokio::sync::Mutex::new($client_write));
        let streams: Arc<tokio::sync::Mutex<std::collections::HashMap<u32, tokio::net::tcp::OwnedWriteHalf>>> =
            Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
        let mut client_read = $client_read;
        let mut client_cipher = $client_cipher;
        let mut upstream_tasks: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

        loop {
            let mut len_buf = [0u8; 2];
            client_read.read_exact(&mut len_buf).await?;
            let len = u16::from_be_bytes(len_buf) as usize;
            if len == 0 { break; }
            let mut blob = vec![0u8; len];
            client_read.read_exact(&mut blob).await?;

            let plaintext = client_cipher.decrypt(&blob)?;
            let frame = Frame::decode(&plaintext)?;

            match frame.header.command {
                MuxCommand::Data => {
                    let mut streams = streams.lock().await;
                    if let Some(w) = streams.get_mut(&frame.header.stream_id) {
                        let data = frame.real_data();
                        if !data.is_empty() {
                            w.write_all(data).await?;
                        }
                    }
                }
                MuxCommand::NewStream => {
                    let client_sid = frame.header.stream_id;
                    let target = String::from_utf8_lossy(&frame.payload);
                    let parts: Vec<&str> = target.splitn(2, ':').collect();
                    let host = parts[0];
                    let port: u16 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(80);

                    if !acl::is_upstream_allowed(host, port) {
                        error!("{}:{} blocked by ACL", host, port);
                        let resp = Frame::new(MuxCommand::Close, client_sid, vec![]);
                        let mut sc = $server_cipher.lock().await;
                        let mut cw = client_write.lock().await;
                        write_frame(&mut *cw, &mut *sc, &resp).await?;
                        continue;
                    }

                    match TcpStream::connect(format!("{}:{}", host, port)).await {
                        Ok(upstream) => {
                            let (up_read, up_write) = upstream.into_split();
                            streams.lock().await.insert(client_sid, up_write);

                            let resp = Frame::new(MuxCommand::NewStream, client_sid, vec![]);
                            {
                                let mut sc = $server_cipher.lock().await;
                                let mut cw = client_write.lock().await;
                                write_frame(&mut *cw, &mut *sc, &resp).await?;
                            }

                            let cw = client_write.clone();
                            let st = streams.clone();
                            let sc = $server_cipher.clone();
                            upstream_tasks.spawn(relay_upstream(client_sid, cw, st, up_read, sc));
                        }
                        Err(e) => error!("{}:{} failed: {}", host, port, e),
                    }
                }
                MuxCommand::Close => { streams.lock().await.remove(&frame.header.stream_id); }
                MuxCommand::Ping => {
                    let pong = Frame::new(MuxCommand::Pong, 0, vec![]);
                    let mut sc = $server_cipher.lock().await;
                    let mut cw = client_write.lock().await;
                    write_frame(&mut *cw, &mut *sc, &pong).await?;
                }
                _ => {}
            }
        }
        drop(streams);
        upstream_tasks.abort_all();
        info!("{} disconnected", $peer);
        Ok(())
    }};
}

async fn run_protocol_tls(
    client_read: tokio::io::ReadHalf<tokio_rustls::server::TlsStream<TcpStream>>,
    client_write: tokio::io::WriteHalf<tokio_rustls::server::TlsStream<TcpStream>>,
    peer: std::net::SocketAddr,
    client_cipher: Cipher,
    server_cipher: Arc<tokio::sync::Mutex<Cipher>>,
) -> Result<()> {
    run_protocol_body!(client_read, client_write, peer, client_cipher, server_cipher)
}

async fn write_frame(
    writer: &mut (impl AsyncWriteExt + Unpin),
    cipher: &mut Cipher,
    frame: &Frame,
) -> Result<()> {
    let plaintext = frame.encode();
    let encrypted = cipher.encrypt(&plaintext)?;
    let len = encrypted.len() as u16;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&encrypted).await?;
    Ok(())
}

async fn relay_upstream<W: AsyncWriteExt + Unpin + Send + 'static>(
    stream_id: u32,
    client_write: Arc<tokio::sync::Mutex<W>>,
    streams: Arc<tokio::sync::Mutex<HashMap<u32, tokio::net::tcp::OwnedWriteHalf>>>,
    mut upstream_read: tokio::net::tcp::OwnedReadHalf,
    server_cipher: Arc<tokio::sync::Mutex<Cipher>>,
) {
    let model = synthetic_generic_browsing();
    let mut morpher = Morpher::new(model);

    loop {
        let mut buf = vec![0u8; 16384];
        let n = match upstream_read.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };

        morpher.push(buf[..n].to_vec(), FmeDirection::Downstream);
        let mut rng = rand_chacha::ChaCha12Rng::from_seed(rand::random());
        let packets = morpher.morph_flush(&mut rng);

        for (i, pkt) in packets.iter().enumerate() {
            if i > 0 && pkt.send_after_us > 0 {
                sleep(Duration::from_micros(pkt.send_after_us)).await;
            }
            let real = pkt.data[..pkt.real_data_len].to_vec();
            let frame = Frame::new_padded(MuxCommand::Data, stream_id, real, pkt.data.len());
            let mut sc = server_cipher.lock().await;
            let mut cw = client_write.lock().await;
            if write_frame(&mut *cw, &mut *sc, &frame).await.is_err() {
                return;
            }
        }
    }
    let frame = Frame::new(MuxCommand::Close, stream_id, vec![]);
    let mut sc = server_cipher.lock().await;
    let mut cw = client_write.lock().await;
    let _ = write_frame(&mut *cw, &mut *sc, &frame).await;
    streams.lock().await.remove(&stream_id);
}
