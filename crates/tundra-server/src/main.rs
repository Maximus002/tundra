mod acl;
mod config;
mod fallback;
mod limiter;
mod tls;

use anyhow::{Context, Result};
use clap::Parser;
use config::ServerConfig;
use limiter::ConnectionLimiter;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::{sleep, Duration};
use tundra_core::crypto::{self, Cipher, ROLE_CLIENT, ROLE_SERVER};
use tundra_core::frame::{MuxCommand, Frame};
use tundra_core::kem;
use tundra_fme::library::model_from_profile;
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

    let mut srv_cfg = match &cli.config {
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
                fme_profile: "browser".into(),
            };
            warn!("no config file found, using defaults");
            default
        }),
    };

    if let Some(v) = &cli.listen_addr { srv_cfg.listen_addr = v.clone(); }
    if let Some(v) = cli.listen_port { srv_cfg.listen_port = v; }
    if let Some(v) = &cli.target_domain { srv_cfg.target_domain = v.clone(); }

    let psk = srv_cfg.psk_bytes()?;
    if psk.is_none() {
        warn!("no PSK configured — any client can connect");
    }

    let addr = format!("{}:{}", srv_cfg.listen_addr, srv_cfg.listen_port);
    let tls_config = Arc::new(tls::TlsConfig::new(&srv_cfg.target_domain)?);
    let limiter = Arc::new(ConnectionLimiter::new(srv_cfg.max_connections, srv_cfg.max_per_ip));
    let cfg = Arc::new(srv_cfg);
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

const AUTH_TTL_SECS: u64 = 300;
const CHALLENGE_SIZE: usize = 16;
const AUTH_PAYLOAD_SIZE: usize = 8 + 32 + kem::HYBRID_PK_SIZE;
const AUTH_ACK_SIZE: usize = kem::HYBRID_CT_SIZE;

fn verify_auth(
    frame: &Frame,
    psk: &Option<[u8; 32]>,
    server_nonce: &[u8; CHALLENGE_SIZE],
) -> Result<([u8; kem::KEM_PK_SIZE], [u8; 32])> {
    if frame.header.command != MuxCommand::Auth {
        anyhow::bail!("expected Auth");
    }
    if frame.payload.len() < AUTH_PAYLOAD_SIZE {
        anyhow::bail!("bad auth payload len: {} expected >= {}", frame.payload.len(), AUTH_PAYLOAD_SIZE);
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

    let kyber_pk: [u8; kem::KEM_PK_SIZE] = frame.payload[40..40 + kem::KEM_PK_SIZE]
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad kyber pk"))?;
    let x25519_pk: [u8; 32] = frame.payload[40 + kem::KEM_PK_SIZE..40 + kem::HYBRID_PK_SIZE]
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad x25519 pk"))?;

    if let Some(psk_bytes) = psk {
        let mut msg = Vec::with_capacity(CHALLENGE_SIZE + 8 + kem::HYBRID_PK_SIZE);
        msg.extend_from_slice(server_nonce);
        msg.extend_from_slice(&frame.payload[..8]);
        msg.extend_from_slice(&kyber_pk);
        msg.extend_from_slice(&x25519_pk);
        let expected_hmac = blake3::keyed_hash(psk_bytes, &msg);
        let received_hmac = &frame.payload[8..40];
        if !crypto::constant_time_eq(expected_hmac.as_bytes(), received_hmac) {
            anyhow::bail!("auth HMAC mismatch");
        }
    }

    Ok((kyber_pk, x25519_pk))
}

async fn handle_connection(
    socket: TcpStream,
    peer: std::net::SocketAddr,
    tls_config: Arc<tls::TlsConfig>,
    target_domain: String,
    psk: Arc<Option<[u8; 32]>>,
    scfg: Arc<ServerConfig>,
) -> Result<()> {
    let acceptor = tls_config.acceptor();
    let tls_stream = tokio::time::timeout(
        Duration::from_secs(scfg.handshake_timeout_secs),
        acceptor.accept(socket),
    )
        .await
        .with_context(|| format!("tls handshake timeout for {}", peer))?
        .with_context(|| format!("tls handshake failed for {}", peer))?;

    info!("{} tls ok", peer);

    let (mut tls_read, mut tls_write) = tokio::io::split(tls_stream);

    let mut server_nonce = [0u8; CHALLENGE_SIZE];
    use rand::RngCore;
    rand::rng().fill_bytes(&mut server_nonce);
    let challenge_frame = Frame::new_handshake(MuxCommand::Challenge, 0, server_nonce.to_vec());
    tls_write.write_all(&challenge_frame.encode()).await?;

    let mut tmp = vec![0u8; 8192];
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
    let (kyber_pk, x25519_pk) = verify_auth(&auth_frame, &psk, &server_nonce)?;

    let enc = kem::hybrid_encapsulate(&kyber_pk, &x25519_pk)
        .map_err(|e| anyhow::anyhow!("hybrid KEM encapsulate failed: {:?}", e))?;

    let server_enc_key = crypto::derive_key(&enc.shared_secret, b"server-enc");
    let client_enc_key = crypto::derive_key(&enc.shared_secret, b"client-enc");
    let server_cipher = Arc::new(Cipher::new_with_role(&server_enc_key, ROLE_SERVER));
    let client_cipher = Cipher::new_with_role(&client_enc_key, ROLE_CLIENT);

    let mut ack_payload = Vec::with_capacity(AUTH_ACK_SIZE);
    ack_payload.extend_from_slice(&enc.kyber_ct);
    ack_payload.extend_from_slice(&enc.x25519_ct);
    let ack = Frame::new_handshake(MuxCommand::AuthAck, 0, ack_payload);
    tls_write.write_all(&ack.encode()).await?;

    let kc_hash = blake3::keyed_hash(&server_enc_key, b"tundra-key-confirm-s2c");
    let kc_frame = Frame::new(MuxCommand::KeyConfirm, 0, kc_hash.as_bytes().to_vec());
    write_encrypted_frame(&mut tls_write, &server_cipher, &kc_frame).await?;

    let mut kc_len_buf = [0u8; 2];
    tls_read.read_exact(&mut kc_len_buf).await?;
    let kc_len = u16::from_be_bytes(kc_len_buf) as usize;
    if kc_len == 0 { anyhow::bail!("empty key confirm"); }
    let mut kc_blob = vec![0u8; kc_len];
    tls_read.read_exact(&mut kc_blob).await?;
    let kc_plain = client_cipher.decrypt(&kc_blob)?;
    let kc_received = Frame::decode(&kc_plain)?;
    if kc_received.header.command != MuxCommand::KeyConfirm {
        anyhow::bail!("expected KeyConfirm from client, got {:?}", kc_received.header.command);
    }
    let expected_c2s = blake3::keyed_hash(&client_enc_key, b"tundra-key-confirm-c2s");
    if !crypto::constant_time_eq(kc_received.payload.get(..32).unwrap_or(&[]), expected_c2s.as_bytes()) {
        anyhow::bail!("client KeyConfirm mismatch");
    }

    info!("{} auth ok (hybrid KEM, key confirmed)", peer);

    run_protocol(tls_read, tls_write, peer, client_cipher, server_cipher, scfg).await
}

async fn run_protocol(
    mut client_read: tokio::io::ReadHalf<tokio_rustls::server::TlsStream<TcpStream>>,
    client_write: tokio::io::WriteHalf<tokio_rustls::server::TlsStream<TcpStream>>,
    peer: std::net::SocketAddr,
    client_cipher: Cipher,
    server_cipher: Arc<Cipher>,
    scfg: Arc<ServerConfig>,
) -> Result<()> {
    let client_write = Arc::new(tokio::sync::Mutex::new(client_write));
    let streams: Arc<tokio::sync::Mutex<HashMap<u32, tokio::net::tcp::OwnedWriteHalf>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let mut upstream_tasks: JoinSet<()> = JoinSet::new();

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
                    let mut cw = client_write.lock().await;
                    write_encrypted_frame(&mut *cw, &server_cipher, &resp).await?;
                    continue;
                }

                match TcpStream::connect(format!("{}:{}", host, port)).await {
                    Ok(upstream) => {
                        let (up_read, up_write) = upstream.into_split();
                        streams.lock().await.insert(client_sid, up_write);

                        let resp = Frame::new(MuxCommand::NewStream, client_sid, vec![]);
                        {
                            let mut cw = client_write.lock().await;
                            write_encrypted_frame(&mut *cw, &server_cipher, &resp).await?;
                        }

                        let cw = client_write.clone();
                        let st = streams.clone();
                        let sc = server_cipher.clone();
                        let fp = scfg.fme_profile.clone();
                        upstream_tasks.spawn(relay_upstream(client_sid, cw, st, up_read, sc, fp));
                    }
                    Err(e) => error!("{}:{} failed: {}", host, port, e),
                }
            }
            MuxCommand::Close => { streams.lock().await.remove(&frame.header.stream_id); }
            MuxCommand::Ping => {
                let pong = Frame::new(MuxCommand::Pong, 0, vec![]);
                let mut cw = client_write.lock().await;
                write_encrypted_frame(&mut *cw, &server_cipher, &pong).await?;
            }
            _ => {}
        }
    }
    drop(streams);
    upstream_tasks.abort_all();
    info!("{} disconnected", peer);
    Ok(())
}

async fn write_encrypted_frame(
    writer: &mut (impl AsyncWriteExt + Unpin),
    cipher: &Cipher,
    frame: &Frame,
) -> Result<()> {
    let plaintext = frame.encode();
    let encrypted = cipher.encrypt(&plaintext)?;
    let len = encrypted.len() as u16;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&encrypted).await?;
    Ok(())
}

async fn relay_upstream(
    stream_id: u32,
    client_write: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio_rustls::server::TlsStream<TcpStream>>>>,
    streams: Arc<tokio::sync::Mutex<HashMap<u32, tokio::net::tcp::OwnedWriteHalf>>>,
    mut upstream_read: tokio::net::tcp::OwnedReadHalf,
    server_cipher: Arc<Cipher>,
    fme_profile: String,
) {
    let model = model_from_profile(&fme_profile);
    let mut morpher = Morpher::new(model);

    loop {
        let mut buf = vec![0u8; 16384];
        let n = match upstream_read.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };

        morpher.push(buf[..n].to_vec(), FmeDirection::Downstream);
        let packets = morpher.morph_flush();

        for (i, pkt) in packets.iter().enumerate() {
            if i > 0 && pkt.send_after_us > 0 {
                sleep(Duration::from_micros(pkt.send_after_us)).await;
            }
            let real = pkt.data[..pkt.real_data_len].to_vec();
            let frame = Frame::new_padded(MuxCommand::Data, stream_id, real, pkt.data.len());
            let mut cw = client_write.lock().await;
            if write_encrypted_frame(&mut *cw, &server_cipher, &frame).await.is_err() {
                return;
            }
        }
    }
    let frame = Frame::new(MuxCommand::Close, stream_id, vec![]);
    let mut cw = client_write.lock().await;
    let _ = write_encrypted_frame(&mut *cw, &server_cipher, &frame).await;
    streams.lock().await.remove(&stream_id);
}
