use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use log;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tundra_core::crypto::Cipher;
use tundra_core::frame::{Frame, MuxCommand};
use tundra_core::kem;

type TlsStream = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub server_addr: String,
    pub server_port: u16,
    pub socks_port: u16,
    pub psk: String,
    pub fme: bool,
    pub name: String,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            server_addr: String::new(),
            server_port: 8443,
            socks_port: 1080,
            psk: String::new(),
            fme: true,
            name: "Default".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyStats {
    pub connected: bool,
    pub streams: usize,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub uptime_secs: u64,
}

struct ActiveSession {
    write: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<TlsStream>>>,
    send_cipher: Arc<tokio::sync::Mutex<Cipher>>,
    streams: Arc<tokio::sync::Mutex<HashMap<u32, tokio::net::tcp::OwnedWriteHalf>>>,
    next_sid: Arc<tokio::sync::Mutex<u32>>,
    bytes_sent: Arc<std::sync::atomic::AtomicU64>,
    bytes_recv: Arc<std::sync::atomic::AtomicU64>,
    connected_at: Arc<Mutex<Option<tokio::time::Instant>>>,
    cancel: tokio_util::sync::CancellationToken,
}

pub struct ProxyState {
    session: Arc<Mutex<Option<ActiveSession>>>,
    stats: Arc<Mutex<ProxyStats>>,
    socks_listener: Arc<Mutex<Option<TcpListener>>>,
    profiles: Arc<Mutex<Vec<ProxyConfig>>>,
}

impl ProxyState {
    pub fn new() -> Self {
        let profiles = load_profiles().unwrap_or_default();
        Self {
            session: Arc::new(Mutex::new(None)),
            stats: Arc::new(Mutex::new(ProxyStats {
                connected: false,
                streams: 0,
                bytes_sent: 0,
                bytes_recv: 0,
                uptime_secs: 0,
            })),
            socks_listener: Arc::new(Mutex::new(None)),
            profiles: Arc::new(Mutex::new(profiles)),
        }
    }

    pub async fn connect(&self, cfg: ProxyConfig) -> Result<()> {
        log::info!("connect called: {}:{}", cfg.server_addr, cfg.server_port);

        let psk_bytes: [u8; 32] = hex::decode(&cfg.psk)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("PSK must be 32 bytes"))?;

        let addr = format!("{}:{}", cfg.server_addr, cfg.server_port);
        log::info!("connecting TCP to {}", addr);
        let tcp = tokio::net::TcpStream::connect(&addr).await?;
        log::info!("TCP connected, starting TLS");
        let tls_stream = tls_connect(tcp, &cfg.server_addr).await?;
        log::info!("TLS connected");

        let (mut tls_r, mut tls_w) = tokio::io::split(tls_stream);

        let kp = kem::generate_keypair()?;
        let kem_pk = kp.public_key;
        log::info!("KEM keypair generated, pk len={}", kem_pk.len());
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let mut auth_payload = Vec::with_capacity(8 + 32 + kem_pk.len());
        auth_payload.extend_from_slice(&ts.to_le_bytes());

        let mut hmac_msg = Vec::with_capacity(8 + kem_pk.len());
        hmac_msg.extend_from_slice(&ts.to_le_bytes());
        hmac_msg.extend_from_slice(&kem_pk);
        let hmac = blake3::keyed_hash(&psk_bytes, &hmac_msg);
        auth_payload.extend_from_slice(hmac.as_bytes());

        auth_payload.extend_from_slice(&kem_pk);

        let auth_frame = Frame::new(MuxCommand::Auth, 0, auth_payload);
        tls_w.write_all(&auth_frame.encode()).await?;
        log::info!("auth frame sent, waiting for ack");

        let mut buf = vec![0u8; 4096];
        let n = tls_r.read(&mut buf).await?;
        log::info!("ack read {} bytes", n);
        if n < 11 {
            anyhow::bail!("no auth ack received");
        }

        let ack_frame = Frame::decode(&buf[..n])?;
        log::info!("ack decoded, cmd={:?}", ack_frame.header.command);
        if ack_frame.header.command != MuxCommand::AuthAck {
            anyhow::bail!("bad ack command: {:?}", ack_frame.header.command);
        }
        let shared_secret = kem::decapsulate(&kp, &ack_frame.payload)?;
        log::info!("KEM decapsulated");

        let client_enc_key = tundra_core::crypto::derive_key(&shared_secret, b"client-enc");
        let server_enc_key = tundra_core::crypto::derive_key(&shared_secret, b"server-enc");

        let send_cipher = Arc::new(tokio::sync::Mutex::new(Cipher::new(&client_enc_key)));
        let recv_cipher = Arc::new(tokio::sync::Mutex::new(Cipher::new(&server_enc_key)));
        let cancel = tokio_util::sync::CancellationToken::new();
        let streams: Arc<Mutex<HashMap<u32, tokio::net::tcp::OwnedWriteHalf>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let next_sid = Arc::new(Mutex::new(1u32));
        let bytes_sent = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let bytes_recv = Arc::new(std::sync::atomic::AtomicU64::new(0));

        let session = ActiveSession {
            write: Arc::new(tokio::sync::Mutex::new(tls_w)),
            send_cipher: send_cipher.clone(),
            streams: streams.clone(),
            next_sid: next_sid.clone(),
            bytes_sent: bytes_sent.clone(),
            bytes_recv: bytes_recv.clone(),
            connected_at: Arc::new(Mutex::new(Some(tokio::time::Instant::now()))),
            cancel: cancel.clone(),
        };

        let socks_listener = TcpListener::bind(format!("127.0.0.1:{}", cfg.socks_port)).await?;
        log::info!("SOCKS5 listening on 127.0.0.1:{}", cfg.socks_port);

        let session_arc = self.session.clone();

        self.start_reader_loop(
            tls_r,
            recv_cipher,
            streams.clone(),
            bytes_recv.clone(),
            cancel.clone(),
        );

        let cancel_socks = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_result = socks_listener.accept() => {
                        let (sock, _) = match accept_result {
                            Ok(r) => r,
                            Err(_) => continue,
                        };
                        let session_ref = session_arc.clone();
                        tokio::spawn(async move {
                            let _ = handle_socks5(sock, &session_ref).await;
                        });
                    }
                    _ = cancel_socks.cancelled() => {
                        log::info!("SOCKS listener cancelled");
                        break;
                    }
                }
            }
        });

        *self.session.lock().await = Some(session);
        self.stats.lock().await.connected = true;
        log::info!("connect completed successfully");

        Ok(())
    }

    pub async fn disconnect(&self) -> Result<()> {
        if let Some(s) = self.session.lock().await.take() {
            s.cancel.cancel();
        }
        *self.socks_listener.lock().await = None;
        self.stats.lock().await.connected = false;
        log::info!("disconnected");
        Ok(())
    }

    pub async fn get_stats(&self) -> ProxyStats {
        let mut stats = self.stats.lock().await.clone();
        if let Some(session) = self.session.lock().await.as_ref() {
            stats.streams = session.streams.lock().await.len();
            stats.bytes_sent = session.bytes_sent.load(std::sync::atomic::Ordering::Relaxed);
            stats.bytes_recv = session.bytes_recv.load(std::sync::atomic::Ordering::Relaxed);
            if let Some(connected_at) = *session.connected_at.lock().await {
                stats.uptime_secs = connected_at.elapsed().as_secs();
            }
        }
        stats
    }

    pub async fn get_profiles(&self) -> Vec<ProxyConfig> {
        self.profiles.lock().await.clone()
    }

    pub async fn save_profile(&self, profile: ProxyConfig) -> Result<()> {
        let mut profiles = self.profiles.lock().await;
        if let Some(idx) = profiles.iter().position(|p| p.name == profile.name) {
            profiles[idx] = profile;
        } else {
            profiles.push(profile);
        }
        save_profiles(&profiles)?;
        Ok(())
    }

    pub async fn delete_profile(&self, name: &str) -> Result<()> {
        let mut profiles = self.profiles.lock().await;
        profiles.retain(|p| p.name != name);
        save_profiles(&profiles)?;
        Ok(())
    }

    fn start_reader_loop(
        &self,
        mut tls_read: tokio::io::ReadHalf<TlsStream>,
        client_cipher: Arc<Mutex<Cipher>>,
        streams: Arc<Mutex<HashMap<u32, tokio::net::tcp::OwnedWriteHalf>>>,
        bytes_recv: Arc<std::sync::atomic::AtomicU64>,
        cancel: tokio_util::sync::CancellationToken,
    ) {
        tokio::spawn(async move {
            loop {
                let mut len_buf = [0u8; 2];
                tokio::select! {
                    r = tls_read.read_exact(&mut len_buf) => {
                        if r.is_err() { break; }
                    }
                    _ = cancel.cancelled() => break,
                }
                let len = u16::from_be_bytes(len_buf) as usize;
                if len == 0 { break; }
                let mut blob = vec![0u8; len];
                if tls_read.read_exact(&mut blob).await.is_err() { break; }

                let mut cipher = client_cipher.lock().await;
                let plaintext = match cipher.decrypt(&blob) {
                    Ok(p) => p,
                    Err(_) => break,
                };
                drop(cipher);

                let frame = match Frame::decode(&plaintext) {
                    Ok(f) => f,
                    Err(_) => continue,
                };

                match frame.header.command {
                    MuxCommand::Data => {
                        let data = frame.real_data().to_vec();
                        let sid = frame.header.stream_id;
                        log::info!("reader: Data frame sid={} len={}", sid, data.len());
                        bytes_recv.fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
                        let mut streams = streams.lock().await;
                        if let Some(w) = streams.get_mut(&sid) {
                            let _ = w.write_all(&data).await;
                        } else {
                            log::warn!("reader: no stream for sid={}", sid);
                        }
                    }
                    MuxCommand::Close => {
                        log::info!("reader: Close frame sid={}", frame.header.stream_id);
                        streams.lock().await.remove(&frame.header.stream_id);
                    }
                    MuxCommand::NewStream => {
                        log::info!("reader: NewStream ack sid={}", frame.header.stream_id);
                    }
                    _ => {
                        log::info!("reader: frame cmd={:?} sid={}", frame.header.command, frame.header.stream_id);
                    }
                }
            }
        });
    }
}

async fn handle_socks5(
    mut sock: tokio::net::TcpStream,
    session: &Arc<Mutex<Option<ActiveSession>>>,
) -> Result<()> {
    log::info!("handle_socks5: new connection");
    let mut buf = [0u8; 256];
    sock.read_exact(&mut buf[..2]).await?;
    let nmethods = buf[1] as usize;
    sock.read_exact(&mut buf[..nmethods]).await?;
    sock.write_all(&[0x05, 0x00]).await?;

    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    if req[0] != 0x05 || req[1] != 0x01 {
        anyhow::bail!("unsupported socks5 command");
    }

    let target = match req[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            sock.read_exact(&mut ip).await?;
            format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], {
                let mut p = [0u8; 2];
                sock.read_exact(&mut p).await?;
                u16::from_be_bytes(p)
            })
        }
        0x03 => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            sock.read_exact(&mut domain).await?;
            let host = String::from_utf8_lossy(&domain);
            format!("{}:{}", host, {
                let mut p = [0u8; 2];
                sock.read_exact(&mut p).await?;
                u16::from_be_bytes(p)
            })
        }
        _ => anyhow::bail!("unsupported address type"),
    };

    let sess_guard = session.lock().await;
    let sess = sess_guard.as_ref().ok_or(anyhow::anyhow!("not connected"))?;

    let stream_id = {
        let mut sid = sess.next_sid.lock().await;
        let id = *sid;
        *sid = (*sid + 1) % (tundra_core::MAX_STREAMS as u32);
        id
    };

    log::info!("socks5 target: {} stream_id={}", target, stream_id);

    let open_frame = Frame::new(MuxCommand::NewStream, stream_id, target.as_bytes().to_vec());
    {
        let mut w = sess.write.lock().await;
        let mut sc = sess.send_cipher.lock().await;
        write_frame_to(&mut *w, &mut *sc, &open_frame).await?;
    }
    log::info!("socks5 NewStream sent, writing reply");

    let reply = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    sock.write_all(&reply).await?;

    let write = sess.write.clone();
    let send_cipher = sess.send_cipher.clone();
    let streams_map = sess.streams.clone();
    let bytes_sent = sess.bytes_sent.clone();
    drop(sess_guard);

    let (sock_r, sock_w) = sock.into_split();
    streams_map.lock().await.insert(stream_id, sock_w);

    let write_clone = write.clone();
    let sc_clone = send_cipher.clone();
    let bs_clone = bytes_sent.clone();
    let streams_clone = streams_map.clone();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        let mut sock_r = sock_r;
        loop {
            match sock_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let data = Frame::new_padded(MuxCommand::Data, stream_id, buf[..n].to_vec(), 0);
                    bs_clone.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                    let mut w = write_clone.lock().await;
                    let mut sc = sc_clone.lock().await;
                    if write_frame_to(&mut *w, &mut *sc, &data).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        streams_clone.lock().await.remove(&stream_id);
        let close = Frame::new(MuxCommand::Close, stream_id, vec![]);
        let mut w = write_clone.lock().await;
        let mut sc = sc_clone.lock().await;
        let _ = write_frame_to(&mut *w, &mut *sc, &close).await;
    });

    Ok(())
}

async fn write_frame_to(
    writer: &mut tokio::io::WriteHalf<TlsStream>,
    cipher: &mut Cipher,
    frame: &Frame,
) -> Result<()> {
    let plaintext = frame.encode();
    let encrypted = cipher.encrypt(&plaintext)?;
    let len = (encrypted.len() as u16).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(&encrypted).await?;
    Ok(())
}

async fn tls_connect(
    tcp: tokio::net::TcpStream,
    domain: &str,
) -> Result<TlsStream> {
    let provider = rustls::crypto::ring::default_provider();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[
            &rustls::version::TLS13,
            &rustls::version::TLS12,
        ])
        .expect("tls versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(domain.to_string())?;
    let tls = connector.connect(server_name, tcp).await?;
    Ok(tls)
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
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

fn profiles_path() -> std::path::PathBuf {
    let dir = dirs::config_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    dir.join("tundra").join("profiles.json")
}

fn load_profiles() -> Result<Vec<ProxyConfig>> {
    let path = profiles_path();
    if !path.exists() {
        return Ok(vec![]);
    }
    let data = std::fs::read_to_string(&path)?;
    let profiles: Vec<ProxyConfig> = serde_json::from_str(&data)?;
    Ok(profiles)
}

fn save_profiles(profiles: &[ProxyConfig]) -> Result<()> {
    let path = profiles_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(profiles)?;
    std::fs::write(&path, data)?;
    Ok(())
}
