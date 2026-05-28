use anyhow::{Context, Result};
use std::sync::Arc;
use std::pin::Pin;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::task::JoinHandle;
use tundra_core::crypto::{self, Cipher, ROLE_CLIENT, ROLE_SERVER};
use tundra_core::frame::{Frame, MuxCommand};
use tundra_core::kem;
use tundra_fme::library::model_from_profile;
use tundra_fme::model::{Direction, MorphedPacket};
use tundra_fme::morpher::Morpher;
use tracing::{debug, info};

use tokio::time::Duration;

type BoxedWrite = Pin<Box<dyn tokio::io::AsyncWrite + Send + Unpin>>;
type BoxedRead = Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>;

struct MorpherWrapper {
    morpher: Morpher,
}

impl MorpherWrapper {
    fn push_and_flush(&mut self, data: Vec<u8>, direction: Direction) -> Vec<MorphedPacket> {
        self.morpher.push(data, direction);
        self.morpher.morph_flush()
    }
}

struct PendingWrite {
    stream_id: u32,
    data: Vec<u8>,
}

pub struct ActiveSession {
    write: Arc<Mutex<BoxedWrite>>,
    client_cipher: Arc<Cipher>,
    reader_handle: JoinHandle<()>,
    fme_handle: Option<JoinHandle<()>>,
    created_at: Instant,
    bytes_sent: std::sync::atomic::AtomicU64,
    next_stream_id: std::sync::atomic::AtomicU32,
    pub streams: Arc<Mutex<Vec<u32>>>,
    pending_tx: Option<mpsc::Sender<PendingWrite>>,
}

pub struct SessionPool {
    active: RwLock<Option<Arc<ActiveSession>>>,
    draining: RwLock<Option<Arc<ActiveSession>>>,
    server_addr: String,
    psk: Option<[u8; 32]>,
    tls_config: Arc<rustls::ClientConfig>,
    max_session_age: Duration,
    max_session_bytes: u64,
    use_fme: bool,
    fme_profile: String,
    transport: String,
    upstream_tx: mpsc::Sender<StreamEvent>,
    upstream_rx: Option<mpsc::Receiver<StreamEvent>>,
}

#[derive(Debug)]
pub struct StreamEvent {
    pub stream_id: u32,
    pub data: Vec<u8>,
    #[allow(dead_code)]
    pub is_close: bool,
}

impl SessionPool {
    pub fn new(
        server_addr: String,
        psk: Option<[u8; 32]>,
        tls_config: Arc<rustls::ClientConfig>,
        max_session_age: Duration,
        max_session_bytes: u64,
        use_fme: bool,
        fme_profile: String,
        transport: String,
    ) -> Self {
        let (upstream_tx, upstream_rx) = mpsc::channel(256);
        Self {
            active: RwLock::new(None),
            draining: RwLock::new(None),
            server_addr,
            psk,
            tls_config,
            max_session_age,
            max_session_bytes,
            use_fme,
            fme_profile,
            transport,
            upstream_tx,
            upstream_rx: Some(upstream_rx),
        }
    }

    async fn read_plaintext_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Frame> {
        let mut magic_buf = [0u8; 4];
        reader.read_exact(&mut magic_buf).await?;
        let magic = u32::from_be_bytes(magic_buf);
        if magic != tundra_core::MAGIC {
            anyhow::bail!("invalid magic in handshake frame");
        }
        let mut header_buf = [0u8; 7];
        reader.read_exact(&mut header_buf).await?;
        let payload_len = u16::from_be_bytes([header_buf[5], header_buf[6]]) as usize;
        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload).await?;

        let mut full = Vec::with_capacity(11 + payload_len);
        full.extend_from_slice(&magic_buf);
        full.extend_from_slice(&header_buf);
        full.extend_from_slice(&payload);
        Frame::decode(&full).map_err(|e| anyhow::anyhow!("frame decode: {:?}", e))
    }

    pub fn take_upstream_rx(&mut self) -> Option<mpsc::Receiver<StreamEvent>> {
        self.upstream_rx.take()
    }

    async fn establish_session(&self) -> Result<Arc<ActiveSession>> {
        let (mut read, mut w): (BoxedRead, BoxedWrite) = if self.transport == "quic" {
            let mut crypto = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
            crypto.alpn_protocols = vec![b"h3".to_vec(), b"h2".to_vec()];
            let quinn_client_config = quinn::ClientConfig::new(Arc::new(
                quinn_proto::crypto::rustls::QuicClientConfig::try_from(Arc::new(crypto))
                    .map_err(|e| anyhow::anyhow!("QUIC client config: {:?}", e))?
            ));
            let mut opts = quinn::TransportConfig::default();
            opts.keep_alive_interval(Some(Duration::from_secs(5)));
            let mut qcfg = quinn_client_config;
            qcfg.transport_config(Arc::new(opts));

            let addr = self.server_addr.parse::<std::net::SocketAddr>()
                .context("invalid server address for QUIC")?;
            let server_name = "tundra-server";
            let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
                .context("QUIC client endpoint")?;
            endpoint.set_default_client_config(qcfg);

            let conn = endpoint.connect(addr, server_name)
                .context("QUIC connect")?
                .await
                .context("QUIC handshake")?;
            let (send, recv) = conn.open_bi().await
                .context("QUIC open_bi")?;
            (Box::pin(recv) as BoxedRead, Box::pin(send) as BoxedWrite)
        } else {
            let tcp = TcpStream::connect(&self.server_addr).await
                .context("connect to server")?;
            let connector = tokio_rustls::TlsConnector::from(self.tls_config.clone());
            let server_name = "tundra-server".try_into()
                .map_err(|e| anyhow::anyhow!("bad server name: {:?}", e))?;
            let tls_stream = connector.connect(server_name, tcp).await
                .context("TLS handshake")?;
            let (r, w) = tokio::io::split(tls_stream);
            (Box::pin(r) as BoxedRead, Box::pin(w) as BoxedWrite)
        };

        let challenge_frame = Self::read_plaintext_frame(&mut read).await?;
        if challenge_frame.header.command != MuxCommand::Challenge {
            anyhow::bail!("expected Challenge, got {:?}", challenge_frame.header.command);
        }
        let server_nonce: [u8; 16] = challenge_frame.payload[..16].try_into()
            .map_err(|_| anyhow::anyhow!("bad challenge nonce"))?;

        let kp = kem::generate_hybrid_keypair().context("hybrid KEM keypair")?;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut auth_payload = Vec::with_capacity(8 + 32 + kem::HYBRID_PK_SIZE);
        auth_payload.extend_from_slice(&ts.to_le_bytes());
        if let Some(psk_bytes) = self.psk {
            let mut msg = Vec::with_capacity(16 + 8 + kem::HYBRID_PK_SIZE);
            msg.extend_from_slice(&server_nonce);
            msg.extend_from_slice(&ts.to_le_bytes());
            msg.extend_from_slice(&kp.kyber_pk);
            msg.extend_from_slice(&kp.x25519_pk);
            let hmac = blake3::keyed_hash(&psk_bytes, &msg);
            auth_payload.extend_from_slice(hmac.as_bytes());
        } else {
            auth_payload.extend_from_slice(&[0u8; 32]);
        }
        auth_payload.extend_from_slice(&kp.kyber_pk);
        auth_payload.extend_from_slice(&kp.x25519_pk);

        let auth_frame = Frame::new_handshake(MuxCommand::Auth, 0, auth_payload);
        w.write_all(&auth_frame.encode()).await?;

        let ack = Self::read_plaintext_frame(&mut read).await?;
        if ack.header.command != MuxCommand::AuthAck { anyhow::bail!("bad ack: {:?}", ack.header.command); }
        if ack.payload.len() < kem::HYBRID_CT_SIZE {
            anyhow::bail!("bad hybrid ct size: {}", ack.payload.len());
        }

        let kyber_ct = &ack.payload[..kem::KEM_CT_SIZE];
        let x25519_ct: [u8; 32] = ack.payload[kem::KEM_CT_SIZE..kem::HYBRID_CT_SIZE].try_into()
            .map_err(|_| anyhow::anyhow!("bad x25519 ct"))?;

        let shared_secret = kem::hybrid_decapsulate(&kp, kyber_ct, &x25519_ct)
            .context("hybrid KEM decapsulate")?;

        let client_enc_key = crypto::derive_key(&shared_secret, b"client-enc");
        let server_enc_key = crypto::derive_key(&shared_secret, b"server-enc");
        let client_cipher = Arc::new(Cipher::new_with_role(&client_enc_key, ROLE_CLIENT));
        let server_cipher = Cipher::new_with_role(&server_enc_key, ROLE_SERVER);

        let kc_hash = blake3::keyed_hash(&client_enc_key, b"tundra-key-confirm-c2s");
        let kc_frame = Frame::new(MuxCommand::KeyConfirm, 0, kc_hash.as_bytes().to_vec());
        let kc_encoded = kc_frame.encode();
        let kc_encrypted = client_cipher.encrypt(&kc_encoded)?;
        let len = (kc_encrypted.len() as u16).to_be_bytes();
        w.write_all(&len).await?;
        w.write_all(&kc_encrypted).await?;

        let mut s2c_len_buf = [0u8; 2];
        read.read_exact(&mut s2c_len_buf).await?;
        let s2c_len = u16::from_be_bytes(s2c_len_buf) as usize;
        if s2c_len == 0 { anyhow::bail!("empty server key confirm"); }
        let mut s2c_blob = vec![0u8; s2c_len];
        read.read_exact(&mut s2c_blob).await?;
        let s2c_plain = server_cipher.decrypt(&s2c_blob)?;
        let s2c_frame = Frame::decode(&s2c_plain)?;
        if s2c_frame.header.command != MuxCommand::KeyConfirm {
            anyhow::bail!("expected KeyConfirm from server, got {:?}", s2c_frame.header.command);
        }
        let expected_s2c = blake3::keyed_hash(&server_enc_key, b"tundra-key-confirm-s2c");
        if !crypto::constant_time_eq(s2c_frame.payload.get(..32).unwrap_or(&[]), expected_s2c.as_bytes()) {
            anyhow::bail!("server KeyConfirm mismatch");
        }

        let write: Arc<Mutex<BoxedWrite>> = Arc::new(Mutex::new(w));

        let streams: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let upstream_tx = self.upstream_tx.clone();

        let reader_handle = tokio::spawn(async move {
            let mut sc = server_cipher;
            loop {
                match Self::read_frame_inner(&mut read, &mut sc).await {
                    Ok(frame) => {
                        let sid = frame.header.stream_id;
                        match frame.header.command {
                            MuxCommand::Data => {
                                let data = frame.real_data().to_vec();
                                if !data.is_empty() {
                                    let _ = upstream_tx.send(StreamEvent {
                                        stream_id: sid,
                                        data,
                                        is_close: false,
                                    }).await;
                                }
                            }
                            MuxCommand::NewStream => {}
                            MuxCommand::Close => {}
                            _ => {}
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let (pending_tx, fme_handle) = if self.use_fme {
                let (ptx, prx) = mpsc::channel::<PendingWrite>(256);
                let model = model_from_profile(&self.fme_profile);
                let scheduler = Arc::new(Mutex::new(MorpherWrapper {
                morpher: tundra_fme::morpher::Morpher::new(model),
            }));

            let write_clone = write.clone();
            let cipher_clone = client_cipher.clone();

            let fme_h = tokio::spawn(async move {
                Self::fme_writer_loop(prx, scheduler, write_clone, cipher_clone).await;
            });

            (Some(ptx), Some(fme_h))
        } else {
            (None, None)
        };

        Ok(Arc::new(ActiveSession {
            write,
            client_cipher,
            reader_handle,
            fme_handle,
            created_at: Instant::now(),
            bytes_sent: std::sync::atomic::AtomicU64::new(0),
            next_stream_id: std::sync::atomic::AtomicU32::new(1),
            streams,
            pending_tx,
        }))
    }

    async fn fme_writer_loop(
        mut pending_rx: mpsc::Receiver<PendingWrite>,
        morpher: Arc<Mutex<MorpherWrapper>>,
        write: Arc<Mutex<BoxedWrite>>,
        cipher: Arc<Cipher>,
    ) {
        while let Some(pw) = pending_rx.recv().await {
            let packets = {
                let mut m = morpher.lock().await;
                m.push_and_flush(pw.data, Direction::Upstream)
            };

            for (i, pkt) in packets.iter().enumerate() {
                if i > 0 && pkt.send_after_us > 0 {
                    tokio::time::sleep(Duration::from_micros(pkt.send_after_us)).await;
                }
                let real = pkt.data[..pkt.real_data_len].to_vec();
                let frame = Frame::new_padded(
                    MuxCommand::Data, pw.stream_id, real, pkt.data.len(),
                );
                let mut w = write.lock().await;
                if Self::write_frame_inner(&mut *w, &cipher, &frame).await.is_err() {
                    return;
                }
            }
        }
    }

    pub async fn get_or_create_session(&self) -> Result<Arc<ActiveSession>> {
        let mut guard = self.active.write().await;

        if let Some(ref session) = *guard {
            let age = session.created_at.elapsed();
            let bytes = session.bytes_sent.load(std::sync::atomic::Ordering::Relaxed);
            if age > self.max_session_age || bytes > self.max_session_bytes {
                let old = guard.take();
                if let Some(old_session) = old {
                    info!("session churn: handover started (age={:.0}s, bytes={})",
                          old_session.created_at.elapsed().as_secs_f64(),
                          old_session.bytes_sent.load(std::sync::atomic::Ordering::Relaxed));
                    if let Some(ref h) = old_session.fme_handle {
                        h.abort();
                    }
                    let mut drain = self.draining.write().await;
                    if let Some(ref prev) = *drain {
                        prev.reader_handle.abort();
                        if let Some(ref h) = prev.fme_handle {
                            h.abort();
                        }
                    }
                    *drain = Some(old_session);
                }
            }
        }

        if let Some(ref session) = *guard {
            return Ok(session.clone());
        }

        drop(guard);

        let session = self.establish_session().await?;
        info!("new TLS session established (fme={})", self.use_fme);

        let mut guard = self.active.write().await;
        if let Some(ref existing) = *guard {
            return Ok(existing.clone());
        }
        *guard = Some(session.clone());
        Ok(session)
    }

    async fn check_draining_empty(&self) -> bool {
        let drain = self.draining.read().await;
        if let Some(ref session) = *drain {
            session.streams.lock().await.is_empty()
        } else {
            true
        }
    }

    pub async fn open_stream(&self, target: &str) -> Result<(u32, Arc<ActiveSession>)> {
        let session = self.get_or_create_session().await?;
        let stream_id = session.next_stream_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if stream_id >= tundra_core::MAX_STREAMS as u32 {
            anyhow::bail!("stream id exhausted");
        }

        let open_frame = Frame::new(MuxCommand::NewStream, stream_id, target.as_bytes().to_vec());
        {
            let mut w = session.write.lock().await;
            Self::write_frame_inner(&mut *w, &session.client_cipher, &open_frame).await?;
        }

        session.streams.lock().await.push(stream_id);
        session.bytes_sent.fetch_add(
            open_frame.encode().len() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );

        debug!("opened stream {} -> {}", stream_id, target);
        Ok((stream_id, session))
    }

    pub async fn send_data(&self, session: &ActiveSession, stream_id: u32, data: Vec<u8>) -> Result<()> {
        if let Some(ref tx) = session.pending_tx {
            tx.send(PendingWrite { stream_id, data }).await
                .map_err(|_| anyhow::anyhow!("fme channel closed"))?;
        } else {
            let frame = Frame::new_padded(MuxCommand::Data, stream_id, data, 0);
            {
                let mut w = session.write.lock().await;
                Self::write_frame_inner(&mut *w, &session.client_cipher, &frame).await?;
            }
            session.bytes_sent.fetch_add(
                frame.encode().len() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        Ok(())
    }

    pub async fn close_stream(&self, session: &ActiveSession, stream_id: u32) -> Result<()> {
        let frame = Frame::new(MuxCommand::Close, stream_id, vec![]);
        {
            let mut w = session.write.lock().await;
            Self::write_frame_inner(&mut *w, &session.client_cipher, &frame).await?;
        }
        session.streams.lock().await.retain(|&s| s != stream_id);
        debug!("closed stream {}", stream_id);
        Ok(())
    }

    pub async fn send_ping(&self, session: &ActiveSession) -> Result<()> {
        let frame = Frame::new(MuxCommand::Ping, 0, vec![]);
        let mut w = session.write.lock().await;
        Self::write_frame_inner(&mut *w, &session.client_cipher, &frame).await?;
        Ok(())
    }

    async fn write_frame_inner(
        writer: &mut (impl AsyncWriteExt + Unpin + ?Sized),
        cipher: &Cipher,
        frame: &Frame,
    ) -> Result<()> {
        let plaintext = frame.encode();
        let encrypted = cipher.encrypt(&plaintext)?;
        anyhow::ensure!(encrypted.len() <= u16::MAX as usize, "encrypted frame too large");
        let len = encrypted.len() as u16;
        writer.write_all(&len.to_be_bytes()).await?;
        writer.write_all(&encrypted).await?;
        Ok(())
    }

    async fn read_frame_inner(
        reader: &mut (impl AsyncReadExt + Unpin),
        cipher: &Cipher,
    ) -> Result<Frame> {
        let mut len_buf = [0u8; 2];
        reader.read_exact(&mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 { anyhow::bail!("zero frame len"); }
        let mut blob = vec![0u8; len];
        reader.read_exact(&mut blob).await?;
        let plaintext = cipher.decrypt(&blob)?;
        Frame::decode(&plaintext).context("bad frame")
    }

    pub async fn shutdown(&self) {
        if let Some(ref session) = *self.active.read().await {
            session.reader_handle.abort();
            if let Some(h) = session.fme_handle.as_ref() {
                h.abort();
            }
        }
        if let Some(ref session) = *self.draining.read().await {
            session.reader_handle.abort();
            if let Some(h) = session.fme_handle.as_ref() {
                h.abort();
            }
        }
    }
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
        ]
    }
}
