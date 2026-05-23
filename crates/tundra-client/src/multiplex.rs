use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::task::JoinHandle;
use tundra_core::crypto::{self, Cipher, ROLE_CLIENT, ROLE_SERVER};
use tundra_core::frame::{Frame, MuxCommand};
use tundra_core::kem;
use rand::SeedableRng;
use tundra_fme::library::synthetic_generic_browsing;
use tundra_fme::model::{Direction, MorphedPacket};
use tundra_fme::morpher::Morpher;
use tracing::{debug, info};

use tokio::time::Duration;
use tokio_rustls::client::TlsStream;

type BoxedWrite = tokio::io::WriteHalf<TlsStream<TcpStream>>;

struct MorpherWrapper {
    morpher: Morpher,
}

impl MorpherWrapper {
    fn push_and_flush(&mut self, data: Vec<u8>, direction: Direction) -> Vec<MorphedPacket> {
        self.morpher.push(data, direction);
        let mut rng = rand_chacha::ChaCha12Rng::from_seed(rand::random());
        self.morpher.morph_flush(&mut rng)
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
    upstream_tx: mpsc::Sender<StreamEvent>,
    upstream_rx: Option<mpsc::Receiver<StreamEvent>>,
}

#[derive(Debug)]
pub struct StreamEvent {
    pub stream_id: u32,
    pub data: Vec<u8>,
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
            upstream_tx,
            upstream_rx: Some(upstream_rx),
        }
    }

    pub fn take_upstream_rx(&mut self) -> Option<mpsc::Receiver<StreamEvent>> {
        self.upstream_rx.take()
    }

    async fn establish_session(&self) -> Result<Arc<ActiveSession>> {
        let tcp = TcpStream::connect(&self.server_addr).await
            .context("connect to server")?;
        let connector = tokio_rustls::TlsConnector::from(self.tls_config.clone());
        let server_name = "tundra-server".try_into()
            .map_err(|e| anyhow::anyhow!("bad server name: {:?}", e))?;
        let tls_stream = connector.connect(server_name, tcp).await
            .context("TLS handshake")?;
        let (mut read, mut w) = tokio::io::split(tls_stream);

        let mut challenge_buf = vec![0u8; 4096];
        let challenge_n = read.read(&mut challenge_buf).await?;
        if challenge_n < 11 { anyhow::bail!("no challenge from server"); }
        let challenge_frame = Frame::decode(&challenge_buf[..challenge_n])?;
        if challenge_frame.header.command != MuxCommand::Challenge {
            anyhow::bail!("expected Challenge, got {:?}", challenge_frame.header.command);
        }
        let server_nonce: [u8; 16] = challenge_frame.payload[..16].try_into()
            .map_err(|_| anyhow::anyhow!("bad challenge nonce"))?;

        let kp = kem::generate_hybrid_keypair().context("hybrid KEM keypair")?;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
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

        let mut ack_buf = vec![0u8; 4096];
        let ack_n = read.read(&mut ack_buf).await?;
        if ack_n < 11 { anyhow::bail!("no auth ack"); }
        let ack = Frame::decode(&ack_buf[..ack_n])?;
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
        let streams_clone = streams.clone();
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
                            MuxCommand::Close => {
                                let _ = upstream_tx.send(StreamEvent {
                                    stream_id: sid,
                                    data: vec![],
                                    is_close: true,
                                }).await;
                                streams_clone.lock().await.retain(|&s| s != sid);
                            }
                            _ => {}
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let (pending_tx, fme_handle) = if self.use_fme {
            let (ptx, prx) = mpsc::channel::<PendingWrite>(256);
            let model = synthetic_generic_browsing();
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
        let should_churn = {
            let guard = self.active.read().await;
            if let Some(ref session) = *guard {
                let age = session.created_at.elapsed();
                let bytes = session.bytes_sent.load(std::sync::atomic::Ordering::Relaxed);
                age > self.max_session_age || bytes > self.max_session_bytes
            } else {
                false
            }
        };

        if should_churn {
            self.do_handover().await?;
        }

        {
            let guard = self.active.read().await;
            if let Some(ref session) = *guard {
                return Ok(session.clone());
            }
        }

        let session = self.establish_session().await?;
        info!("new TLS session established (fme={})", self.use_fme);
        let mut guard = self.active.write().await;
        *guard = Some(session.clone());
        Ok(session)
    }

    async fn do_handover(&self) -> Result<()> {
        let old = {
            let mut guard = self.active.write().await;
            guard.take()
        };

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

        let new_session = self.establish_session().await?;
        info!("handover: new session ready");
        let mut guard = self.active.write().await;
        *guard = Some(new_session);

        if self.check_draining_empty().await {
            let mut drain = self.draining.write().await;
            if let Some(ref s) = *drain {
                s.reader_handle.abort();
                if let Some(ref h) = s.fme_handle {
                    h.abort();
                }
            }
            *drain = None;
            info!("handover: drained session cleaned up");
        }

        Ok(())
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
