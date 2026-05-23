use crate::model::{Direction, MorphedPacket, SiteModel};
use crate::morpher::Morpher;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, Duration};

#[derive(Debug, Clone, Default)]
pub struct SchedulerMetrics {
    pub bytes_morphed: u64,
    pub packets_scheduled: u64,
    pub queue_depth: u64,
    pub avg_jitter_us: u64,
}

pub struct MorphScheduler {
    morpher: Arc<Mutex<Morpher>>,
    outbound_tx: mpsc::Sender<MorphedPacket>,
    metrics: Arc<SchedulerMetrics>,
}

impl MorphScheduler {
    pub fn new(model: SiteModel, buffer_size: usize) -> (Self, mpsc::Receiver<MorphedPacket>) {
        let (tx, rx) = mpsc::channel(buffer_size);
        let morpher = Arc::new(Mutex::new(Morpher::new(model)));
        let metrics = Arc::new(SchedulerMetrics::default());

        (
            Self {
                morpher,
                outbound_tx: tx,
                metrics,
            },
            rx,
        )
    }

    /// Feed raw data into the morpher.
    pub async fn feed(&self, data: Vec<u8>, direction: Direction) {
        let mut morpher = self.morpher.lock().await;
        morpher.push(data, direction);
    }

    /// Flush buffered data and schedule output packets with timing.
    /// Returns number of packets produced.
    pub async fn flush(&self) -> usize {
        let mut morpher = self.morpher.lock().await;
        let mut rng = rand::rng();
        let packets = morpher.morph_flush(&mut rng);

        let count = packets.len();
        for pkt in packets {
            let _ = self.outbound_tx.send(pkt).await;
        }

        count
    }

    pub fn metrics(&self) -> &SchedulerMetrics {
        &self.metrics
    }
}

/// Async task that drains the outbound channel and emits packets
/// with correct inter-packet delays.
pub async fn packet_emitter(
    mut rx: mpsc::Receiver<MorphedPacket>,
    mut callback: impl AsyncPacketSender,
) {
    while let Some(pkt) = rx.recv().await {
        if pkt.send_after_us > 0 {
            sleep(Duration::from_micros(pkt.send_after_us)).await;
        }
        callback.send(pkt).await;
    }
}

pub trait AsyncPacketSender: Send {
    fn send(&mut self, packet: MorphedPacket) -> impl std::future::Future<Output = ()> + Send;
}
