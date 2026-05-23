use crate::model::{Direction, MorphedPacket, SiteModel};
use rand::Rng;
use std::collections::VecDeque;

const MTU: usize = 1460;
const HDR_SIZE: usize = 40;

pub struct MorphStats {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_out: u64,
    pub cover_packets: u64,
}

impl MorphStats {
    pub fn overhead_ratio(&self) -> f64 {
        if self.bytes_in == 0 {
            return 0.0;
        }
        (self.bytes_out as f64 - self.bytes_in as f64) / self.bytes_in as f64
    }
}

pub struct Morpher {
    model: SiteModel,
    up_queue: VecDeque<Vec<u8>>,
    dn_queue: VecDeque<Vec<u8>>,
    stats: MorphStats,
}

impl Morpher {
    pub fn new(model: SiteModel) -> Self {
        Self {
            model,
            up_queue: VecDeque::new(),
            dn_queue: VecDeque::new(),
            stats: MorphStats {
                bytes_in: 0,
                bytes_out: 0,
                packets_out: 0,
                cover_packets: 0,
            },
        }
    }

    pub fn push(&mut self, data: Vec<u8>, direction: Direction) {
        match direction {
            Direction::Upstream => self.up_queue.push_back(data),
            Direction::Downstream => self.dn_queue.push_back(data),
        }
    }

    pub fn morph_flush(&mut self, rng: &mut impl Rng) -> Vec<MorphedPacket> {
        let mut packets = Vec::new();

        packets.extend(drain_queue(
            std::mem::take(&mut self.up_queue),
            Direction::Upstream,
            &self.model,
            &mut self.stats,
            rng,
        ));
        packets.extend(drain_queue(
            std::mem::take(&mut self.dn_queue),
            Direction::Downstream,
            &self.model,
            &mut self.stats,
            rng,
        ));

        packets
    }

    pub fn generate_cover_traffic(&mut self, elapsed_us: u64) -> Vec<MorphedPacket> {
        if elapsed_us < self.model.keepalive_us {
            return Vec::new();
        }

        self.stats.cover_packets += 1;
        self.stats.packets_out += 1;
        self.stats.bytes_out += 40;

        vec![MorphedPacket {
            data: vec![0u8; 40],
            real_data_len: 0,
            direction: Direction::Upstream,
            send_after_us: 0,
        }]
    }

    pub fn stats(&self) -> &MorphStats {
        &self.stats
    }

    pub fn model(&self) -> &SiteModel {
        &self.model
    }
}

fn drain_queue(
    mut queue: VecDeque<Vec<u8>>,
    direction: Direction,
    model: &SiteModel,
    stats: &mut MorphStats,
    rng: &mut impl Rng,
) -> Vec<MorphedPacket> {
    if queue.is_empty() {
        return Vec::new();
    }

    let hist = match direction {
        Direction::Upstream => &model.upstream_sizes,
        Direction::Downstream => &model.downstream_sizes,
    };
    let iat_hist = match direction {
        Direction::Upstream => &model.iat_client,
        Direction::Downstream => &model.iat_server,
    };

    let mut buf = Vec::new();
    while let Some(chunk) = queue.pop_front() {
        stats.bytes_in += chunk.len() as u64;
        buf.extend(chunk);
    }

    let mut packets = Vec::new();
    let mut offset = 0;
    let max_payload = MTU.saturating_sub(HDR_SIZE);

    while offset < buf.len() {
        let u: f64 = rng.random_range(0.0..1.0);
        let target_size = hist.sample(u) as usize;
        let clamped_size = target_size.clamp(64, max_payload);

        let actual_data = (buf.len() - offset).min(clamped_size);
        let mut packet_data = buf[offset..offset + actual_data].to_vec();
        offset += actual_data;

        // Always pad to target size, even if data is less
        if packet_data.len() < clamped_size {
            packet_data.resize(clamped_size, 0);
        }

        let iat_u: f64 = rng.random_range(0.0..1.0);
        let iat = iat_hist.sample(iat_u);

        stats.bytes_out += packet_data.len() as u64;
        stats.packets_out += 1;

        packets.push(MorphedPacket {
            data: packet_data,
            real_data_len: actual_data,
            direction,
            send_after_us: iat,
        });
    }

    enforce_overhead(model, stats, &mut packets);
    packets
}

fn enforce_overhead(
    model: &SiteModel,
    stats: &MorphStats,
    packets: &mut Vec<MorphedPacket>,
) {
    let overhead = stats.overhead_ratio();
    if overhead <= model.overhead_budget || packets.len() <= 1 {
        return;
    }

    let mut buf = Vec::new();
    let mut real_len_acc = 0usize;
    let mut merged = Vec::new();
    let max_payload = MTU.saturating_sub(HDR_SIZE);
    let mut last_dir = Direction::Upstream;

    for pkt in packets.drain(..) {
        if buf.len() + pkt.data.len() > max_payload && !buf.is_empty() {
            let send_after = merged.last().map_or(0, |p: &MorphedPacket| p.send_after_us) + 10;
            merged.push(MorphedPacket {
                data: std::mem::take(&mut buf),
                real_data_len: real_len_acc,
                direction: last_dir,
                send_after_us: send_after,
            });
            real_len_acc = 0;
        }
        real_len_acc += pkt.real_data_len;
        last_dir = pkt.direction;
        buf.extend(pkt.data);
    }
    if !buf.is_empty() {
        let send_after = merged.last().map_or(0, |p: &MorphedPacket| p.send_after_us) + 10;
        merged.push(MorphedPacket {
            data: buf,
            real_data_len: real_len_acc,
            direction: last_dir,
            send_after_us: send_after,
        });
    }

    *packets = merged;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BurstEntry, CompactHistogram, MorphGranularity};

    fn sample_model() -> SiteModel {
        let sizes = vec![64, 256, 512, 1024, 1460, 1460, 1460, 1460];
        let iats = vec![10, 50, 100, 500, 1000, 5000, 10000];
        SiteModel {
            name: "test".into(),
            upstream_sizes: CompactHistogram::new(&sizes, 21),
            downstream_sizes: CompactHistogram::new(&sizes, 21),
            iat_client: CompactHistogram::new(&iats, 21),
            iat_server: CompactHistogram::new(&iats, 21),
            burst_pattern: vec![
                BurstEntry { batch_size: 3, pause_us: 100_000, direction: Direction::Upstream },
                BurstEntry { batch_size: 8, pause_us: 200_000, direction: Direction::Downstream },
            ],
            init_window_client: 29200,
            init_window_server: 29200,
            keepalive_us: 30_000_000,
            overhead_budget: 1.0,
            granularity: MorphGranularity::PerBurst,
        }
    }

    #[test]
    fn morpher_produces_valid_packets() {
        let mut morpher = Morpher::new(sample_model());
        let mut rng = rand::rng();

        morpher.push(vec![0xAB; 5000], Direction::Upstream);

        let packets = morpher.morph_flush(&mut rng);
        assert!(!packets.is_empty());

        for pkt in &packets {
            assert!(pkt.data.len() >= 40, "packet too small: {}", pkt.data.len());
            assert!(pkt.data.len() <= MTU, "packet exceeds MTU: {}", pkt.data.len());
            assert_eq!(pkt.direction, Direction::Upstream);
        }
    }

    #[test]
    fn morpher_preserves_data() {
        let mut morpher = Morpher::new(sample_model());
        let mut rng = rand::rng();

        let original = vec![0x42; 2000];
        morpher.push(original.clone(), Direction::Downstream);

        let packets = morpher.morph_flush(&mut rng);
        let reassembled: Vec<u8> = packets.iter().flat_map(|p| p.data.clone()).collect();

        assert!(reassembled.len() >= original.len());
        assert_eq!(&reassembled[..original.len()], &original);
    }

    #[test]
    fn morpher_respects_overhead_budget() {
        let model = SiteModel {
            overhead_budget: 0.2,
            ..sample_model()
        };
        let mut morpher = Morpher::new(model);
        let mut rng = rand::rng();

        morpher.push(vec![0u8; 50000], Direction::Upstream);

        let _packets = morpher.morph_flush(&mut rng);
        let overhead = morpher.stats().overhead_ratio();

        assert!(
            overhead <= 0.25,
            "overhead {} exceeds budget 0.2 (with 5% tolerance)",
            overhead
        );
    }

    #[test]
    fn compact_histogram_sample_within_range() {
        let hist = CompactHistogram::new(&[100, 200, 500, 1000, 1460], 21);
        for _ in 0..1000 {
            let u = rand::rng().random_range(0.0..1.0);
            let v = hist.sample(u);
            assert!(v >= 100, "sample {} below min 100", v);
            assert!(v <= 1460, "sample {} above max 1460", v);
        }
    }

    #[test]
    fn compact_histogram_median() {
        let hist = CompactHistogram::new(&[100, 200, 500, 1000, 1460], 21);
        let median = hist.median();
        assert!((100..=1460).contains(&median));
    }

    #[test]
    fn morpher_iat_nonzero() {
        let mut morpher = Morpher::new(sample_model());
        let mut rng = rand::rng();

        morpher.push(vec![0u8; 3000], Direction::Upstream);
        let packets = morpher.morph_flush(&mut rng);

        assert!(!packets.is_empty());
        assert!(packets.iter().all(|p| p.send_after_us > 0 || packets.len() == 1));
    }
}
