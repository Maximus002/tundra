use crate::chaff::ChaffGenerator;
use crate::distribution::{
    apply_adversarial_jitter, apply_size_noise, fill_random_padding, GaussianCache, IatSampler,
    SizeSampler,
};
use crate::model::*;
use rand::SeedableRng;
use std::collections::VecDeque;

type FastRng = rand::rngs::SmallRng;

const MTU: usize = 1460;
const HDR_SIZE: usize = 40;

pub struct MorphStats {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_out: u64,
    pub cover_packets: u64,
    pub chaff_packets: u64,
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
    up_size: SizeSampler,
    dn_size: SizeSampler,
    up_iat: IatSampler,
    dn_iat: IatSampler,
    chaff: ChaffGenerator,
    rng: FastRng,
    gaussian: GaussianCache,
    stats: MorphStats,
}

impl Morpher {
    pub fn new(model: SiteModel) -> Self {
        let up_size = SizeSampler::from_distribution(&model.upstream_sizes);
        let dn_size = SizeSampler::from_distribution(&model.downstream_sizes);
        let up_iat = IatSampler::from_generator(&model.iat_client);
        let dn_iat = IatSampler::from_generator(&model.iat_server);
        let chaff = ChaffGenerator::new(model.chaff.clone());
        Self {
            model,
            up_queue: VecDeque::new(),
            dn_queue: VecDeque::new(),
            up_size,
            dn_size,
            up_iat,
            dn_iat,
            chaff,
            rng: FastRng::from_os_rng(),
            gaussian: GaussianCache::new(),
            stats: MorphStats {
                bytes_in: 0,
                bytes_out: 0,
                packets_out: 0,
                cover_packets: 0,
                chaff_packets: 0,
            },
        }
    }

    pub fn push(&mut self, data: Vec<u8>, direction: Direction) {
        match direction {
            Direction::Upstream => self.up_queue.push_back(data),
            Direction::Downstream => self.dn_queue.push_back(data),
        }
    }

    pub fn morph_flush(&mut self) -> Vec<MorphedPacket> {
        let up_queue = std::mem::take(&mut self.up_queue);
        let dn_queue = std::mem::take(&mut self.dn_queue);
        let mut packets = Vec::new();

        {
            let size_dist = &self.model.upstream_sizes;
            let model = &self.model;
            let stats = &mut self.stats;
            let rng = &mut self.rng;
            let gaussian = &mut self.gaussian;
            let up_size = &mut self.up_size;
            let up_iat = &mut self.up_iat;
            drain_queue_into(up_queue, Direction::Upstream, model, size_dist, up_size, up_iat, rng, gaussian, stats, &mut packets);
        }
        {
            let size_dist = &self.model.downstream_sizes;
            let model = &self.model;
            let stats = &mut self.stats;
            let rng = &mut self.rng;
            let gaussian = &mut self.gaussian;
            let dn_size = &mut self.dn_size;
            let dn_iat = &mut self.dn_iat;
            drain_queue_into(dn_queue, Direction::Downstream, model, size_dist, dn_size, dn_iat, rng, gaussian, stats, &mut packets);
        }

        packets
    }

    pub fn generate_chaff(&mut self, elapsed_us: u64) -> Option<MorphedPacket> {
        if self.chaff.should_generate(elapsed_us) {
            let pkt = self.chaff.generate(&mut self.rng);
            self.stats.chaff_packets += 1;
            self.stats.packets_out += 1;
            self.stats.bytes_out += pkt.data.len() as u64;
            Some(pkt)
        } else {
            None
        }
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
            is_chaff: false,
        }]
    }

    pub fn stats(&self) -> &MorphStats {
        &self.stats
    }

    pub fn model(&self) -> &SiteModel {
        &self.model
    }

    pub fn reset_chaff(&mut self) {
        self.chaff.reset();
    }
}

fn drain_queue_into(
    queue: VecDeque<Vec<u8>>,
    direction: Direction,
    model: &SiteModel,
    size_dist: &SizeDistribution,
    size_sampler: &mut SizeSampler,
    iat_sampler: &mut IatSampler,
    rng: &mut FastRng,
    gaussian: &mut GaussianCache,
    stats: &mut MorphStats,
    output: &mut Vec<MorphedPacket>,
) {
    if queue.is_empty() {
        return;
    }

    let mut buf = Vec::new();
    for chunk in queue {
        stats.bytes_in += chunk.len() as u64;
        buf.extend(chunk);
    }

    let mut packets = Vec::new();
    let mut offset = 0;
    let max_payload = MTU.saturating_sub(HDR_SIZE);

    while offset < buf.len() {
        let mut target_size = size_sampler.next(size_dist, rng);
        if model.adversarial.enabled {
            target_size = apply_size_noise(target_size, model.adversarial.size_noise_pct, rng, gaussian);
        }
        let clamped_size = target_size.clamp(64, max_payload);

        let actual_data = (buf.len() - offset).min(clamped_size);
        let mut packet_data = buf[offset..offset + actual_data].to_vec();
        offset += actual_data;

        if packet_data.len() < clamped_size {
            let pad_start = packet_data.len();
            packet_data.resize(clamped_size, 0);
            if model.random_padding {
                fill_random_padding(&mut packet_data, pad_start, rng);
            }
        }

        let mut iat = iat_sampler.next_iat(rng);
        if model.adversarial.enabled {
            iat = apply_adversarial_jitter(iat, model.adversarial.jitter_pct, rng, gaussian);
        }

        stats.bytes_out += packet_data.len() as u64;
        stats.packets_out += 1;

        packets.push(MorphedPacket {
            data: packet_data,
            real_data_len: actual_data,
            direction,
            send_after_us: iat,
            is_chaff: false,
        });
    }

    enforce_overhead(model, stats, &mut packets);
    output.extend(packets);
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
                is_chaff: false,
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
            is_chaff: false,
        });
    }

    *packets = merged;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gmm_model() -> SiteModel {
        SiteModel {
            name: "test_gmm".into(),
            upstream_sizes: SizeDistribution::from_gmm(vec![
                GmmComponent { mean: 200.0, std_dev: 30.0, weight: 0.3 },
                GmmComponent { mean: 800.0, std_dev: 80.0, weight: 0.5 },
                GmmComponent { mean: 1400.0, std_dev: 40.0, weight: 0.2 },
            ]),
            downstream_sizes: SizeDistribution::from_gmm(vec![
                GmmComponent { mean: 500.0, std_dev: 50.0, weight: 0.4 },
                GmmComponent { mean: 1460.0, std_dev: 20.0, weight: 0.6 },
            ]),
            iat_client: IatGenerator::MarkovChain {
                states: vec![
                    MarkovState { mean_us: 100.0, std_dev_us: 30.0 },
                    MarkovState { mean_us: 2000.0, std_dev_us: 500.0 },
                    MarkovState { mean_us: 10000.0, std_dev_us: 2000.0 },
                ],
                transition: vec![
                    vec![0.6, 0.3, 0.1],
                    vec![0.2, 0.5, 0.3],
                    vec![0.4, 0.3, 0.3],
                ],
                initial_state: 0,
            },
            iat_server: IatGenerator::MarkovChain {
                states: vec![
                    MarkovState { mean_us: 50.0, std_dev_us: 15.0 },
                    MarkovState { mean_us: 500.0, std_dev_us: 100.0 },
                    MarkovState { mean_us: 5000.0, std_dev_us: 1000.0 },
                ],
                transition: vec![
                    vec![0.7, 0.2, 0.1],
                    vec![0.1, 0.6, 0.3],
                    vec![0.3, 0.4, 0.3],
                ],
                initial_state: 0,
            },
            burst_pattern: vec![
                BurstEntry { batch_size: 2, pause_us: 0, direction: Direction::Upstream },
                BurstEntry { batch_size: 6, pause_us: 150_000, direction: Direction::Downstream },
            ],
            init_window_client: 29200,
            init_window_server: 29200,
            keepalive_us: 30_000_000,
            overhead_budget: 1.0,
            granularity: MorphGranularity::PerBurst,
            chaff: ChaffConfig {
                enabled: true,
                min_interval_us: 500_000,
                max_interval_us: 2_000_000,
                size_distribution: SizeDistribution::from_histogram(&[64, 128, 256], 21),
                content: ChaffContent::RandomBytes,
                type_weights: vec![],
            },
            adversarial: AdversarialConfig {
                enabled: true,
                jitter_pct: 0.10,
                size_noise_pct: 0.05,
            },
            random_padding: true,
        }
    }

    fn histogram_model() -> SiteModel {
        let sizes = vec![64, 256, 512, 1024, 1460, 1460, 1460, 1460];
        let iats = vec![10, 50, 100, 500, 1000, 5000, 10000];
        SiteModel {
            name: "test_hist".into(),
            upstream_sizes: SizeDistribution::from_histogram(&sizes, 21),
            downstream_sizes: SizeDistribution::from_histogram(&sizes, 21),
            iat_client: IatGenerator::Histogram(CompactHistogram::new(&iats, 21)),
            iat_server: IatGenerator::Histogram(CompactHistogram::new(&iats, 21)),
            burst_pattern: vec![
                BurstEntry { batch_size: 3, pause_us: 100_000, direction: Direction::Upstream },
            ],
            init_window_client: 29200,
            init_window_server: 29200,
            keepalive_us: 30_000_000,
            overhead_budget: 1.0,
            granularity: MorphGranularity::PerBurst,
            chaff: ChaffConfig::default(),
            adversarial: AdversarialConfig::default(),
            random_padding: false,
        }
    }

    #[test]
    fn gmm_morpher_produces_valid_packets() {
        let mut morpher = Morpher::new(gmm_model());
        morpher.push(vec![0xAB; 5000], Direction::Upstream);
        let packets = morpher.morph_flush();
        assert!(!packets.is_empty());
        for pkt in &packets {
            assert!(pkt.data.len() >= 40, "packet too small: {}", pkt.data.len());
            assert!(pkt.data.len() <= MTU, "packet exceeds MTU: {}", pkt.data.len());
        }
    }

    #[test]
    fn gmm_morpher_preserves_data() {
        let mut morpher = Morpher::new(gmm_model());
        let original = vec![0x42; 2000];
        morpher.push(original.clone(), Direction::Downstream);
        let packets = morpher.morph_flush();
        let mut reassembled = Vec::new();
        for pkt in &packets {
            reassembled.extend_from_slice(&pkt.data[..pkt.real_data_len]);
        }
        assert_eq!(reassembled, original);
    }

    #[test]
    fn markov_iat_nonzero() {
        let mut morpher = Morpher::new(gmm_model());
        morpher.push(vec![0u8; 3000], Direction::Upstream);
        let packets = morpher.morph_flush();
        assert!(!packets.is_empty());
        assert!(packets.iter().all(|p| p.send_after_us > 0 || packets.len() == 1));
    }

    #[test]
    fn histogram_backward_compat() {
        let mut morpher = Morpher::new(histogram_model());
        morpher.push(vec![0u8; 5000], Direction::Upstream);
        let packets = morpher.morph_flush();
        assert!(!packets.is_empty());
        for pkt in &packets {
            assert!(pkt.data.len() >= 40);
            assert!(pkt.data.len() <= MTU);
        }
    }

    #[test]
    fn random_padding_nonzero() {
        let mut morpher = Morpher::new(gmm_model());
        morpher.push(vec![0x01; 10], Direction::Upstream);
        let packets = morpher.morph_flush();
        assert!(!packets.is_empty());
        let pkt = &packets[0];
        assert!(pkt.data.len() > 10, "should be padded");
        let has_nonzero_pad = pkt.data[10..].iter().any(|&b| b != 0);
        assert!(has_nonzero_pad, "padding should be random, not zeros");
    }

    #[test]
    fn chaff_generation() {
        let mut morpher = Morpher::new(gmm_model());
        let pkt = morpher.generate_chaff(1_000_000);
        assert!(pkt.is_some());
        let pkt = pkt.unwrap();
        assert!(pkt.is_chaff);
        assert_eq!(pkt.real_data_len, 0);
    }

    #[test]
    fn chaff_too_early() {
        let mut morpher = Morpher::new(gmm_model());
        let pkt = morpher.generate_chaff(10);
        assert!(pkt.is_none());
    }

    #[test]
    fn overhead_budget_enforced() {
        let mut model = gmm_model();
        model.overhead_budget = 0.2;
        let mut morpher = Morpher::new(model);
        morpher.push(vec![0u8; 50000], Direction::Upstream);
        let _packets = morpher.morph_flush();
        let overhead = morpher.stats().overhead_ratio();
        assert!(overhead <= 0.25, "overhead {} exceeds budget 0.2", overhead);
    }

    #[test]
    fn cover_traffic_after_keepalive() {
        let mut morpher = Morpher::new(gmm_model());
        let packets = morpher.generate_cover_traffic(35_000_000);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].data.len(), 40);
    }

    #[test]
    fn cover_traffic_before_keepalive() {
        let mut morpher = Morpher::new(gmm_model());
        let packets = morpher.generate_cover_traffic(10_000_000);
        assert!(packets.is_empty());
    }

    #[test]
    fn large_payload_morphing() {
        let mut morpher = Morpher::new(gmm_model());
        morpher.push(vec![0xAA; 100_000], Direction::Downstream);
        let packets = morpher.morph_flush();
        let mut reassembled = Vec::new();
        for pkt in &packets {
            reassembled.extend_from_slice(&pkt.data[..pkt.real_data_len]);
        }
        assert_eq!(reassembled.len(), 100_000);
        assert!(reassembled.iter().all(|&b| b == 0xAA));
    }
}
