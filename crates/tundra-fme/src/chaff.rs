use crate::model::{ChaffConfig, ChaffContent, ChaffTypeWeight, Direction, MorphedPacket};
use rand::Rng;

pub struct ChaffGenerator {
    config: ChaffConfig,
    last_chaff_us: u64,
    accumulator_us: u64,
}

impl ChaffGenerator {
    pub fn new(config: ChaffConfig) -> Self {
        Self {
            config,
            last_chaff_us: 0,
            accumulator_us: 0,
        }
    }

    pub fn should_generate(&mut self, elapsed_since_last_data_us: u64) -> bool {
        if !self.config.enabled {
            return false;
        }
        self.accumulator_us += elapsed_since_last_data_us;
        let threshold = if self.last_chaff_us == 0 {
            self.config.min_interval_us / 2
        } else {
            let mut rng = rand::rng();
            let range = (self.config.max_interval_us - self.config.min_interval_us) as f64;
            self.config.min_interval_us + (rng.random::<f64>() * range) as u64
        };
        if self.accumulator_us >= threshold {
            self.accumulator_us = 0;
            self.last_chaff_us = threshold;
            true
        } else {
            false
        }
    }

    pub fn generate(&self, rng: &mut impl Rng) -> MorphedPacket {
        let size = crate::distribution::sample_size(&self.config.size_distribution, rng);
        let size = size.clamp(64, 1420);

        let content = self.select_content(rng);

        let mut data = vec![0u8; size];
        match content {
            ChaffContent::RandomBytes => {
                rng.fill_bytes(&mut data);
            }
            ChaffContent::HttpLikeHeaders => {
                fill_http_like(&mut data, rng);
            }
            ChaffContent::DnsLikeQuery => {
                fill_dns_like(&mut data, rng);
            }
            ChaffContent::DummyTlsRecord => {
                fill_tls_record(&mut data, rng);
            }
            ChaffContent::Http2Frame => {
                fill_http2_frame(&mut data, rng);
            }
            ChaffContent::RandomHighEntropy => {
                rng.fill_bytes(&mut data);
            }
        }

        MorphedPacket {
            data,
            real_data_len: 0,
            direction: Direction::Upstream,
            send_after_us: 0,
            is_chaff: true,
        }
    }

    fn select_content(&self, rng: &mut impl Rng) -> ChaffContent {
        if self.config.type_weights.is_empty() {
            return self.config.content.clone();
        }
        let total: f64 = self.config.type_weights.iter().map(|w| w.weight).sum();
        let mut u = rng.random::<f64>() * total;
        for tw in &self.config.type_weights {
            u -= tw.weight;
            if u <= 0.0 {
                return tw.content.clone();
            }
        }
        self.config.type_weights.last().map(|tw| tw.content.clone())
            .unwrap_or_else(|| self.config.content.clone())
    }

    pub fn reset(&mut self) {
        self.accumulator_us = 0;
        self.last_chaff_us = 0;
    }
}

fn fill_http_like(data: &mut [u8], rng: &mut impl Rng) {
    let headers: &[&[u8]] = &[
        b"GET /static/",
        b"POST /api/v2/",
        b"GET /assets/",
        b"GET /favicon.ico",
        b"GET /images/",
    ];
    let header = headers[rng.random_range(0usize..headers.len())];    let header_len = header.len().min(data.len());
    data[..header_len].copy_from_slice(&header[..header_len]);
    if data.len() > header_len {
        rng.fill_bytes(&mut data[header_len..]);
    }
}

fn fill_dns_like(data: &mut [u8], rng: &mut impl Rng) {
    if data.len() < 16 {
        rng.fill_bytes(data);
        return;
    }
    let txid = rng.random::<u16>();
    data[0..2].copy_from_slice(&txid.to_be_bytes());
    data[2] = 0x01;
    data[3] = 0x00;
    data[4] = 0x00;
    data[5] = 0x01;
    data[6..12].copy_from_slice(&[0, 0, 0, 0, 0, 0]);
    let qname_start = 12;
    let labels: &[&[u8]] = &[b"www", b"cdn", b"static", b"api"];
    let mut pos = qname_start;
    for label in labels {
        if pos + label.len() + 1 >= data.len() { break; }
        data[pos] = label.len() as u8;
        pos += 1;
        data[pos..pos + label.len()].copy_from_slice(label);
        pos += label.len();    }
    if pos < data.len() { data[pos] = 0; pos += 1; }
    if pos + 4 <= data.len() {
        data[pos..pos + 2].copy_from_slice(&[0x00, 0x01]);
        data[pos + 2..pos + 4].copy_from_slice(&[0x00, 0x01]);
        pos += 4;
    }
    if pos < data.len() { rng.fill_bytes(&mut data[pos..]); }
}

fn fill_tls_record(data: &mut [u8], rng: &mut impl Rng) {
    if data.len() < 5 {
        rng.fill_bytes(data);
        return;
    }
    data[0] = 0x17;
    data[1] = 0x03;
    data[2] = 0x03;
    let payload_len = (data.len() - 5).min(u16::MAX as usize) as u16;
    data[3..5].copy_from_slice(&payload_len.to_be_bytes());
    rng.fill_bytes(&mut data[5..]);
}

fn fill_http2_frame(data: &mut [u8], rng: &mut impl Rng) {
    if data.len() < 9 {
        rng.fill_bytes(data);
        return;
    }
    let frame_types = [0x00u8, 0x01, 0x04, 0x08];
    let frame_type = frame_types[rng.random_range(0usize..frame_types.len())];
    let payload_len = (data.len() - 9).min((1 << 24) - 1);
    data[0] = ((payload_len >> 16) & 0xFF) as u8;
    data[1] = ((payload_len >> 8) & 0xFF) as u8;
    data[2] = (payload_len & 0xFF) as u8;
    data[3] = frame_type;
    data[4] = 0x04;
    let stream_id = rng.random_range(1u32..256);
    data[5..9].copy_from_slice(&stream_id.to_be_bytes());
    rng.fill_bytes(&mut data[9..]);
}

pub fn browser_chaff_weights() -> Vec<ChaffTypeWeight> {
    vec![
        ChaffTypeWeight { content: ChaffContent::DummyTlsRecord, weight: 0.5 },
        ChaffTypeWeight { content: ChaffContent::Http2Frame, weight: 0.3 },
        ChaffTypeWeight { content: ChaffContent::RandomHighEntropy, weight: 0.2 },
    ]
}

pub fn chat_chaff_weights() -> Vec<ChaffTypeWeight> {
    vec![
        ChaffTypeWeight { content: ChaffContent::DummyTlsRecord, weight: 0.4 },
        ChaffTypeWeight { content: ChaffContent::RandomHighEntropy, weight: 0.4 },
        ChaffTypeWeight { content: ChaffContent::Http2Frame, weight: 0.2 },
    ]
}

pub fn paranoid_chaff_weights() -> Vec<ChaffTypeWeight> {
    vec![
        ChaffTypeWeight { content: ChaffContent::RandomHighEntropy, weight: 0.4 },
        ChaffTypeWeight { content: ChaffContent::DummyTlsRecord, weight: 0.3 },
        ChaffTypeWeight { content: ChaffContent::Http2Frame, weight: 0.2 },
        ChaffTypeWeight { content: ChaffContent::DnsLikeQuery, weight: 0.1 },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SizeDistribution;

    fn test_config() -> ChaffConfig {
        ChaffConfig {
            enabled: true,
            min_interval_us: 100_000,
            max_interval_us: 500_000,
            size_distribution: SizeDistribution::from_histogram(&[64, 128, 256], 21),
            content: ChaffContent::RandomBytes,
            type_weights: vec![
                ChaffTypeWeight { content: ChaffContent::DummyTlsRecord, weight: 0.5 },
                ChaffTypeWeight { content: ChaffContent::Http2Frame, weight: 0.3 },
                ChaffTypeWeight { content: ChaffContent::RandomHighEntropy, weight: 0.2 },
            ],
        }
    }

    #[test]
    fn chaff_generator_produces_valid_packets() {
        let cg = ChaffGenerator::new(test_config());
        let mut rng = rand::rng();
        let pkt = cg.generate(&mut rng);
        assert!(pkt.data.len() >= 64);
        assert!(pkt.is_chaff);
        assert_eq!(pkt.real_data_len, 0);
    }

    #[test]
    fn chaff_generator_timing() {
        let mut cg = ChaffGenerator::new(test_config());
        assert!(cg.should_generate(200_000));
        cg.accumulator_us = 0;
        assert!(!cg.should_generate(10_000));
    }

    #[test]
    fn chaff_disabled() {
        let config = ChaffConfig { enabled: false, ..test_config() };
        let mut cg = ChaffGenerator::new(config);
        assert!(!cg.should_generate(1_000_000));
    }

    #[test]
    fn tls_record_content() {
        let config = ChaffConfig { content: ChaffContent::DummyTlsRecord, type_weights: vec![], ..test_config() };
        let cg = ChaffGenerator::new(config);
        let mut rng = rand::rng();
        let pkt = cg.generate(&mut rng);
        assert_eq!(pkt.data[0], 0x17);
        assert_eq!(pkt.data[1], 0x03);
        assert_eq!(pkt.data[2], 0x03);
    }

    #[test]
    fn http2_frame_content() {
        let config = ChaffConfig { content: ChaffContent::Http2Frame, type_weights: vec![], ..test_config() };
        let cg = ChaffGenerator::new(config);
        let mut rng = rand::rng();
        let pkt = cg.generate(&mut rng);
        assert!(pkt.data.len() >= 9);
        let frame_type = pkt.data[3];
        assert!(frame_type == 0x00 || frame_type == 0x01 || frame_type == 0x04 || frame_type == 0x08);
    }

    #[test]
    fn weighted_selection_varies() {
        let cg = ChaffGenerator::new(test_config());
        let mut rng = rand::rng();
        let mut seen_tls = false;
        let mut seen_h2 = false;
        for _ in 0..50 {
            let content = cg.select_content(&mut rng);
            match content {
                ChaffContent::DummyTlsRecord => seen_tls = true,
                ChaffContent::Http2Frame => seen_h2 = true,
                _ => {}
            }
        }
        assert!(seen_tls);
        assert!(seen_h2);
    }
}
