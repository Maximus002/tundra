use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MorphGranularity {
    PerBurst,
    PerPacket,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurstEntry {
    pub batch_size: usize,
    pub pause_us: u64,
    pub direction: Direction,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Direction {
    Upstream,
    Downstream,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactHistogram {
    pub boundaries: Vec<u64>,
    pub resolution: usize,
}

impl CompactHistogram {
    pub fn new(values: &[u64], resolution: usize) -> Self {
        if values.is_empty() {
            return Self { boundaries: vec![0], resolution };
        }
        let n = values.len();
        let mut sorted = values.to_vec();
        sorted.sort_unstable();

        let points: Vec<f64> = (0..resolution)
            .map(|i| i as f64 / (resolution - 1) as f64)
            .collect();

        let boundaries: Vec<u64> = points
            .iter()
            .map(|&p| {
                let idx = ((p * (n - 1) as f64).round()) as usize;
                sorted[idx.min(n - 1)]
            })
            .collect();

        Self { boundaries, resolution }
    }

    pub fn sample(&self, u: f64) -> u64 {
        debug_assert!((0.0..=1.0).contains(&u));
        let scaled = u * (self.boundaries.len() - 1) as f64;
        let lo = scaled.floor() as usize;
        let hi = lo + 1;
        let frac = scaled - lo as f64;

        let lo_val = self.boundaries[lo] as f64;
        let hi_val = if hi < self.boundaries.len() {
            self.boundaries[hi] as f64
        } else {
            lo_val
        };

        (lo_val + frac * (hi_val - lo_val)) as u64
    }

    pub fn median(&self) -> u64 {
        self.sample(0.5)
    }

    pub fn mean(&self) -> f64 {
        if self.boundaries.len() < 2 {
            return self.boundaries[0] as f64;
        }
        let n = self.boundaries.len() - 1;
        let mut sum = self.boundaries[0] as f64 + self.boundaries[n] as f64;
        for i in 1..n {
            sum += 2.0 * self.boundaries[i] as f64;
        }
        sum / (2.0 * n as f64)
    }

    pub fn std_dev(&self) -> f64 {
        let m = self.mean();
        let n = self.boundaries.len();
        let variance: f64 = self
            .boundaries
            .iter()
            .map(|&v| {
                let d = v as f64 - m;
                d * d
            })
            .sum::<f64>()
            / n as f64;
        variance.sqrt()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmmComponent {
    pub mean: f64,
    pub std_dev: f64,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SizeDistribution {
    Histogram(CompactHistogram),
    GMM { components: Vec<GmmComponent> },
}

impl SizeDistribution {
    pub fn from_histogram(values: &[u64], resolution: usize) -> Self {
        SizeDistribution::Histogram(CompactHistogram::new(values, resolution))
    }

    pub fn from_gmm(components: Vec<GmmComponent>) -> Self {
        let total_weight: f64 = components.iter().map(|c| c.weight).sum();
        assert!(total_weight > 0.0, "GMM weights must sum > 0");
        SizeDistribution::GMM { components }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarkovState {
    pub mean_us: f64,
    pub std_dev_us: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IatGenerator {
    Histogram(CompactHistogram),
    MarkovChain {
        states: Vec<MarkovState>,
        transition: Vec<Vec<f64>>,
        #[serde(default)]
        initial_state: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChaffContent {
    RandomBytes,
    HttpLikeHeaders,
    DnsLikeQuery,
    DummyTlsRecord,
    Http2Frame,
    RandomHighEntropy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaffTypeWeight {
    pub content: ChaffContent,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaffConfig {
    pub enabled: bool,
    pub min_interval_us: u64,
    pub max_interval_us: u64,
    pub size_distribution: SizeDistribution,
    pub content: ChaffContent,
    #[serde(default)]
    pub type_weights: Vec<ChaffTypeWeight>,
}

impl Default for ChaffConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_interval_us: 800_000,
            max_interval_us: 3_000_000,
            size_distribution: SizeDistribution::from_histogram(&[64, 128, 256, 512], 21),
            content: ChaffContent::RandomBytes,
            type_weights: vec![],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ModelRotation {
    Never,
    PerSession,
    Hourly,
}

impl Default for ModelRotation {
    fn default() -> Self {
        ModelRotation::Never
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdversarialConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_jitter_pct")]
    pub jitter_pct: f64,
    #[serde(default = "default_size_noise_pct")]
    pub size_noise_pct: f64,
}

fn default_jitter_pct() -> f64 { 0.10 }
fn default_size_noise_pct() -> f64 { 0.05 }

impl Default for AdversarialConfig {
    fn default() -> Self {
        Self { enabled: false, jitter_pct: default_jitter_pct(), size_noise_pct: default_size_noise_pct() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MorphProfile {
    pub name: String,
    pub overhead_budget: f64,
    #[serde(default)]
    pub chaff: ChaffConfig,
    #[serde(default)]
    pub rotation: ModelRotation,
    #[serde(default)]
    pub adversarial: AdversarialConfig,
    #[serde(default)]
    pub random_padding: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteModel {
    pub name: String,
    pub upstream_sizes: SizeDistribution,
    pub downstream_sizes: SizeDistribution,
    pub iat_client: IatGenerator,
    pub iat_server: IatGenerator,
    pub burst_pattern: Vec<BurstEntry>,
    pub init_window_client: u32,
    pub init_window_server: u32,
    pub keepalive_us: u64,
    pub overhead_budget: f64,
    pub granularity: MorphGranularity,
    #[serde(default)]
    pub chaff: ChaffConfig,
    #[serde(default)]
    pub adversarial: AdversarialConfig,
    #[serde(default = "default_true")]
    pub random_padding: bool,
}

fn default_true() -> bool { true }

impl SiteModel {
    pub fn new(name: String) -> Self {
        Self {
            name,
            upstream_sizes: SizeDistribution::from_histogram(&[1460], 21),
            downstream_sizes: SizeDistribution::from_histogram(&[1460], 21),
            iat_client: IatGenerator::Histogram(CompactHistogram::new(&[1000], 21)),
            iat_server: IatGenerator::Histogram(CompactHistogram::new(&[1000], 21)),
            burst_pattern: vec![BurstEntry {
                batch_size: 3,
                pause_us: 50_000,
                direction: Direction::Upstream,
            }],
            init_window_client: 29200,
            init_window_server: 29200,
            keepalive_us: 30_000_000,
            overhead_budget: 0.5,
            granularity: MorphGranularity::PerBurst,
            chaff: ChaffConfig::default(),
            adversarial: AdversarialConfig::default(),
            random_padding: true,
        }
    }

    pub fn from_measurements(name: String, m: &TrafficMeasurements) -> Self {
        let up_sizes: Vec<u64> = m.upstream_sizes.iter().map(|&v| v as u64).collect();
        let dn_sizes: Vec<u64> = m.downstream_sizes.iter().map(|&v| v as u64).collect();
        let iat_c: Vec<u64> = m.iat_client_us.iter().map(|&v| v).collect();
        let iat_s: Vec<u64> = m.iat_server_us.iter().map(|&v| v).collect();

        let resolution = 41;
        Self {
            name,
            upstream_sizes: SizeDistribution::from_histogram(&up_sizes, resolution),
            downstream_sizes: SizeDistribution::from_histogram(&dn_sizes, resolution),
            iat_client: IatGenerator::Histogram(CompactHistogram::new(&iat_c, resolution)),
            iat_server: IatGenerator::Histogram(CompactHistogram::new(&iat_s, resolution)),
            burst_pattern: m.burst_pattern.clone(),
            init_window_client: m.init_window_client,
            init_window_server: m.init_window_server,
            keepalive_us: m.keepalive_us,
            overhead_budget: 0.5,
            granularity: MorphGranularity::PerBurst,
            chaff: ChaffConfig::default(),
            adversarial: AdversarialConfig::default(),
            random_padding: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TrafficMeasurements {
    pub upstream_sizes: Vec<usize>,
    pub downstream_sizes: Vec<usize>,
    pub iat_client_us: Vec<u64>,
    pub iat_server_us: Vec<u64>,
    pub burst_pattern: Vec<BurstEntry>,
    pub init_window_client: u32,
    pub init_window_server: u32,
    pub keepalive_us: u64,
}

impl TrafficMeasurements {
    pub fn merge(&mut self, other: &TrafficMeasurements) {
        self.upstream_sizes.extend(&other.upstream_sizes);
        self.downstream_sizes.extend(&other.downstream_sizes);
        self.iat_client_us.extend(&other.iat_client_us);
        self.iat_server_us.extend(&other.iat_server_us);
        if other.burst_pattern.len() > self.burst_pattern.len() {
            self.burst_pattern = other.burst_pattern.clone();
        }
        self.init_window_client = other.init_window_client;
        self.init_window_server = other.init_window_server;
        self.keepalive_us = other.keepalive_us;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MorphedPacket {
    pub data: Vec<u8>,
    pub real_data_len: usize,
    pub direction: Direction,
    pub send_after_us: u64,
    #[serde(default)]
    pub is_chaff: bool,
}
