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

/// A histogram that can be sampled from and serialized compactly.
/// Stores percentile boundaries instead of individual values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactHistogram {
    /// Percentile boundaries: [p0, p5, p10, ..., p95, p99, p100]
    pub boundaries: Vec<u64>,
    /// How many percentile points (uniform spacing, default 21 = every 5%)
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

    /// Sample a value via linear interpolation between percentile boundaries.
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
        // Trapezoidal integration
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

/// Statistical model of a site's traffic patterns, used for morphing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteModel {
    pub name: String,
    pub upstream_sizes: CompactHistogram,
    pub downstream_sizes: CompactHistogram,
    pub iat_client: CompactHistogram,
    pub iat_server: CompactHistogram,
    pub burst_pattern: Vec<BurstEntry>,
    pub init_window_client: u32,
    pub init_window_server: u32,
    pub keepalive_us: u64,
    pub overhead_budget: f64,
    pub granularity: MorphGranularity,
}

impl SiteModel {
    pub fn new(name: String) -> Self {
        Self {
            name,
            upstream_sizes: CompactHistogram::new(&[1460], 21),
            downstream_sizes: CompactHistogram::new(&[1460], 21),
            iat_client: CompactHistogram::new(&[1000], 21),
            iat_server: CompactHistogram::new(&[1000], 21),
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
            upstream_sizes: CompactHistogram::new(&up_sizes, resolution),
            downstream_sizes: CompactHistogram::new(&dn_sizes, resolution),
            iat_client: CompactHistogram::new(&iat_c, resolution),
            iat_server: CompactHistogram::new(&iat_s, resolution),
            burst_pattern: m.burst_pattern.clone(),
            init_window_client: m.init_window_client,
            init_window_server: m.init_window_server,
            keepalive_us: m.keepalive_us,
            overhead_budget: 0.5,
            granularity: MorphGranularity::PerBurst,
        }
    }
}

/// Raw traffic measurements, collected by the traffic collector.
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
}
