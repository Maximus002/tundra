use crate::model::{CompactHistogram, GmmComponent, IatGenerator, MarkovState, SizeDistribution};
use rand::Rng;
use rand::SeedableRng;

type FastRng = rand::rngs::SmallRng;

pub fn box_muller(rng: &mut impl Rng) -> (f64, f64) {
    let u1: f64 = rng.random_range(1e-10..=1.0);
    let u2: f64 = rng.random();
    let r = (-2.0 * u1.ln()).sqrt();
    let theta = 2.0 * std::f64::consts::PI * u2;
    (r * theta.cos(), r * theta.sin())
}

pub struct GaussianCache {
    spare: Option<f64>,
}

impl GaussianCache {
    pub fn new() -> Self {
        Self { spare: None }
    }

    pub fn sample(&mut self, rng: &mut impl Rng, mean: f64, std_dev: f64) -> f64 {
        if let Some(s) = self.spare.take() {
            return mean + std_dev * s;
        }
        let (z0, z1) = box_muller(rng);
        self.spare = Some(z1);
        mean + std_dev * z0
    }
}

const SAMPLE_CACHE_SIZE: usize = 128;

pub struct SizeSampler {
    cache: Vec<usize>,
    pos: usize,
    gaussian: GaussianCache,
}

impl SizeSampler {
    pub fn from_distribution(dist: &SizeDistribution) -> Self {
        let mut sampler = Self {
            cache: Vec::with_capacity(SAMPLE_CACHE_SIZE),
            pos: SAMPLE_CACHE_SIZE,
            gaussian: GaussianCache::new(),
        };
        sampler.refill_cache_if_needed(dist);
        sampler
    }

    pub fn next(&mut self, dist: &SizeDistribution, rng: &mut impl Rng) -> usize {
        if self.pos >= self.cache.len() {
            self.refill(dist, rng);
        }
        let v = self.cache[self.pos];
        self.pos += 1;
        v
    }

    fn refill_cache_if_needed(&mut self, dist: &SizeDistribution) {
        if self.pos >= self.cache.len() {
            let mut tmp_rng = FastRng::from_os_rng();
            self.refill(dist, &mut tmp_rng);
        }
    }

    fn refill(&mut self, dist: &SizeDistribution, rng: &mut impl Rng) {
        self.cache.clear();
        self.pos = 0;
        for _ in 0..SAMPLE_CACHE_SIZE {
            self.cache.push(sample_size_inner(dist, rng, &mut self.gaussian));
        }
    }
}

fn sample_size_inner(dist: &SizeDistribution, rng: &mut impl Rng, gc: &mut GaussianCache) -> usize {
    match dist {
        SizeDistribution::Histogram(hist) => {
            let u: f64 = rng.random_range(0.0..1.0);
            hist.sample(u) as usize
        }
        SizeDistribution::GMM { components } => sample_gmm_inner(components, rng, gc),
    }
}

fn sample_gmm_inner(components: &[GmmComponent], rng: &mut impl Rng, gc: &mut GaussianCache) -> usize {
    let total_weight: f64 = components.iter().map(|c| c.weight).sum();
    let mut u: f64 = rng.random_range(0.0..total_weight);
    for comp in components {
        u -= comp.weight;
        if u <= 0.0 {
            return gc.sample(rng, comp.mean, comp.std_dev).max(64.0) as usize;
        }
    }
    let last = components.last().unwrap();
    gc.sample(rng, last.mean, last.std_dev).max(64.0) as usize
}

pub fn sample_size(dist: &SizeDistribution, rng: &mut impl Rng) -> usize {
    let mut gc = GaussianCache::new();
    sample_size_inner(dist, rng, &mut gc)
}

pub struct MarkovChainState {
    states: Vec<MarkovState>,
    transition: Vec<Vec<f64>>,
    current: usize,
    gaussian: GaussianCache,
}

impl MarkovChainState {
    pub fn new(states: Vec<MarkovState>, transition: Vec<Vec<f64>>, initial: usize) -> Self {
        let current = initial.min(states.len().saturating_sub(1));
        Self {
            states,
            transition,
            current,
            gaussian: GaussianCache::new(),
        }
    }

    pub fn next_iat(&mut self, rng: &mut impl Rng) -> u64 {
        let row = &self.transition[self.current];
        let mut u: f64 = rng.random();
        for (i, &prob) in row.iter().enumerate() {
            u -= prob;
            if u <= 0.0 {
                self.current = i;
                break;
            }
        }

        let state = &self.states[self.current];
        let val = self.gaussian.sample(rng, state.mean_us, state.std_dev_us);
        val.max(10.0) as u64
    }

    pub fn current_state(&self) -> usize {
        self.current
    }

    pub fn reset(&mut self, initial: usize) {
        self.current = initial.min(self.states.len().saturating_sub(1));
    }
}

pub struct IatSampler {
    inner: IatSamplerInner,
    cache: Vec<u64>,
    pos: usize,
}

enum IatSamplerInner {
    Histogram(CompactHistogram),
    Markov(MarkovChainState),
}

impl IatSampler {
    pub fn from_generator(src: &IatGenerator) -> Self {
        let inner = match src {
            IatGenerator::Histogram(hist) => IatSamplerInner::Histogram(hist.clone()),
            IatGenerator::MarkovChain { states, transition, initial_state } => {
                IatSamplerInner::Markov(MarkovChainState::new(
                    states.clone(),
                    transition.clone(),
                    *initial_state,
                ))
            }
        };
        Self {
            inner,
            cache: Vec::with_capacity(SAMPLE_CACHE_SIZE),
            pos: SAMPLE_CACHE_SIZE,
        }
    }

    pub fn next_iat(&mut self, rng: &mut impl Rng) -> u64 {
        if self.pos >= self.cache.len() {
            self.cache.clear();
            self.pos = 0;
            for _ in 0..SAMPLE_CACHE_SIZE {
                let val = match &mut self.inner {
                    IatSamplerInner::Histogram(hist) => {
                        let u: f64 = rng.random_range(0.0..1.0);
                        hist.sample(u)
                    }
                    IatSamplerInner::Markov(mc) => mc.next_iat(rng),
                };
                self.cache.push(val);
            }
        }
        let v = self.cache[self.pos];
        self.pos += 1;
        v
    }
}

pub fn apply_adversarial_jitter(value: u64, jitter_pct: f64, rng: &mut impl Rng, gc: &mut GaussianCache) -> u64 {
    if jitter_pct <= 0.0 {
        return value;
    }
    let noise = value as f64 * jitter_pct;
    let jitter = gc.sample(rng, 0.0, noise / 2.0);
    (value as f64 + jitter).max(10.0) as u64
}

pub fn apply_size_noise(size: usize, noise_pct: f64, rng: &mut impl Rng, gc: &mut GaussianCache) -> usize {
    if noise_pct <= 0.0 {
        return size;
    }
    let noise = size as f64 * noise_pct;
    let jitter = gc.sample(rng, 0.0, noise / 2.0);
    (size as f64 + jitter).max(64.0) as usize
}

pub fn fill_random_padding(data: &mut [u8], start: usize, rng: &mut impl Rng) {
    if start >= data.len() {
        return;
    }
    rng.fill_bytes(&mut data[start..]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn box_muller_pair() {
        let mut rng = rand::rng();
        for _ in 0..1000 {
            let (a, b) = box_muller(&mut rng);
            assert!(a.is_finite());
            assert!(b.is_finite());
        }
    }

    #[test]
    fn gaussian_cache_near_mean() {
        let mut rng = rand::rng();
        let mut gc = GaussianCache::new();
        let samples: Vec<f64> = (0..10000).map(|_| gc.sample(&mut rng, 500.0, 50.0)).collect();
        let mean = samples.iter().sum::<f64>() / samples.len() as f64;
        assert!((mean - 500.0).abs() < 5.0, "mean {} too far from 500", mean);
    }

    #[test]
    fn size_sampler_cache() {
        let dist = SizeDistribution::from_gmm(vec![
            GmmComponent { mean: 300.0, std_dev: 30.0, weight: 0.5 },
            GmmComponent { mean: 1200.0, std_dev: 80.0, weight: 0.5 },
        ]);
        let mut sampler = SizeSampler::from_distribution(&dist);
        let mut rng = FastRng::from_os_rng();
        for _ in 0..300 {
            let s = sampler.next(&dist, &mut rng);
            assert!(s >= 64);
        }
    }

    #[test]
    fn iat_sampler_cache() {
        let iat_src = IatGenerator::MarkovChain {
            states: vec![
                MarkovState { mean_us: 100.0, std_dev_us: 20.0 },
                MarkovState { mean_us: 1000.0, std_dev_us: 200.0 },
            ],
            transition: vec![vec![0.8, 0.2], vec![0.3, 0.7]],
            initial_state: 0,
        };
        let mut sampler = IatSampler::from_generator(&iat_src);
        let mut rng = FastRng::from_os_rng();
        for _ in 0..300 {
            let iat = sampler.next_iat(&mut rng);
            assert!(iat >= 10);
        }
    }

    #[test]
    fn markov_chain_transitions() {
        let states = vec![
            MarkovState { mean_us: 100.0, std_dev_us: 20.0 },
            MarkovState { mean_us: 1000.0, std_dev_us: 200.0 },
            MarkovState { mean_us: 5000.0, std_dev_us: 1000.0 },
        ];
        let transition = vec![
            vec![0.7, 0.2, 0.1],
            vec![0.1, 0.6, 0.3],
            vec![0.3, 0.3, 0.4],
        ];
        let mut mc = MarkovChainState::new(states, transition, 0);
        let mut rng = rand::rng();
        for _ in 0..100 {
            let iat = mc.next_iat(&mut rng);
            assert!(iat >= 10);
        }
    }

    #[test]
    fn adversarial_jitter_modifies_value() {
        let mut rng = rand::rng();
        let mut gc = GaussianCache::new();
        let orig = 1000u64;
        let mut changed = 0;
        for _ in 0..100 {
            let v = apply_adversarial_jitter(orig, 0.10, &mut rng, &mut gc);
            if v != orig { changed += 1; }
            assert!(v >= 10);
        }
        assert!(changed > 50, "jitter should modify most values, got {}/100", changed);
    }

    #[test]
    fn fill_random_padding_changes_bytes() {
        let mut data = vec![0u8; 100];
        fill_random_padding(&mut data, 50, &mut rand::rng());
        assert!(data[..50].iter().all(|&b| b == 0));
        assert!(data[50..].iter().any(|&b| b != 0));
    }
}
