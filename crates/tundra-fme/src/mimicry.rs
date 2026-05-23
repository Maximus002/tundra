use crate::model::*;

pub fn chrome_like_model() -> SiteModel {
    SiteModel {
        name: "chrome_tls".into(),
        upstream_sizes: SizeDistribution::from_gmm(vec![
            GmmComponent { mean: 80.0, std_dev: 20.0, weight: 0.25 },
            GmmComponent { mean: 350.0, std_dev: 60.0, weight: 0.35 },
            GmmComponent { mean: 700.0, std_dev: 100.0, weight: 0.25 },
            GmmComponent { mean: 1420.0, std_dev: 30.0, weight: 0.15 },
        ]),
        downstream_sizes: SizeDistribution::from_gmm(vec![
            GmmComponent { mean: 200.0, std_dev: 40.0, weight: 0.15 },
            GmmComponent { mean: 800.0, std_dev: 100.0, weight: 0.25 },
            GmmComponent { mean: 1460.0, std_dev: 15.0, weight: 0.60 },
        ]),
        iat_client: IatGenerator::MarkovChain {
            states: vec![
                MarkovState { mean_us: 50.0, std_dev_us: 15.0 },
                MarkovState { mean_us: 500.0, std_dev_us: 100.0 },
                MarkovState { mean_us: 5000.0, std_dev_us: 1500.0 },
                MarkovState { mean_us: 50000.0, std_dev_us: 10000.0 },
            ],
            transition: vec![
                vec![0.5, 0.3, 0.15, 0.05],
                vec![0.2, 0.4, 0.3, 0.1],
                vec![0.1, 0.2, 0.5, 0.2],
                vec![0.4, 0.3, 0.2, 0.1],
            ],
            initial_state: 0,
        },
        iat_server: IatGenerator::MarkovChain {
            states: vec![
                MarkovState { mean_us: 30.0, std_dev_us: 10.0 },
                MarkovState { mean_us: 300.0, std_dev_us: 80.0 },
                MarkovState { mean_us: 3000.0, std_dev_us: 500.0 },
                MarkovState { mean_us: 30000.0, std_dev_us: 8000.0 },
            ],
            transition: vec![
                vec![0.6, 0.3, 0.08, 0.02],
                vec![0.15, 0.5, 0.3, 0.05],
                vec![0.05, 0.15, 0.6, 0.2],
                vec![0.3, 0.2, 0.3, 0.2],
            ],
            initial_state: 0,
        },
        burst_pattern: vec![
            BurstEntry { batch_size: 1, pause_us: 0, direction: Direction::Upstream },
            BurstEntry { batch_size: 4, pause_us: 80_000, direction: Direction::Downstream },
            BurstEntry { batch_size: 2, pause_us: 200_000, direction: Direction::Upstream },
            BurstEntry { batch_size: 8, pause_us: 100_000, direction: Direction::Downstream },
        ],
        init_window_client: 29200,
        init_window_server: 29200,
        keepalive_us: 45_000_000,
        overhead_budget: 0.5,
        granularity: MorphGranularity::PerBurst,
        chaff: ChaffConfig {
            enabled: true,
            min_interval_us: 1_000_000,
            max_interval_us: 5_000_000,
            size_distribution: SizeDistribution::from_gmm(vec![
                GmmComponent { mean: 100.0, std_dev: 30.0, weight: 0.5 },
                GmmComponent { mean: 400.0, std_dev: 60.0, weight: 0.5 },
            ]),
            content: ChaffContent::RandomBytes,
            type_weights: crate::chaff::browser_chaff_weights(),
        },
        adversarial: AdversarialConfig {
            enabled: true,
            jitter_pct: 0.08,
            size_noise_pct: 0.03,
        },
        random_padding: true,
    }
}

pub fn firefox_like_model() -> SiteModel {
    SiteModel {
        name: "firefox_tls".into(),
        upstream_sizes: SizeDistribution::from_gmm(vec![
            GmmComponent { mean: 90.0, std_dev: 25.0, weight: 0.3 },
            GmmComponent { mean: 400.0, std_dev: 70.0, weight: 0.3 },
            GmmComponent { mean: 750.0, std_dev: 80.0, weight: 0.25 },
            GmmComponent { mean: 1420.0, std_dev: 30.0, weight: 0.15 },
        ]),
        downstream_sizes: SizeDistribution::from_gmm(vec![
            GmmComponent { mean: 250.0, std_dev: 50.0, weight: 0.2 },
            GmmComponent { mean: 900.0, std_dev: 120.0, weight: 0.3 },
            GmmComponent { mean: 1460.0, std_dev: 15.0, weight: 0.5 },
        ]),
        iat_client: IatGenerator::MarkovChain {
            states: vec![
                MarkovState { mean_us: 60.0, std_dev_us: 20.0 },
                MarkovState { mean_us: 600.0, std_dev_us: 150.0 },
                MarkovState { mean_us: 6000.0, std_dev_us: 2000.0 },
                MarkovState { mean_us: 60000.0, std_dev_us: 15000.0 },
            ],
            transition: vec![
                vec![0.45, 0.35, 0.15, 0.05],
                vec![0.15, 0.45, 0.30, 0.10],
                vec![0.08, 0.18, 0.50, 0.24],
                vec![0.35, 0.25, 0.25, 0.15],
            ],
            initial_state: 0,
        },
        iat_server: IatGenerator::MarkovChain {
            states: vec![
                MarkovState { mean_us: 40.0, std_dev_us: 12.0 },
                MarkovState { mean_us: 400.0, std_dev_us: 100.0 },
                MarkovState { mean_us: 4000.0, std_dev_us: 800.0 },
                MarkovState { mean_us: 40000.0, std_dev_us: 12000.0 },
            ],
            transition: vec![
                vec![0.55, 0.30, 0.10, 0.05],
                vec![0.12, 0.50, 0.30, 0.08],
                vec![0.06, 0.14, 0.55, 0.25],
                vec![0.25, 0.20, 0.30, 0.25],
            ],
            initial_state: 0,
        },
        burst_pattern: vec![
            BurstEntry { batch_size: 1, pause_us: 0, direction: Direction::Upstream },
            BurstEntry { batch_size: 5, pause_us: 100_000, direction: Direction::Downstream },
            BurstEntry { batch_size: 3, pause_us: 300_000, direction: Direction::Upstream },
            BurstEntry { batch_size: 10, pause_us: 80_000, direction: Direction::Downstream },
        ],
        init_window_client: 29200,
        init_window_server: 29200,
        keepalive_us: 45_000_000,
        overhead_budget: 0.5,
        granularity: MorphGranularity::PerBurst,
        chaff: ChaffConfig {
            enabled: true,
            min_interval_us: 1_200_000,
            max_interval_us: 4_000_000,
            size_distribution: SizeDistribution::from_gmm(vec![
                GmmComponent { mean: 120.0, std_dev: 40.0, weight: 0.6 },
                GmmComponent { mean: 500.0, std_dev: 80.0, weight: 0.4 },
            ]),
            content: ChaffContent::HttpLikeHeaders,
            type_weights: crate::chaff::browser_chaff_weights(),
        },
        adversarial: AdversarialConfig {
            enabled: true,
            jitter_pct: 0.10,
            size_noise_pct: 0.04,
        },
        random_padding: true,
    }
}

pub fn http2_multiplexed_model() -> SiteModel {
    SiteModel {
        name: "http2_multiplexed".into(),
        upstream_sizes: SizeDistribution::from_gmm(vec![
            GmmComponent { mean: 40.0, std_dev: 10.0, weight: 0.35 },
            GmmComponent { mean: 200.0, std_dev: 40.0, weight: 0.35 },
            GmmComponent { mean: 600.0, std_dev: 80.0, weight: 0.20 },
            GmmComponent { mean: 1400.0, std_dev: 40.0, weight: 0.10 },
        ]),
        downstream_sizes: SizeDistribution::from_gmm(vec![
            GmmComponent { mean: 100.0, std_dev: 30.0, weight: 0.20 },
            GmmComponent { mean: 500.0, std_dev: 80.0, weight: 0.30 },
            GmmComponent { mean: 1460.0, std_dev: 15.0, weight: 0.50 },
        ]),
        iat_client: IatGenerator::MarkovChain {
            states: vec![
                MarkovState { mean_us: 20.0, std_dev_us: 8.0 },
                MarkovState { mean_us: 200.0, std_dev_us: 50.0 },
                MarkovState { mean_us: 2000.0, std_dev_us: 400.0 },
                MarkovState { mean_us: 20000.0, std_dev_us: 5000.0 },
            ],
            transition: vec![
                vec![0.6, 0.25, 0.10, 0.05],
                vec![0.20, 0.50, 0.25, 0.05],
                vec![0.10, 0.20, 0.50, 0.20],
                vec![0.30, 0.25, 0.25, 0.20],
            ],
            initial_state: 0,
        },
        iat_server: IatGenerator::MarkovChain {
            states: vec![
                MarkovState { mean_us: 15.0, std_dev_us: 5.0 },
                MarkovState { mean_us: 150.0, std_dev_us: 40.0 },
                MarkovState { mean_us: 1500.0, std_dev_us: 300.0 },
                MarkovState { mean_us: 15000.0, std_dev_us: 4000.0 },
            ],
            transition: vec![
                vec![0.65, 0.25, 0.08, 0.02],
                vec![0.15, 0.55, 0.25, 0.05],
                vec![0.05, 0.15, 0.55, 0.25],
                vec![0.25, 0.20, 0.30, 0.25],
            ],
            initial_state: 0,
        },
        burst_pattern: vec![
            BurstEntry { batch_size: 2, pause_us: 0, direction: Direction::Upstream },
            BurstEntry { batch_size: 3, pause_us: 20_000, direction: Direction::Downstream },
            BurstEntry { batch_size: 1, pause_us: 50_000, direction: Direction::Upstream },
            BurstEntry { batch_size: 5, pause_us: 15_000, direction: Direction::Downstream },
        ],
        init_window_client: 65535,
        init_window_server: 65535,
        keepalive_us: 30_000_000,
        overhead_budget: 0.4,
        granularity: MorphGranularity::PerPacket,
        chaff: ChaffConfig {
            enabled: true,
            min_interval_us: 800_000,
            max_interval_us: 3_000_000,
            size_distribution: SizeDistribution::from_gmm(vec![
                 GmmComponent { mean: 60.0, std_dev: 15.0, weight: 0.5 },
                 GmmComponent { mean: 300.0, std_dev: 50.0, weight: 0.5 },
             ]),
            content: ChaffContent::RandomBytes,
            type_weights: crate::chaff::browser_chaff_weights(),
        },
        adversarial: AdversarialConfig {
            enabled: true,
            jitter_pct: 0.06,
            size_noise_pct: 0.03,
        },
        random_padding: true,
    }
}

pub fn video_streaming_model() -> SiteModel {
    SiteModel {
        name: "video_streaming".into(),
        upstream_sizes: SizeDistribution::from_gmm(vec![
            GmmComponent { mean: 50.0, std_dev: 15.0, weight: 0.7 },
            GmmComponent { mean: 300.0, std_dev: 50.0, weight: 0.2 },
            GmmComponent { mean: 800.0, std_dev: 100.0, weight: 0.1 },
        ]),
        downstream_sizes: SizeDistribution::from_gmm(vec![
            GmmComponent { mean: 1460.0, std_dev: 10.0, weight: 0.85 },
            GmmComponent { mean: 800.0, std_dev: 100.0, weight: 0.10 },
            GmmComponent { mean: 200.0, std_dev: 40.0, weight: 0.05 },
        ]),
        iat_client: IatGenerator::MarkovChain {
            states: vec![
                MarkovState { mean_us: 30000.0, std_dev_us: 5000.0 },
                MarkovState { mean_us: 500000.0, std_dev_us: 100000.0 },
            ],
            transition: vec![
                vec![0.8, 0.2],
                vec![0.3, 0.7],
            ],
            initial_state: 0,
        },
        iat_server: IatGenerator::MarkovChain {
            states: vec![
                MarkovState { mean_us: 1000.0, std_dev_us: 200.0 },
                MarkovState { mean_us: 5000.0, std_dev_us: 500.0 },
                MarkovState { mean_us: 16000.0, std_dev_us: 3000.0 },
            ],
            transition: vec![
                vec![0.3, 0.5, 0.2],
                vec![0.1, 0.6, 0.3],
                vec![0.2, 0.3, 0.5],
            ],
            initial_state: 1,
        },
        burst_pattern: vec![
            BurstEntry { batch_size: 10, pause_us: 16_000, direction: Direction::Downstream },
            BurstEntry { batch_size: 1, pause_us: 100_000, direction: Direction::Upstream },
            BurstEntry { batch_size: 10, pause_us: 16_000, direction: Direction::Downstream },
        ],
        init_window_client: 29200,
        init_window_server: 262144,
        keepalive_us: 10_000_000,
        overhead_budget: 0.2,
        granularity: MorphGranularity::PerBurst,
        chaff: ChaffConfig { enabled: false, ..ChaffConfig::default() },
        adversarial: AdversarialConfig { enabled: true, jitter_pct: 0.03, size_noise_pct: 0.01 },
        random_padding: true,
    }
}

pub fn chat_messaging_model() -> SiteModel {
    SiteModel {
        name: "chat_messaging".into(),
        upstream_sizes: SizeDistribution::from_gmm(vec![
            GmmComponent { mean: 60.0, std_dev: 15.0, weight: 0.5 },
            GmmComponent { mean: 200.0, std_dev: 40.0, weight: 0.35 },
            GmmComponent { mean: 600.0, std_dev: 80.0, weight: 0.15 },
        ]),
        downstream_sizes: SizeDistribution::from_gmm(vec![
            GmmComponent { mean: 80.0, std_dev: 20.0, weight: 0.45 },
            GmmComponent { mean: 300.0, std_dev: 50.0, weight: 0.35 },
            GmmComponent { mean: 900.0, std_dev: 120.0, weight: 0.20 },
        ]),
        iat_client: IatGenerator::MarkovChain {
            states: vec![
                MarkovState { mean_us: 50.0, std_dev_us: 20.0 },
                MarkovState { mean_us: 500_000.0, std_dev_us: 200_000.0 },
                MarkovState { mean_us: 3_000_000.0, std_dev_us: 1_000_000.0 },
                MarkovState { mean_us: 15_000_000.0, std_dev_us: 5_000_000.0 },
            ],
            transition: vec![
                vec![0.4, 0.3, 0.2, 0.1],
                vec![0.3, 0.3, 0.25, 0.15],
                vec![0.15, 0.2, 0.4, 0.25],
                vec![0.2, 0.25, 0.3, 0.25],
            ],
            initial_state: 1,
        },
        iat_server: IatGenerator::MarkovChain {
            states: vec![
                MarkovState { mean_us: 40.0, std_dev_us: 15.0 },
                MarkovState { mean_us: 800_000.0, std_dev_us: 300_000.0 },
                MarkovState { mean_us: 5_000_000.0, std_dev_us: 2_000_000.0 },
            ],
            transition: vec![
                vec![0.5, 0.35, 0.15],
                vec![0.2, 0.4, 0.4],
                vec![0.25, 0.35, 0.4],
            ],
            initial_state: 1,
        },
        burst_pattern: vec![
            BurstEntry { batch_size: 1, pause_us: 0, direction: Direction::Upstream },
            BurstEntry { batch_size: 1, pause_us: 50_000, direction: Direction::Downstream },
        ],
        init_window_client: 14600,
        init_window_server: 14600,
        keepalive_us: 25_000_000,
        overhead_budget: 0.8,
        granularity: MorphGranularity::PerPacket,
        chaff: ChaffConfig {
            enabled: true,
            min_interval_us: 500_000,
            max_interval_us: 2_000_000,
            size_distribution: SizeDistribution::from_gmm(vec![
                 GmmComponent { mean: 70.0, std_dev: 20.0, weight: 0.6 },
                 GmmComponent { mean: 250.0, std_dev: 40.0, weight: 0.4 },
             ]),
            content: ChaffContent::RandomBytes,
            type_weights: crate::chaff::chat_chaff_weights(),
        },
        adversarial: AdversarialConfig { enabled: true, jitter_pct: 0.15, size_noise_pct: 0.05 },
        random_padding: true,
    }
}

pub fn paranoid_model() -> SiteModel {
    SiteModel {
        name: "paranoid".into(),
        upstream_sizes: SizeDistribution::from_gmm(vec![
            GmmComponent { mean: 100.0, std_dev: 30.0, weight: 0.25 },
            GmmComponent { mean: 500.0, std_dev: 80.0, weight: 0.30 },
            GmmComponent { mean: 1000.0, std_dev: 100.0, weight: 0.25 },
            GmmComponent { mean: 1400.0, std_dev: 40.0, weight: 0.20 },
        ]),
        downstream_sizes: SizeDistribution::from_gmm(vec![
            GmmComponent { mean: 150.0, std_dev: 40.0, weight: 0.15 },
            GmmComponent { mean: 600.0, std_dev: 100.0, weight: 0.25 },
            GmmComponent { mean: 1100.0, std_dev: 80.0, weight: 0.25 },
            GmmComponent { mean: 1460.0, std_dev: 15.0, weight: 0.35 },
        ]),
        iat_client: IatGenerator::MarkovChain {
            states: vec![
                MarkovState { mean_us: 30.0, std_dev_us: 10.0 },
                MarkovState { mean_us: 300.0, std_dev_us: 80.0 },
                MarkovState { mean_us: 3000.0, std_dev_us: 800.0 },
                MarkovState { mean_us: 30000.0, std_dev_us: 8000.0 },
                MarkovState { mean_us: 100000.0, std_dev_us: 30000.0 },
                MarkovState { mean_us: 500000.0, std_dev_us: 150000.0 },
                MarkovState { mean_us: 2000000.0, std_dev_us: 500000.0 },
                MarkovState { mean_us: 10000000.0, std_dev_us: 3000000.0 },
            ],
            transition: vec![
                vec![0.40, 0.25, 0.15, 0.08, 0.05, 0.03, 0.02, 0.02],
                vec![0.15, 0.35, 0.25, 0.12, 0.06, 0.03, 0.02, 0.02],
                vec![0.08, 0.15, 0.35, 0.20, 0.10, 0.06, 0.03, 0.03],
                vec![0.05, 0.08, 0.15, 0.30, 0.20, 0.12, 0.05, 0.05],
                vec![0.10, 0.10, 0.10, 0.15, 0.25, 0.15, 0.10, 0.05],
                vec![0.08, 0.08, 0.08, 0.10, 0.15, 0.25, 0.15, 0.11],
                vec![0.10, 0.10, 0.10, 0.10, 0.10, 0.15, 0.20, 0.15],
                vec![0.20, 0.15, 0.15, 0.10, 0.10, 0.10, 0.10, 0.10],
            ],
            initial_state: 2,
        },
        iat_server: IatGenerator::MarkovChain {
            states: vec![
                MarkovState { mean_us: 20.0, std_dev_us: 8.0 },
                MarkovState { mean_us: 200.0, std_dev_us: 60.0 },
                MarkovState { mean_us: 2000.0, std_dev_us: 500.0 },
                MarkovState { mean_us: 20000.0, std_dev_us: 5000.0 },
                MarkovState { mean_us: 80000.0, std_dev_us: 20000.0 },
                MarkovState { mean_us: 400000.0, std_dev_us: 100000.0 },
                MarkovState { mean_us: 1500000.0, std_dev_us: 400000.0 },
                MarkovState { mean_us: 8000000.0, std_dev_us: 2000000.0 },
            ],
            transition: vec![
                vec![0.45, 0.30, 0.12, 0.06, 0.03, 0.02, 0.01, 0.01],
                vec![0.12, 0.40, 0.25, 0.12, 0.05, 0.03, 0.02, 0.01],
                vec![0.06, 0.12, 0.38, 0.22, 0.10, 0.06, 0.03, 0.03],
                vec![0.04, 0.06, 0.12, 0.32, 0.22, 0.12, 0.06, 0.06],
                vec![0.08, 0.08, 0.10, 0.14, 0.25, 0.18, 0.10, 0.07],
                vec![0.06, 0.06, 0.08, 0.10, 0.15, 0.28, 0.15, 0.12],
                vec![0.08, 0.08, 0.08, 0.10, 0.12, 0.18, 0.22, 0.14],
                vec![0.15, 0.12, 0.12, 0.10, 0.12, 0.12, 0.12, 0.15],
            ],
            initial_state: 2,
        },
        burst_pattern: vec![
            BurstEntry { batch_size: 1, pause_us: 0, direction: Direction::Upstream },
            BurstEntry { batch_size: 2, pause_us: 50_000, direction: Direction::Downstream },
            BurstEntry { batch_size: 1, pause_us: 200_000, direction: Direction::Upstream },
            BurstEntry { batch_size: 3, pause_us: 80_000, direction: Direction::Downstream },
        ],
        init_window_client: 29200,
        init_window_server: 29200,
        keepalive_us: 15_000_000,
        overhead_budget: 1.5,
        granularity: MorphGranularity::PerPacket,
        chaff: ChaffConfig {
            enabled: true,
            min_interval_us: 200_000,
            max_interval_us: 1_000_000,
            size_distribution: SizeDistribution::from_gmm(vec![
                GmmComponent { mean: 100.0, std_dev: 30.0, weight: 0.3 },
                GmmComponent { mean: 500.0, std_dev: 80.0, weight: 0.3 },
                GmmComponent { mean: 1000.0, std_dev: 100.0, weight: 0.2 },
                 GmmComponent { mean: 1400.0, std_dev: 40.0, weight: 0.2 },
             ]),
            content: ChaffContent::RandomBytes,
            type_weights: crate::chaff::paranoid_chaff_weights(),
        },
        adversarial: AdversarialConfig { enabled: true, jitter_pct: 0.20, size_noise_pct: 0.08 },
        random_padding: true,
    }
}

pub fn all_mimicry_models() -> Vec<SiteModel> {
    vec![
        chrome_like_model(),
        firefox_like_model(),
        http2_multiplexed_model(),
        video_streaming_model(),
        chat_messaging_model(),
        paranoid_model(),
    ]
}

pub fn model_by_profile(profile: &str) -> Option<SiteModel> {
    match profile {
        "browser" => Some(chrome_like_model()),
        "video" => Some(video_streaming_model()),
        "chat" => Some(chat_messaging_model()),
        "streaming" => Some(http2_multiplexed_model()),
        "paranoid" => Some(paranoid_model()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_models_have_valid_names() {
        for model in all_mimicry_models() {
            assert!(!model.name.is_empty());
        }
    }

    #[test]
    fn model_by_profile_browser() {
        let m = model_by_profile("browser").unwrap();
        assert_eq!(m.name, "chrome_tls");
    }

    #[test]
    fn model_by_profile_unknown() {
        assert!(model_by_profile("nonexistent").is_none());
    }

    #[test]
    fn all_models_morph_5000_bytes() {
        for src in all_mimicry_models() {
            let name = src.name.clone();
            let mut morpher = crate::morpher::Morpher::new(src);
            let mut _rng = rand::rng();
            morpher.push(vec![0xAB; 5000], crate::model::Direction::Upstream);
            let packets = morpher.morph_flush();
            assert!(!packets.is_empty(), "model produced no packets");
            for pkt in &packets {
                assert!(pkt.data.len() >= 40, "{}: packet too small {}", name, pkt.data.len());
                assert!(pkt.data.len() <= 1460, "{}: packet exceeds MTU {}", name, pkt.data.len());
            }
        }
    }

    #[test]
    fn all_models_preserve_data() {
        for src in all_mimicry_models() {
            let _name = src.name.clone();
            let mut morpher = crate::morpher::Morpher::new(src);
            let mut _rng = rand::rng();
            let original = vec![0x42; 2000];
            morpher.push(original.clone(), crate::model::Direction::Downstream);
            let packets = morpher.morph_flush();
            let mut reassembled = Vec::new();
            for pkt in &packets {
                reassembled.extend_from_slice(&pkt.data[..pkt.real_data_len]);
            }
            assert_eq!(reassembled, original, "{} failed data preservation", _name);
        }
    }
}
