use crate::model::*;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FmeConfig {
    pub profile: String,
    #[serde(default)]
    pub rotation: ModelRotation,
    #[serde(default)]
    pub custom_profiles: Vec<MorphProfile>,
}

impl Default for FmeConfig {
    fn default() -> Self {
        Self {
            profile: "browser".into(),
            rotation: ModelRotation::Never,
            custom_profiles: vec![],
        }
    }
}

impl FmeConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read_to_string(path)?;
        let config: FmeConfig = toml::from_str(&data)?;
        Ok(config)
    }

    pub fn load_str(s: &str) -> anyhow::Result<Self> {
        toml::from_str(s).map_err(Into::into)
    }
}

pub fn builtin_profiles() -> Vec<MorphProfile> {
    vec![
        MorphProfile {
            name: "browser".into(),
            overhead_budget: 0.5,
            chaff: ChaffConfig {
                enabled: true,
                min_interval_us: 800_000,
                max_interval_us: 3_000_000,
                size_distribution: SizeDistribution::from_gmm(vec![
                    GmmComponent { mean: 128.0, std_dev: 32.0, weight: 0.4 },
                    GmmComponent { mean: 512.0, std_dev: 80.0, weight: 0.4 },
                    GmmComponent { mean: 1200.0, std_dev: 100.0, weight: 0.2 },
                ]),
                content: ChaffContent::HttpLikeHeaders,
                type_weights: crate::chaff::browser_chaff_weights(),
            },
            rotation: ModelRotation::Never,
            adversarial: AdversarialConfig {
                enabled: true,
                jitter_pct: 0.08,
                size_noise_pct: 0.03,
            },
            random_padding: true,
        },
        MorphProfile {
            name: "video".into(),
            overhead_budget: 0.3,
            chaff: ChaffConfig {
                enabled: false,
                ..ChaffConfig::default()
            },
            rotation: ModelRotation::Never,
            adversarial: AdversarialConfig {
                enabled: true,
                jitter_pct: 0.05,
                size_noise_pct: 0.02,
            },
            random_padding: true,
        },
        MorphProfile {
            name: "chat".into(),
            overhead_budget: 0.8,
            chaff: ChaffConfig {
                enabled: true,
                min_interval_us: 500_000,
                max_interval_us: 2_000_000,
                size_distribution: SizeDistribution::from_gmm(vec![
                    GmmComponent { mean: 80.0, std_dev: 20.0, weight: 0.6 },
                    GmmComponent { mean: 300.0, std_dev: 50.0, weight: 0.3 },
                    GmmComponent { mean: 800.0, std_dev: 100.0, weight: 0.1 },
                ]),
                content: ChaffContent::RandomBytes,
                type_weights: crate::chaff::chat_chaff_weights(),
            },
            rotation: ModelRotation::Never,
            adversarial: AdversarialConfig {
                enabled: true,
                jitter_pct: 0.15,
                size_noise_pct: 0.05,
            },
            random_padding: true,
        },
        MorphProfile {
            name: "streaming".into(),
            overhead_budget: 0.2,
            chaff: ChaffConfig {
                enabled: false,
                ..ChaffConfig::default()
            },
            rotation: ModelRotation::Never,
            adversarial: AdversarialConfig {
                enabled: true,
                jitter_pct: 0.03,
                size_noise_pct: 0.02,
            },
            random_padding: true,
        },
        MorphProfile {
            name: "paranoid".into(),
            overhead_budget: 1.5,
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
            rotation: ModelRotation::PerSession,
            adversarial: AdversarialConfig {
                enabled: true,
                jitter_pct: 0.20,
                size_noise_pct: 0.08,
            },
            random_padding: true,
        },
    ]
}

pub fn get_profile(name: &str) -> Option<MorphProfile> {
    builtin_profiles().into_iter().find(|p| p.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_profiles_count() {
        assert_eq!(builtin_profiles().len(), 5);
    }

    #[test]
    fn get_browser_profile() {
        let p = get_profile("browser").unwrap();
        assert_eq!(p.name, "browser");
        assert!(p.chaff.enabled);
        assert!(p.adversarial.enabled);
    }

    #[test]
    fn get_paranoid_profile() {
        let p = get_profile("paranoid").unwrap();
        assert_eq!(p.name, "paranoid");
        assert!(p.chaff.enabled);
        assert!(p.overhead_budget > 1.0);
        assert_eq!(p.rotation, ModelRotation::PerSession);
    }

    #[test]
    fn config_default() {
        let c = FmeConfig::default();
        assert_eq!(c.profile, "browser");
    }

    #[test]
    fn config_parse_toml() {
        let s = r#"
profile = "paranoid"
rotation = "PerSession"
"#;
        let c = FmeConfig::load_str(s).unwrap();
        assert_eq!(c.profile, "paranoid");
    }
}
