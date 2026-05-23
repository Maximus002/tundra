use crate::model::{Direction, MorphGranularity, SiteModel};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Pre-built model library with generic traffic profiles.
pub struct ModelLibrary {
    models: HashMap<String, SiteModel>,
}

impl ModelLibrary {
    pub fn new() -> Self {
        Self {
            models: HashMap::new(),
        }
    }

    /// Load all .bin model files from a directory.
    pub fn load_dir(dir: &Path) -> anyhow::Result<Self> {
        let mut lib = Self::new();
        if !dir.exists() {
            return Ok(lib);
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "bin") {
                let data = std::fs::read(&path)?;
                let model: SiteModel = bincode::deserialize(&data)?;
                lib.models.insert(model.name.clone(), model);
            }
        }
        Ok(lib)
    }

    pub fn add(&mut self, model: SiteModel) {
        self.models.insert(model.name.clone(), model);
    }

    pub fn get(&self, name: &str) -> Option<&SiteModel> {
        self.models.get(name)
    }

    /// Default model for generic HTTPS browsing.
    pub fn default_model(&self) -> Option<&SiteModel> {
        self.models.get("generic_browsing").or_else(|| {
            self.models.values().next()
        })
    }

    /// Save a model to disk.
    pub fn save(model: &SiteModel, dir: &Path) -> anyhow::Result<PathBuf> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(format!("{}.bin", model.name));
        let data = bincode::serialize(model)?;
        std::fs::write(&path, &data)?;
        Ok(path)
    }

    pub fn model_names(&self) -> Vec<&str> {
        self.models.keys().map(|s: &String| s.as_str()).collect()
    }
}

/// Create a synthetic "generic HTTPS browsing" model from typical web traffic statistics.
/// This is a fallback when no collected data is available.
pub fn synthetic_generic_browsing() -> SiteModel {
    use crate::model::{BurstEntry, CompactHistogram};

    let up_sizes: Vec<u64> = vec![
        200, 256, 300, 350, 400, 450,     // small requests
        500, 512, 600, 700, 800, 900,     // medium requests
        1000, 1100, 1200, 1300, 1400,     // large requests
        1420, 1440, 1460, 1460, 1460, 1460, 1460, 1460, // full-MTU (weighted)
    ];
    let dn_sizes: Vec<u64> = vec![
        200, 500, 1000, 1200, 1300, 1400, // mixed
        1420, 1440, 1460, 1460, 1460, 1460, // full-MTU (HTML, images)
        1460, 1460, 1460, 1460, 1460, 1460, 1460, 1460, 1460, // heavily weighted
    ];
    let iat_c: Vec<u64> = vec![
        50, 100, 200,                       // burst
        500, 1000, 2000,                    // intra-page
        5000, 10000, 30000,                // inter-page
    ];
    let iat_s: Vec<u64> = vec![
        20, 50, 100,                        // burst
        200, 500, 1000,                     // response
        2000, 5000,                         // thinking
    ];

    SiteModel {
        name: "generic_browsing".into(),
        upstream_sizes: CompactHistogram::new(&up_sizes, 41),
        downstream_sizes: CompactHistogram::new(&dn_sizes, 41),
        iat_client: CompactHistogram::new(&iat_c, 41),
        iat_server: CompactHistogram::new(&iat_s, 41),
        burst_pattern: vec![
            BurstEntry { batch_size: 2, pause_us: 0, direction: Direction::Upstream },
            BurstEntry { batch_size: 6, pause_us: 150_000, direction: Direction::Downstream },
            BurstEntry { batch_size: 1, pause_us: 500_000, direction: Direction::Upstream },
            BurstEntry { batch_size: 3, pause_us: 1_000_000, direction: Direction::Downstream },
        ],
        init_window_client: 29200,
        init_window_server: 29200,
        keepalive_us: 30_000_000,
        overhead_budget: 0.5,
        granularity: MorphGranularity::PerBurst,
    }
}
