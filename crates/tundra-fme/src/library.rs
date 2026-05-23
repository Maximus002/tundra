use crate::model::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct ModelLibrary {
    models: HashMap<String, SiteModel>,
}

impl ModelLibrary {
    pub fn new() -> Self {
        Self {
            models: HashMap::new(),
        }
    }

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

    pub fn default_model(&self) -> Option<&SiteModel> {
        self.models.get("generic_browsing").or_else(|| {
            self.models.values().next()
        })
    }

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

    pub fn random_model(&self) -> Option<&SiteModel> {
        if self.models.is_empty() {
            return None;
        }
        let idx = (rand::random::<u64>() as usize) % self.models.len();
        self.models.values().nth(idx)
    }

    pub fn load_builtin_models(&mut self) {
        for model in crate::mimicry::all_mimicry_models() {
            self.models.insert(model.name.clone(), model);
        }
        if !self.models.contains_key("generic_browsing") {
            self.models.insert("generic_browsing".into(), synthetic_generic_browsing());
        }
    }

    pub fn model_for_profile(&self, profile: &str) -> Option<&SiteModel> {
        match profile {
            "browser" => self.models.get("chrome_tls"),
            "video" => self.models.get("video_streaming"),
            "chat" => self.models.get("chat_messaging"),
            "streaming" => self.models.get("http2_multiplexed"),
            "paranoid" => self.models.get("paranoid"),
            _ => self.default_model(),
        }
    }
}

pub fn synthetic_generic_browsing() -> SiteModel {
    crate::mimicry::chrome_like_model()
}

pub fn model_from_profile(profile: &str) -> SiteModel {
    let mut lib = ModelLibrary::new();
    lib.load_builtin_models();
    lib.model_for_profile(profile)
        .cloned()
        .unwrap_or_else(|| synthetic_generic_browsing())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn library_loads_builtins() {
        let mut lib = ModelLibrary::new();
        lib.load_builtin_models();
        assert!(lib.model_names().len() >= 6);
        assert!(lib.get("chrome_tls").is_some());
        assert!(lib.get("paranoid").is_some());
    }

    #[test]
    fn library_profile_lookup() {
        let mut lib = ModelLibrary::new();
        lib.load_builtin_models();
        assert!(lib.model_for_profile("browser").is_some());
        assert!(lib.model_for_profile("paranoid").is_some());
    }

    #[test]
    fn library_random_model() {
        let mut lib = ModelLibrary::new();
        lib.load_builtin_models();
        let m = lib.random_model();
        assert!(m.is_some());
    }
}
