use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    #[serde(default = "default_target_domain")]
    pub target_domain: String,
    pub psk: Option<String>,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_max_per_ip")]
    pub max_per_ip: usize,
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout_secs: u64,
}

fn default_listen_addr() -> String { "0.0.0.0".into() }
fn default_listen_port() -> u16 { 8443 }
fn default_target_domain() -> String { "www.microsoft.com".into() }
fn default_max_connections() -> usize { 1000 }
fn default_max_per_ip() -> usize { 10 }
fn default_handshake_timeout() -> u64 { 10 }

impl ServerConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config from {}", path.display()))?;
        toml::from_str(&content)
            .with_context(|| format!("failed to parse config from {}", path.display()))
    }

    pub fn psk_bytes(&self) -> Result<Option<[u8; 32]>> {
        match &self.psk {
            Some(hex) => {
                let bytes: Vec<u8> = (0..hex.len())
                    .step_by(2)
                    .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
                    .collect();
                let arr: [u8; 32] = bytes.as_slice().try_into()
                    .map_err(|_| anyhow::anyhow!("PSK must be exactly 32 bytes (64 hex chars)"))?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}
