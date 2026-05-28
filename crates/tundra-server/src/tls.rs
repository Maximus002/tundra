use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tracing::info;

pub struct TlsConfig {
    acceptor: TlsAcceptor,
    rustls_config: Arc<rustls::ServerConfig>,
}

impl TlsConfig {
    pub fn new(target_domain: &str) -> Result<Self> {
        let key_pair = rcgen::KeyPair::generate()
            .with_context(|| "key generation failed")?;

        let params = rcgen::CertificateParams::new(vec![target_domain.to_string()])
            .with_context(|| "cert params failed")?;

        let cert = params.self_signed(&key_pair)
            .with_context(|| "self-signed cert failed")?;
        let cert_der = CertificateDer::from(cert);
        let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|e| anyhow::anyhow!("tls config: {}", e))?;

        let rustls_config = Arc::new(server_config);
        let acceptor = TlsAcceptor::from(rustls_config.clone());

        info!("TLS: self-signed cert for {}", target_domain);

        Ok(Self {
            acceptor,
            rustls_config,
        })
    }

    pub fn acceptor(&self) -> &TlsAcceptor {
        &self.acceptor
    }

    pub fn rustls_config(&self) -> Arc<rustls::ServerConfig> {
        self.rustls_config.clone()
    }
}
