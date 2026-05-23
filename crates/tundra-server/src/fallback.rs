use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, warn};

pub async fn fallback_to_target(
    mut client_read: tokio::io::ReadHalf<tokio_rustls::server::TlsStream<TcpStream>>,
    mut client_write: tokio::io::WriteHalf<tokio_rustls::server::TlsStream<TcpStream>>,
    target_domain: &str,
    initial_data: Vec<u8>,
) -> Result<()> {
    let target = match TcpStream::connect(format!("{}:443", target_domain)).await {
        Ok(t) => t,
        Err(e) => {
            warn!("fallback: cannot connect to {}:443: {}", target_domain, e);
            return Ok(());
        }
    };

    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
    };

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));
    let server_name: rustls::pki_types::ServerName<'_> = match target_domain.try_into() {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };

    let target_tls = match connector.connect(server_name.to_owned(), target).await {
        Ok(t) => t,
        Err(e) => {
            warn!("fallback: tls to {} failed: {}", target_domain, e);
            return Ok(());
        }
    };

    let (mut target_read, mut target_write) = tokio::io::split(target_tls);

    if target_write.write_all(&initial_data).await.is_err() {
        return Ok(());
    }

    info!("fallback: relaying to {}:443", target_domain);

    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            if target_write.write_all(&buf[..n]).await.is_err() { break; }
        }
    });

    let down = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = match target_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            if client_write.write_all(&buf[..n]).await.is_err() { break; }
        }
    });

    let _ = up.await;
    let _ = down.await;
    Ok(())
}
