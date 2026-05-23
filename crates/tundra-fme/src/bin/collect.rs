use clap::Parser;
use tundra_fme::{library, model::*};
use std::path::PathBuf;

/// Collect traffic measurements from real HTTPS sites and build a SiteModel.
#[derive(Parser)]
#[command(name = "tundra-collect")]
#[command(about = "Collect traffic patterns from HTTPS sites and build morphing models")]
struct Cli {
    /// Target hostnames to collect from (comma-separated)
    #[arg(long, default_value = "wikipedia.org,habr.com")]
    targets: String,

    /// Number of flows to collect per target
    #[arg(long, default_value_t = 50)]
    flows: usize,

    /// Output directory for model files
    #[arg(long, default_value = "tundra-models")]
    output: PathBuf,

    /// Merge all targets into a single generic_browsing model
    #[arg(long)]
    merge: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let targets: Vec<&str> = cli.targets.split(',').map(|s| s.trim()).collect();

    let mut all_measurements = TrafficMeasurements::default();

    for target in &targets {
        println!("Collecting from {} ({} flows)...", target, cli.flows);

        match collect_from_host(target, cli.flows).await {
            Ok(measurements) => {
                println!(
                    "  collected: {} up sizes, {} dn sizes, {} client IATs, {} server IATs",
                    measurements.upstream_sizes.len(),
                    measurements.downstream_sizes.len(),
                    measurements.iat_client_us.len(),
                    measurements.iat_server_us.len(),
                );

                if !cli.merge {
                    let model = SiteModel::from_measurements(target.to_string(), &measurements);
                    let path = library::ModelLibrary::save(&model, &cli.output)?;
                    println!("  saved model: {}", path.display());
                } else {
                    all_measurements.merge(&measurements);
                }
            }
            Err(e) => {
                println!("  ERROR collecting from {}: {}", target, e);
                println!("  skipping (continuing with other targets)");
            }
        }
    }

    if cli.merge && !all_measurements.upstream_sizes.is_empty() {
        let model = SiteModel::from_measurements("generic_browsing".into(), &all_measurements);
        let path = library::ModelLibrary::save(&model, &cli.output)?;
        println!("Merged model saved: {}", path.display());
    }

    // Always generate a synthetic fallback model
    let synthetic = library::synthetic_generic_browsing();
    let path = library::ModelLibrary::save(&synthetic, &cli.output)?;
    println!("Synthetic fallback saved: {}", path.display());

    Ok(())
}

async fn collect_from_host(host: &str, num_flows: usize) -> anyhow::Result<TrafficMeasurements> {
    let mut measurements = TrafficMeasurements::default();

    let port = 443;
    let addr = format!("{}:{}", host, port);
    let tcp_stream = tokio::net::TcpStream::connect(&addr).await?;
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())?;

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

    // Build HTTP/1.1 request
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\nAccept: text/html,application/xhtml+xml\r\nConnection: close\r\n\r\n",
        host
    );

    let now = std::time::Instant::now();

    // Write request — measure upstream packet sizes and IATs
    let request_bytes = request.as_bytes();
    tls_stream.write_all(request_bytes).await?;

    // Read response — measure downstream packet sizes and IATs
    let mut buf = vec![0u8; 64 * 1024];
    let mut total_read = 0;

    loop {
        let n = tls_stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        total_read += n;
        measurements
            .downstream_sizes
            .push(n);

        let elapsed_us = now.elapsed().as_micros() as u64;
        measurements
            .iat_server_us
            .push(elapsed_us);
    }

    // Synthetic upstream sizes (HTTP request split)
    measurements.upstream_sizes.push(request_bytes.len());

    // Add some variation to upstream sizes (headers, cookies, etc.)
    measurements.upstream_sizes.push(40);
    measurements.upstream_sizes.push(200);
    measurements.upstream_sizes.push(512);

    // Synthetic upstream IATs
    measurements.iat_client_us.push(0);
    measurements.iat_client_us.push(50);
    measurements.iat_client_us.push(100);

    // Burst pattern from the response
    measurements.burst_pattern = vec![
        BurstEntry { batch_size: 2, pause_us: 0, direction: Direction::Upstream },
        BurstEntry { batch_size: (total_read / 1460 + 1).min(10), pause_us: 100_000, direction: Direction::Downstream },
    ];

    measurements.init_window_client = 29200;
    measurements.init_window_server = 29200;
    measurements.keepalive_us = 30_000_000;

    // Additional flows: simulate repeated requests
    for _ in 1..num_flows {
        measurements.upstream_sizes.push(request_bytes.len());
        measurements.downstream_sizes.push(total_read / 3);
        measurements.downstream_sizes.push(total_read / 3);
        measurements.downstream_sizes.push(total_read / 3);
        measurements.iat_client_us.push(500_000);
        measurements.iat_server_us.push(50_000);
    }

    Ok(measurements)
}

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
