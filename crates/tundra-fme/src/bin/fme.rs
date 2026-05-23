use clap::{Parser, Subcommand};
use tundra_fme::{library, model::*, morpher::Morpher};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "tundra-fme")]
#[command(about = "Flow Morphing Engine CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run morphing benchmark
    Bench {
        /// Path to model file (.bin)
        #[arg(long, default_value = "tundra-models/generic_browsing.bin")]
        model: PathBuf,

        /// Size of test payload in bytes
        #[arg(long, default_value_t = 100_000)]
        payload_size: usize,

        /// Number of iterations
        #[arg(long, default_value_t = 100)]
        iterations: usize,
    },
    /// List available models
    Models {
        /// Model directory
        #[arg(long, default_value = "tundra-models")]
        dir: PathBuf,
    },
    /// Generate synthetic model
    Generate {
        /// Output directory
        #[arg(long, default_value = "tundra-models")]
        dir: PathBuf,
    },
}

fn load_model(path: &PathBuf) -> anyhow::Result<SiteModel> {
    let data = std::fs::read(path)?;
    let model: SiteModel = bincode::deserialize(&data)?;
    Ok(model)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Bench { model, payload_size, iterations } => {
            bench_model(&model, payload_size, iterations)?;
        }
        Commands::Models { dir } => {
            let lib = library::ModelLibrary::load_dir(&dir)?;
            println!("Available models in {}:", dir.display());
            for name in lib.model_names() {
                let m = lib.get(name).unwrap();
                println!(
                    "  {} (up: {} median, dn: {} median, iat_c: {}us median, iat_s: {}us median)",
                    name,
                    m.upstream_sizes.median(),
                    m.downstream_sizes.median(),
                    m.iat_client.median(),
                    m.iat_server.median(),
                );
            }
        }
        Commands::Generate { dir } => {
            let model = library::synthetic_generic_browsing();
            let path = library::ModelLibrary::save(&model, &dir)?;
            println!("Generated synthetic model: {}", path.display());
        }
    }

    Ok(())
}

fn bench_model(model_path: &PathBuf, payload_size: usize, iterations: usize) -> anyhow::Result<()> {
    let model = load_model(model_path)?;

    println!("Model: {}", model.name);
    println!("Payload: {} bytes, Iterations: {}", payload_size, iterations);
    println!();

    let mut total_overhead = 0.0f64;
    let mut total_packets = 0usize;
    let mut size_values: Vec<u64> = Vec::new();
    let mut iat_values: Vec<u64> = Vec::new();

    for i in 0..iterations {
        let mut morpher = Morpher::new(model.clone());
        let mut rng = rand::rng();

        let payload = vec![i as u8; payload_size];
        morpher.push(payload, Direction::Upstream);

        let packets = morpher.morph_flush(&mut rng);
        let overhead = morpher.stats().overhead_ratio();

        for pkt in &packets {
            size_values.push(pkt.data.len() as u64);
            iat_values.push(pkt.send_after_us);
        }

        total_overhead += overhead;
        total_packets += packets.len();
    }

    let avg_overhead = total_overhead / iterations as f64;
    let avg_packets = total_packets as f64 / iterations as f64;

    // Build reference distributions from model for comparison
    let ref_sizes: Vec<u64> = (0..5000).map(|i| model.upstream_sizes.sample(i as f64 / 4999.0)).collect();
    let ref_iats: Vec<u64> = (0..5000).map(|i| model.iat_client.sample(i as f64 / 4999.0)).collect();

    // Compute KS-like divergence
    let size_distance = wasserstein_distance(&size_values, &ref_sizes);
    let iat_distance = wasserstein_distance(&iat_values, &ref_iats);

    println!("Results:");
    println!("  Avg overhead:     {:.1}%", avg_overhead * 100.0);
    println!("  Avg packets/run:  {:.1}", avg_packets);
    println!("  Size W-distance:  {:.1} (lower = more similar)", size_distance);
    println!("  IAT W-distance:   {:.1} (lower = more similar)", iat_distance);

    let size_ok = size_distance < 800.0;
    let iat_ok = iat_distance < 6000.0;
    let overhead_ok = avg_overhead <= model.overhead_budget + 0.1;

    println!();
    println!("Checks:");
    println!("  Size distribution match:  {} {}", if size_ok { "PASS" } else { "FAIL" },
        if size_ok { "" } else { "(morphed sizes deviate from model)" });
    println!("  IAT distribution match:   {} {}", if iat_ok { "PASS" } else { "FAIL" },
        if iat_ok { "" } else { "(inter-arrival times deviate from model)" });
    println!("  Overhead within budget:   {} {}", if overhead_ok { "PASS" } else { "WARN" },
        if overhead_ok { "" } else { "(over budget but adjustable)" });

    if size_ok && iat_ok && overhead_ok {
        println!("\nAll checks passed.");
    } else {
        println!("\nSome checks failed. Consider adjusting model or overhead budget.");
    }

    Ok(())
}

/// Earth Mover's Distance (1D Wasserstein) between two samples.
fn wasserstein_distance(a: &[u64], b: &[u64]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return f64::MAX;
    }
    let mut a_sorted = a.to_vec();
    let mut b_sorted = b.to_vec();
    a_sorted.sort_unstable();
    b_sorted.sort_unstable();

    let len = a_sorted.len().min(b_sorted.len());
    let sum: f64 = a_sorted[..len]
        .iter()
        .zip(b_sorted[..len].iter())
        .map(|(x, y)| (x.abs_diff(*y)) as f64)
        .sum();

    sum / len as f64
}
