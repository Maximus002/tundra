use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tundra_fme::library::model_from_profile;
use tundra_fme::model::Direction;
use tundra_fme::morpher::Morpher;

const PROFILES: &[&str] = &["browser", "video", "chat", "streaming", "paranoid"];

fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");
    for size in [10_000usize, 100_000, 1_000_000] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::new("browser", size), |b| {
            let model = model_from_profile("browser");
            b.iter(|| {
                let mut morpher = Morpher::new(model.clone());
                morpher.push(vec![0u8; size], Direction::Upstream);
                let _ = morpher.morph_flush();
            })
        });
    }
    group.finish();
}

fn bench_profiles(c: &mut Criterion) {
    let mut group = c.benchmark_group("profiles_100kb");
    group.throughput(Throughput::Bytes(100_000));
    for profile in PROFILES {
        group.bench_function(*profile, |b| {
            let model = model_from_profile(profile);
            b.iter(|| {
                let mut morpher = Morpher::new(model.clone());
                morpher.push(vec![0u8; 100_000], Direction::Upstream);
                let _ = morpher.morph_flush();
            })
        });
    }
    group.finish();
}

fn bench_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("overhead_100kb");
    group.throughput(Throughput::Bytes(100_000));
    for profile in PROFILES {
        group.bench_function(BenchmarkId::new("overhead", profile), |b| {
            let model = model_from_profile(profile);
            b.iter(|| {
                let mut morpher = Morpher::new(model.clone());
                morpher.push(vec![0u8; 100_000], Direction::Upstream);
                let packets = morpher.morph_flush();
                let total: usize = packets.iter().map(|p| p.data.len()).sum();
                let overhead = total as f64 / 100_000.0;
                assert!(overhead >= 1.0);
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_throughput, bench_profiles, bench_overhead);
criterion_main!(benches);
