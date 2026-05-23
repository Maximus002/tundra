use criterion::{criterion_group, criterion_main, Criterion};
use rand::Rng;
use tundra_fme::library::synthetic_generic_browsing;
use tundra_fme::model::Direction;
use tundra_fme::morpher::Morpher;

fn bench_morphing(c: &mut Criterion) {
    let model = synthetic_generic_browsing();

    c.bench_function("morph_10kb", |b| {
        b.iter(|| {
            let mut morpher = Morpher::new(model.clone());
            let mut rng = rand::rng();
            morpher.push(vec![0u8; 10_000], Direction::Upstream);
            let _packets = morpher.morph_flush(&mut rng);
        })
    });

    c.bench_function("morph_100kb", |b| {
        b.iter(|| {
            let mut morpher = Morpher::new(model.clone());
            let mut rng = rand::rng();
            morpher.push(vec![0u8; 100_000], Direction::Upstream);
            let _packets = morpher.morph_flush(&mut rng);
        })
    });

    c.bench_function("morph_1mb", |b| {
        b.iter(|| {
            let mut morpher = Morpher::new(model.clone());
            let mut rng = rand::rng();
            morpher.push(vec![0u8; 1_000_000], Direction::Upstream);
            let _packets = morpher.morph_flush(&mut rng);
        })
    });
}

criterion_group!(benches, bench_morphing);
criterion_main!(benches);
