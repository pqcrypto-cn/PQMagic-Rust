use criterion::{black_box, criterion_group, criterion_main, Criterion};

use pqmagic::utils::*;

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("Key Generation");
    group.sample_size(500); 
    
    for algo in kem_instances() {
        group.bench_function(algo.name(), |b| {
            b.iter(|| {
                black_box(algo.keypair().expect("Keygen failed"));
            });
        });
    }
    group.finish();
}

fn bench_encaps(c: &mut Criterion) {
    let mut group = c.benchmark_group("Encapsulation");
    group.sample_size(500);
    
    for algo in kem_instances() {
        let (pk, _) = algo.keypair().expect("Keygen failed");
        let pk = black_box(pk);
        
        group.bench_function(algo.name(), |b| {
            b.iter(|| {
                black_box(algo.encaps(&pk).expect("Encaps failed"));
            });
        });
    }
    group.finish();
}

fn bench_decaps(c: &mut Criterion) {
    let mut group = c.benchmark_group("Decapsulation");
    group.sample_size(500);
    
    for algo in kem_instances() {
        let (pk, sk) = algo.keypair().expect("Keygen failed");
        let (ct, _) = algo.encaps(&pk).expect("Encaps failed");

        let ct = black_box(ct);
        let sk = black_box(sk);
        
        group.bench_function(algo.name(), |b| {
            b.iter(|| {
                black_box(algo.decaps(&ct, &sk).expect("Decaps failed"));
            });
        });
    }
    group.finish();
}

criterion_group!{
    name = kem_benches;
    config = Criterion::default()
        .with_plots()
        .measurement_time(std::time::Duration::from_secs(3));
    targets = bench_keygen, bench_encaps, bench_decaps
}
criterion_main!(kem_benches);
