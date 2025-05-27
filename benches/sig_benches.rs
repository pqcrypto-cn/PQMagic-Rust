use criterion::{black_box, criterion_group, criterion_main, Criterion};

use pqmagic::utils::*;

fn bench_keypair(c: &mut Criterion) {
    let mut group = c.benchmark_group("Key Generation");
    group.sample_size(10); 
    
    for algo in sig_instances() {
        group.bench_function(algo.name(), |b| {
            b.iter(|| {
                black_box(algo.keypair().expect("Keygen failed"));
            });
        });
    }
    group.finish();
}

fn bench_sign(c: &mut Criterion) {
    let msg = black_box(test_message());
    let mut group = c.benchmark_group("Signing");
    group.sample_size(10);
    
    for algo in sig_instances() {
        let (_, sk) = algo.keypair().expect("Keygen failed");
        let sk = black_box(sk);
        
        group.bench_function(algo.name(), |b| {
            b.iter(|| {
                black_box(algo.sign(&msg, None, &sk).expect("Sign failed"));
            });
        });
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let msg = black_box(test_message());
    let mut group = c.benchmark_group("Verification");
    group.sample_size(10);
    
    for algo in sig_instances() {
        let (pk, sk) = algo.keypair().expect("Keygen failed");
        let sig = black_box(algo.sign(&msg, None, &sk).expect("Sign failed"));
        let pk = black_box(pk);
        
        group.bench_function(algo.name(), |b| {
            b.iter(|| {
                black_box(algo.verify(&sig, &msg, None, &pk).expect("Verify failed"));
            });
        });
    }
    group.finish();
}


criterion_group!{
    name = sig_benches;
    config = Criterion::default()
        .with_plots()
        .measurement_time(std::time::Duration::from_secs(3));
    targets = bench_keypair, bench_sign, bench_verify
}
criterion_main!(sig_benches);
