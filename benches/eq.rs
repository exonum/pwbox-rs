//! Measures constant-time quality of equality comparisons.

#[macro_use]
extern crate criterion;
extern crate crypto as rcrypto;
extern crate rand;

use criterion::{black_box, Bencher, Criterion, ParameterizedBenchmark};
use rand::{thread_rng, RngCore};
use rcrypto::util::fixed_time_eq as rcrypto_eq;

const BUFFER_LEN: usize = 256;

/// Variable-time equality.
#[inline(never)]
fn var_time_eq(x: &[u8], y: &[u8]) -> bool {
    x == y
}

/// Pure rust constant-time equality inspired by the technique used in `rust-crypto`.
fn const_time_eq(x: &[u8], y: &[u8]) -> bool {
    #[inline(never)]
    fn accumulated_diff(x: &[u8], y: &[u8]) -> u8 {
        if x.len() != y.len() {
            1
        } else {
            x.iter()
                .zip(y.iter())
                .map(|(a, b)| a ^ b)
                .fold(0, |acc, a| acc | a)
        }
    }

    accumulated_diff(x, y) == 0
}

fn bench_eq<F>(bencher: &mut Bencher, differing_byte: usize, eq: F)
where
    F: Fn(&[u8], &[u8]) -> bool,
{
    const SAMPLE_SIZE: usize = 8;

    let mut rng = thread_rng();
    let sample: Vec<_> = (0..SAMPLE_SIZE)
        .map(|_| {
            let mut x = [0_u8; BUFFER_LEN];
            rng.fill_bytes(&mut x);
            let mut y = black_box(x);
            y[differing_byte] ^= 1;
            (x, y)
        }).collect();

    bencher.iter(|| assert!(black_box(sample.iter().all(|&(ref x, ref y)| !eq(x, y)))));
}

fn bench_var_time_eq(bencher: &mut Bencher, &differing_byte: &usize) {
    bench_eq(bencher, differing_byte, var_time_eq);
}

fn bench_const_time_eq(bencher: &mut Bencher, &differing_byte: &usize) {
    bench_eq(bencher, differing_byte, const_time_eq);
}

fn bench_rcrypto_eq(bencher: &mut Bencher, &differing_byte: &usize) {
    bench_eq(bencher, differing_byte, rcrypto_eq);
}

fn eq_benches(c: &mut Criterion) {
    let differing_byte = vec![
        0,
        BUFFER_LEN - 1,
        BUFFER_LEN / 16,
        BUFFER_LEN / 8,
        BUFFER_LEN / 4,
        BUFFER_LEN / 2,
    ];

    c.bench(
        "var_time_eq",
        ParameterizedBenchmark::new("diff_byte", bench_var_time_eq, differing_byte.clone()),
    );

    c.bench(
        "const_time_eq",
        ParameterizedBenchmark::new("diff_byte", bench_const_time_eq, differing_byte.clone()),
    );

    c.bench(
        "rcrypto_eq",
        ParameterizedBenchmark::new("diff_byte", bench_rcrypto_eq, differing_byte.clone()),
    );
}

criterion_group!(benches, eq_benches);
criterion_main!(benches);
