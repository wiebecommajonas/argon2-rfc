use criterion::{criterion_group, criterion_main, Criterion};

fn argon2d(c: &mut Criterion) {
    let arg = argon2::Argon2::new(
        1,
        3,
        40000,
        argon2::Version::V0x13,
        argon2::Variant::Argon2d,
    );
    c.bench_function("argon2d", |b| {
        b.iter(|| arg.hash::<64>(&[1; 64], &[4; 16], None, None));
    });
}

criterion_group!(benches, argon2d);
criterion_main!(benches);
