//! star-constellation benchmarks

use star_constellation::api::client;
use star_constellation::randomness::testing::LocalFetcher;

use criterion::{criterion_group, criterion_main};
use criterion::{black_box, Criterion};

fn prepare(threshold: u32) -> Result<Vec<u8>, star_constellation::Error> {
    let epoch = 0u8;

    // Ordered list of attribute values to encode
    let attributes = ["hello", "benchmark", "data"];
    // Construct a Vec<Vec<u8>> of the attributes
    let measurements = attributes.iter()
        .map(|s| s.as_bytes().to_vec())
        .collect::<Vec<Vec<u8>>>();
    let rrs = client::prepare_measurement(&measurements, epoch).unwrap();
    let req = client::construct_randomness_request(&rrs);

    let req_slice_vec: Vec<&[u8]> = req.iter()
        .map(|v| v.as_slice()).collect();
    let oprf = LocalFetcher::new();
    let res = oprf.eval(&req_slice_vec, epoch).unwrap();

    let res_slice_vec: Vec<&[u8]> =
        res.serialized_points.iter().map(|v| v.as_slice()).collect();
    client::construct_message(&res_slice_vec, None, &rrs, &None, &[], threshold)
}

pub fn client(c: &mut Criterion) {
    let threshold = 20;
    c.bench_function("client prepare", |b| b.iter(|| prepare(black_box(threshold))));
}

criterion_group!(benches, client);
criterion_main!(benches);
