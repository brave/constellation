//! star-constellation benchmarks

use star_constellation::api::{client, server};
use star_constellation::format::AggregationResult;
use star_constellation::randomness::testing::LocalFetcher;

use criterion::{black_box, Criterion};
use criterion::{criterion_group, criterion_main};

const EPOCH: u8 = 0;
const THRESHOLD: u32 = 20;

fn prepare(threshold: u32) -> Result<Vec<u8>, star_constellation::Error> {
  // Ordered list of attribute values to encode
  let attributes = ["hello", "benchmark", "data"];
  // Construct a Vec<Vec<u8>> of the attributes
  let measurements = attributes
    .iter()
    .map(|s| s.as_bytes().to_vec())
    .collect::<Vec<Vec<u8>>>();
  let rrs = client::prepare_measurement(&measurements, EPOCH).unwrap();
  let req = client::construct_randomness_request(&rrs);

  let req_slice_vec: Vec<&[u8]> = req.iter().map(|v| v.as_slice()).collect();
  let oprf = LocalFetcher::new();
  let res = oprf.eval(&req_slice_vec, EPOCH).unwrap();

  let res_slice_vec: Vec<&[u8]> =
    res.serialized_points.iter().map(|v| v.as_slice()).collect();
  client::construct_message(&res_slice_vec, None, &rrs, &None, &[], threshold)
}

fn aggregate(messages: &[Vec<u8>]) -> AggregationResult {
  let n_attributes = 3;
  server::aggregate(messages, THRESHOLD, EPOCH, n_attributes)
}

pub fn client(c: &mut Criterion) {
  c.bench_function("client prepare", |b| {
    b.iter(|| prepare(black_box(THRESHOLD)).unwrap())
  });
}

pub fn server(c: &mut Criterion) {
  let messages: Vec<_> = (0..THRESHOLD)
    .map(|_| prepare(THRESHOLD).unwrap())
    .collect();
  c.bench_function("server aggregate", |b| {
    b.iter(|| aggregate(black_box(&messages)))
  });
}

criterion_group!(benches, client, server);
criterion_main!(benches);
