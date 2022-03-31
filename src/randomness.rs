use crate::consts::RANDOMNESS_LEN;
use crate::errors::NestedSTARError;
use crate::format::RandomnessSampling;
use ppoprf::ppoprf;

use reqwest::blocking::Client as HttpClient;
use serde::{Deserialize, Serialize};

const QUERY_LABEL: &str = "Client randomness request";
const RESPONSE_LABEL: &str = "Server randomness response";

/// Explicit request body.
#[derive(Serialize, Clone)]
pub struct Request {
  name: String,
  epoch: u8,
  points: Vec<ppoprf::Point>,
}

/// Explicit response body.
#[derive(Serialize, Deserialize)]
pub struct Response {
  name: String,
  results: Vec<ppoprf::Evaluation>,
}

/// `RequestState` for building and building all state associated with randomness requests
pub struct RequestState {
  rsf: RandomnessSampling,
  req: Request,
  blinds: Vec<ppoprf::CurveScalar>,
}
impl RequestState {
  pub fn new(rsf: RandomnessSampling) -> Self {
    let measurements = rsf.input();
    let epoch = rsf.epoch();
    let mut blinded_points = Vec::with_capacity(measurements.len());
    let mut blinds = Vec::with_capacity(measurements.len());
    for x in measurements {
      let (p, r) = ppoprf::Client::blind(x);
      blinded_points.push(p);
      blinds.push(r);
    }

    // convert blinded points into a single response
    let req = Request {
      name: QUERY_LABEL.into(),
      epoch,
      points: blinded_points,
    };

    Self { rsf, req, blinds }
  }

  // Finalize randomness outputs
  pub fn finalize_response(
    &self,
    results: &[ppoprf::Evaluation],
    public_key: &Option<ppoprf::ServerPublicKey>,
  ) -> Result<Vec<[u8; RANDOMNESS_LEN]>, NestedSTARError> {
    let mut buf = [0u8; RANDOMNESS_LEN];
    let mut rand_out = Vec::with_capacity(results.len());
    for (i, result) in results.iter().enumerate() {
      let blinded_point = &self.blinded_points()[i];

      // if a server public key was specified, attempt to verify
      // the result of the randomness
      if let Some(pk) = public_key {
        if !ppoprf::Client::verify(pk, blinded_point, result, self.epoch()) {
          return Err(NestedSTARError::RandomnessSamplingError(
            "Client ZK proof verification failed".into(),
          ));
        }
      }

      // unblind and finalize randomness output
      let unblinded = ppoprf::Client::unblind(&result.output, &self.blinds[i]);
      ppoprf::Client::finalize(
        self.measurement(i),
        self.epoch(),
        &unblinded,
        &mut buf,
      );
      rand_out.push(buf);
    }
    Ok(rand_out)
  }

  pub fn request(&self) -> &Request {
    &self.req
  }

  fn blinded_points(&self) -> &[ppoprf::Point] {
    &self.req.points
  }

  fn measurement(&self, idx: usize) -> &[u8] {
    &self.rsf.input()[idx]
  }

  fn epoch(&self) -> u8 {
    self.rsf.epoch()
  }
}

/// The `Fetcher` trait defines the fetching interface for sampling
/// consistent randomness for clients
pub trait Fetcher {
  /// The `fetch` function uses the constructed randomness request to sample randomness from the server found at the specified URL.
  fn fetch(
    &self,
    req: &Request,
  ) -> Result<Vec<ppoprf::Evaluation>, NestedSTARError>;
}

/// The `HTTPFetcher` provides a default implementation of the
/// randomness fetcher trait, using reqwest for launching queries to a
/// randomness server that runs a PPOPRF protocol.
pub struct HTTPFetcher {
  url: String,
}
impl Fetcher for HTTPFetcher {
  fn fetch(
    &self,
    req: &Request,
  ) -> Result<Vec<ppoprf::Evaluation>, NestedSTARError> {
    // send request and process response
    let resp = HttpClient::new()
      .post(&self.url)
      .json(req)
      .send()
      .map_err(|e| NestedSTARError::RandomnessSamplingError(e.to_string()))?;
    // check status okay
    let status = resp.status();
    if !status.is_success() {
      return Err(NestedSTARError::RandomnessSamplingError(format!(
        "Server returned bad status code: {}",
        status
      )));
    }
    // attempt to parse JSON response
    match resp.json::<Response>() {
      Ok(r) => {
        // Check that response is well-formed
        if r.name != RESPONSE_LABEL {
          return Err(NestedSTARError::RandomnessSamplingError(format!(
            "Incorrect response label specified: {}",
            r.name
          )));
        }
        let results = r.results;
        if results.len() != req.points.len() {
          return Err(NestedSTARError::RandomnessSamplingError(format!(
            "Server returned {} results, but expected {}.",
            results.len(),
            req.points.len(),
          )));
        }
        Ok(results)
      }
      Err(e) => Err(NestedSTARError::RandomnessSamplingError(e.to_string())),
    }
  }
}
impl HTTPFetcher {
  pub fn new(url: &str) -> Self {
    Self { url: url.into() }
  }
}

pub mod testing {
  //! This module provides a mock `LocalFetcher` for locally fetching
  //! randomness during tests.
  //!
  //! IMPORTANT: the local fetching method should only be used for
  //! tests!
  use super::ppoprf::Server as PPOPRFServer;
  use super::*;

  // This is a hack to make sure that we always use the same key for
  // PPOPRF evaluations
  lazy_static::lazy_static! {
    pub static ref PPOPRF_SERVER: PPOPRFServer = PPOPRFServer::new((0u8..=7).collect()).unwrap();
  }

  /// The `LocalFetcher` provides a test implementation of the
  /// fetching interface, using a local instantiation of the PPOPRF.
  ///
  /// NOT TO BE USED IN PRODUCTION
  pub struct LocalFetcher {
    pub ppoprf_server: PPOPRFServer,
  }
  impl Fetcher for LocalFetcher {
    fn fetch(
      &self,
      req: &Request,
    ) -> Result<Vec<ppoprf::Evaluation>, NestedSTARError> {
      let resp = self.eval(req)?;
      Ok(resp.results)
    }
  }
  impl LocalFetcher {
    pub fn new() -> Self {
      Self {
        ppoprf_server: PPOPRF_SERVER.clone(),
      }
    }

    pub fn eval(&self, req: &Request) -> Result<Response, NestedSTARError> {
      // Create a mock response based on expected PPOPRF functionality
      let mut evaluations = Vec::new();
      for point in req.points.iter() {
        let eval_result = self.ppoprf_server.eval(point, req.epoch, true);
        if let Err(e) = eval_result {
          return Err(NestedSTARError::RandomnessSamplingError(e.to_string()));
        }
        evaluations.push(eval_result.unwrap());
      }
      Ok(Response {
        name: RESPONSE_LABEL.into(),
        results: evaluations,
      })
    }
  }
  impl Default for LocalFetcher {
    fn default() -> Self {
      LocalFetcher::new()
    }
  }
}

#[cfg(test)]
mod tests {
  use super::testing::LocalFetcher;
  use super::*;
  use crate::format::*;
  use crate::internal::*;
  use httpmock::prelude::*;
  use serde_json::json;

  #[test]
  fn test_ppoprf_fetching() {
    // Start a lightweight mock server.
    let http_server = MockServer::start();
    // We have to setup alternative endpoints for mocking stuff
    let endpoint_1 = "/sample_1";
    let endpoint_2 = "/sample_2";
    let url_1 = &http_server.url(endpoint_1);
    let url_2 = &http_server.url(endpoint_2);

    // set epoch
    let epoch = 0u8;

    // sample two separate states for the same measurement (simulates two clients
    // sharing the same measurement)
    let nm = NestedMeasurement::new(&[
      "hello".as_bytes().to_vec(),
      "world".as_bytes().to_vec(),
    ])
    .unwrap();
    let state_1 = RequestState::new(RandomnessSampling::new(&nm, epoch));
    let state_2 = RequestState::new(RandomnessSampling::new(&nm, epoch));

    // set up the ppoprf fetching instance that we are mocking
    let mut pf = HTTPFetcher::new(url_1);

    // set up a dummy fetching using the local fetcher instance to simulate local evaluation of the PPOPRF for checking results
    let lf = LocalFetcher::new();

    // mock_1 response for first evaluation
    let mock_1 = http_server.mock(|when, then| {
      when.method(POST).path(endpoint_1);
      then
        .status(200)
        .header("content-type", "application/json")
        .json_body(json!(lf.eval(&state_1.req).unwrap()));
    });
    let results_1 = pf.fetch(&state_1.req).unwrap();
    let finalized_1 = state_1
      .finalize_response(&results_1, &Some(lf.ppoprf_server.get_public_key()))
      .unwrap();
    mock_1.assert();

    // mock_2 response for second evaluation
    let mock_2 = http_server.mock(|when, then| {
      when.method(POST).path(endpoint_2);
      then
        .status(200)
        .header("content-type", "application/json")
        .json_body(json!(lf.eval(&state_2.req).unwrap()));
    });
    // switch endpoint for new mock
    pf.url = url_2.into();
    // sample randomness
    let results_2 = pf.fetch(&state_2.req).unwrap();
    let finalized_2 = state_2
      .finalize_response(&results_2, &Some(lf.ppoprf_server.get_public_key()))
      .unwrap();
    mock_2.assert();

    // check finalized results length
    assert_eq!(finalized_1.len(), nm.len());
    assert_eq!(finalized_2.len(), nm.len());
    // check finalized results are the same in both circumstances
    assert_eq!(finalized_1, finalized_2);
  }
}
