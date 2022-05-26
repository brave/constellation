use crate::consts::RANDOMNESS_LEN;
use crate::errors::NestedSTARError;
use crate::format::RandomnessSampling;
use ppoprf::ppoprf;

use serde::{Deserialize, Serialize};

const QUERY_LABEL: &str = "Client randomness request";
const RESPONSE_LABEL: &str = "Server randomness response";

/// Explicit request body.
#[derive(Serialize, Deserialize, Clone)]
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

pub fn process_randomness_response(
  points: &[ppoprf::Point],
  resp_data: &[u8],
) -> Result<Vec<ppoprf::Evaluation>, NestedSTARError> {
  let r: Response = serde_json::from_slice(resp_data)
    .map_err(|_| NestedSTARError::SerdeJSONError)?;
  // Check that response is well-formed
  if r.name != RESPONSE_LABEL {
    return Err(NestedSTARError::RandomnessSamplingError(format!(
      "Incorrect response label specified: {}",
      r.name
    )));
  }
  let results = r.results;
  if results.len() != points.len() {
    return Err(NestedSTARError::RandomnessSamplingError(format!(
      "Server returned {} results, but expected {}.",
      results.len(),
      points.len(),
    )));
  }
  Ok(results)
}

/// `RequestState` for building and building all state associated with
/// randomness requests
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

      // if a server public key was specified, attempt to verify the
      // result of the randomness
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
        &self.measurement(i),
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

  pub fn blinded_points(&self) -> &[ppoprf::Point] {
    &self.req.points
  }

  fn measurement(&self, idx: usize) -> Vec<u8> {
    let mut result = Vec::new();
    for m in &self.rsf.input()[..(idx + 1)] {
      result.extend(m);
    }
    result
  }

  fn epoch(&self) -> u8 {
    self.rsf.epoch()
  }

  pub fn rsf(&self) -> &RandomnessSampling {
    &self.rsf
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

  /// The `LocalFetcher` provides a test implementation of the fetching
  /// interface, using a local instantiation of the PPOPRF.
  ///
  /// NOT TO BE USED IN PRODUCTION
  pub struct LocalFetcher {
    ppoprf_server: PPOPRFServer,
  }
  impl LocalFetcher {
    pub fn new() -> Self {
      Self {
        ppoprf_server: PPOPRF_SERVER.clone(),
      }
    }

    pub fn eval(
      &self,
      serialized_req: &[u8],
    ) -> Result<Vec<u8>, NestedSTARError> {
      let req: Request = serde_json::from_slice(serialized_req)
        .map_err(|_| NestedSTARError::SerdeJSONError)?;
      // Create a mock response based on expected PPOPRF functionality
      let mut evaluations = Vec::new();
      for point in req.points.iter() {
        let eval_result = self.ppoprf_server.eval(point, req.epoch, true);
        if let Err(e) = eval_result {
          return Err(NestedSTARError::RandomnessSamplingError(e.to_string()));
        }
        evaluations.push(eval_result.unwrap());
      }
      let resp = Response {
        name: RESPONSE_LABEL.into(),
        results: evaluations,
      };
      let serialized_resp = serde_json::to_vec(&resp)
        .map_err(|_| NestedSTARError::SerdeJSONError)?;
      Ok(serialized_resp)
    }

    pub fn get_server(&self) -> &PPOPRFServer {
      &self.ppoprf_server
    }
  }
  impl Default for LocalFetcher {
    fn default() -> Self {
      LocalFetcher::new()
    }
  }
}
