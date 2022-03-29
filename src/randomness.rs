use crate::consts::RANDOMNESS_LEN;
use crate::errors::NestedSTARError;
use ppoprf::ppoprf;
use reqwest::blocking::Client as HttpClient;
use serde::{Deserialize, Serialize};

const QUERY_LABEL: &str = "";
const RESPONSE_LABEL: &str = "";

/// Explicit query body.
#[derive(Serialize)]
struct Query {
  name: String,
  points: Vec<ppoprf::Point>,
}

/// Explicit response body.
#[derive(Deserialize)]
struct Response {
  name: String,
  results: Vec<ppoprf::Evaluation>,
}

/// The `ServerInfo` struct contains the address and public key
/// information for the randomness server
#[derive(Clone)]
pub struct ServerInfo<T> {
  url: String,
  public_key: Option<T>,
}
impl<T: Clone> ServerInfo<T> {
  pub fn new(url: String, public_key: Option<T>) -> Self {
    Self { url, public_key }
  }

  pub fn url(&self) -> &str {
    &self.url
  }

  pub fn public_key(&self) -> Option<T> {
    self.public_key.clone()
  }
}

/// The `Fetcher` trait defines the fetching interface for sampling
/// consistent randomness for clients
pub trait Fetcher<T> {
  /// Generate a new instance of the fetcher, with the contact URL and
  /// the public key used for verifying responses
  fn new(info: ServerInfo<T>) -> Self;

  /// Return the associated URL
  fn url(&self) -> &str;

  /// Return the associated public key
  fn public_key(&self) -> Option<T>;

  /// The `fetch` function takes the randomness sampling object as input
  /// and associated server information, writes out the randomness to
  /// the provided input buffer
  fn fetch(
    &self,
    rsf: &crate::format::RandomnessSampling,
  ) -> Result<Vec<[u8; RANDOMNESS_LEN]>, NestedSTARError>;
}

/// The `PPOPRFFetcher` provides a default implementation of the
/// randomness fetcher trait, using reqwest for launching queries to a
/// randomness server that runs a PPOPRF protocol.
pub struct PPOPRFFetcher {
  url: String,
  public_key: Option<ppoprf::ServerPublicKey>,
}
impl Fetcher<ppoprf::ServerPublicKey> for PPOPRFFetcher {
  fn new(info: ServerInfo<ppoprf::ServerPublicKey>) -> Self {
    Self {
      url: info.url,
      public_key: info.public_key,
    }
  }

  fn url(&self) -> &str {
    &self.url
  }

  fn public_key(&self) -> Option<ppoprf::ServerPublicKey> {
    self.public_key.clone()
  }

  fn fetch(
    &self,
    rsf: &crate::format::RandomnessSampling,
  ) -> Result<Vec<[u8; RANDOMNESS_LEN]>, NestedSTARError> {
    // default implementation of randomness fetching
    let measurements = rsf.input();
    let epoch = rsf.epoch();
    let mut blinded_points = Vec::with_capacity(measurements.len());
    let mut blinds = Vec::with_capacity(measurements.len());
    for x in &measurements {
      let (p, r) = ppoprf::Client::blind(x);
      blinded_points.push(p);
      blinds.push(r);
    }

    // convert blinded points into a single response
    let query = Query {
      name: QUERY_LABEL.into(),
      points: blinded_points,
    };

    // send request and process response
    match HttpClient::new()
      .post(self.url().to_string())
      .json(&query)
      .send()
    {
      Ok(resp) => {
        let status = resp.status();
        if status != 200 {
          return Err(NestedSTARError::RandomnessSamplingError(format!(
            "Server returned bad status code: {}",
            status
          )));
        }
        match resp.json::<Response>() {
          Ok(r) => {
            // Check that response is well-formed
            if r.name != RESPONSE_LABEL {
              return Err(NestedSTARError::RandomnessSamplingError(format!("Incorrect response label specified: {}", r.name)));
            }
            let results = r.results;
            if results.len() != measurements.len() {
              return Err(NestedSTARError::RandomnessSamplingError(format!(
                "Server returned bad number of results: {}",
                results.len()
              )));
            }

            // Finalize randomness outputs
            let server_pk = self.public_key();
            let mut buf = [0u8; RANDOMNESS_LEN];
            let mut rand_out = Vec::with_capacity(measurements.len());
            for (i, result) in results.iter().enumerate() {
              let blinded_point = &query.points[i];
              let blind = blinds[i];

              // if a server public key was specified, attempt to verify
              // the result of the randomness
              if let Some(pk) = &server_pk {
                if !ppoprf::Client::verify(pk, blinded_point, result, epoch) {
                  return Err(NestedSTARError::RandomnessSamplingError(
                    "Client ZK proof verification failed".into(),
                  ));
                }
              }

              // unblind and finalize randomness output
              let unblinded = ppoprf::Client::unblind(&result.output, &blind);
              ppoprf::Client::finalize(
                &measurements[i],
                epoch,
                &unblinded,
                &mut buf,
              );
              rand_out.push(buf);
            }
            Ok(rand_out)
          }
          Err(e) => {
            Err(NestedSTARError::RandomnessSamplingError(e.to_string()))
          }
        }
      }
      Err(e) => Err(NestedSTARError::RandomnessSamplingError(e.to_string())),
    }
  }
}

#[cfg(test)]
mod tests {}
