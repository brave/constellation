// The `api` module consists of the client- and server-specific functions for producing
// messages and aggregating them, respectively.
pub use crate::internal::{key_recover, recover};
pub use crate::internal::{
  NestedMessage, PartialMeasurement, SerializableNestedMessage,
};

pub mod client {
  //! The client module wraps all API functions used by clients for
  //! constructing their aggregation messages relative to the
  //! NestedSTAR aggregation protocol.
  //!
  //! The default implementations of each of the functions can be used
  //! for running an example Client. Each of these functions can be
  //! swapped out for alternative implementations.
  use crate::errors::NestedSTARError;
  use crate::format::*;
  use crate::internal::sample_layer_enc_keys;
  use crate::internal::NestedMeasurement;
  use crate::internal::{NestedMessage, SerializableNestedMessage};
  use crate::randomness;
  use ppoprf::ppoprf;

  /// The function `format_measurement` takes a vector of measurement
  /// values (serialized as bytes), and an agreed threshold and epoch.
  /// Ultimately, the client constructs a nested measurement that is
  /// compatible with the Nested STAR aggregation protocol.
  ///
  /// The output of the function is a serializable object that can be
  /// passed as input to `randomness_sampling()`.
  pub fn format_measurement(
    measurement: &[Vec<u8>],
    epoch: u8,
  ) -> Result<RandomnessSampling, NestedSTARError> {
    let nm = NestedMeasurement::new(measurement)?;
    Ok(RandomnessSampling::new(&nm, epoch))
  }

  /// In `sample_randomness`, the client uses the output of
  /// `format_measurement()` to retrieve randomness for each layer of
  /// their nested measurement. The randomness is retrieved via
  /// a randomness fetcher instance, in coordination with a randomness server.
  ///
  /// The output of the function can be passed as an input to
  /// `construct_message()`.
  pub fn sample_randomness(
    fetcher: &impl randomness::Fetcher,
    rsf: RandomnessSampling,
    verification_key: &Option<ppoprf::ServerPublicKey>,
  ) -> Result<MessageGeneration, NestedSTARError> {
    // construct randomness request state
    let state = randomness::RequestState::new(rsf.clone());

    // fetch randomness
    let results = fetcher.fetch(state.request())?;
    let finalized = state.finalize_response(&results, verification_key)?;

    // output in client aggregation message generation format
    MessageGeneration::new(rsf, finalized)
  }

  /// In `construct_message` the client uses the output from
  /// `randomness_sampling()`, containing their nested measurement and
  /// generated randomness and generates a JSON-formatted aggregation
  /// message.
  ///
  /// The client can optionally specify any amount of additional data
  /// to be included with their message in `aux`.
  pub fn construct_message(
    mgf: MessageGeneration,
    aux_bytes: &[u8],
    threshold: u32,
  ) -> Result<String, NestedSTARError> {
    let nm: NestedMeasurement = mgf.clone().into();
    let mgs = nm.get_message_generators(threshold, mgf.epoch());
    let keys = sample_layer_enc_keys(mgf.input_len());
    let snm = SerializableNestedMessage::from(NestedMessage::new(
      &mgs,
      &mgf.rand(),
      &keys,
      aux_bytes,
      mgf.epoch,
    )?);
    if let Ok(s) = bincode::serialize(&snm) {
      return Ok(base64::encode(s));
    }
    Err(NestedSTARError::SerdeJSONError)
  }
}

pub mod server {
  //! The server module wraps all public API functions used by the
  //! aggregation server
  use crate::format::*;
  use crate::internal::recover_partial_measurements;
  use crate::internal::{NestedMessage, SerializableNestedMessage};
  use std::collections::hash_map::Entry;
  use std::collections::HashMap;

  /// The `aggregate` function is a public API function that takes
  /// a list of serialized Nested STAR messages as input (along
  /// with standard STAR parameters) and outputs a JSON-formatted
  /// vector of output measurements using the Nested STAR recovery
  /// mechanism.
  ///
  /// The output measurements include the number of occurrences
  /// that were recorded, along with attached auxiliary data
  /// submitted by each contributing client.
  pub fn aggregate(
    snms_serialized: &[Vec<u8>],
    threshold: u32,
    epoch: u8,
    num_layers: usize,
  ) -> AggregationResult {
    let mut serde_errors = 0;
    let mut recovery_errors = 0;
    let mut nms = Vec::<NestedMessage>::new();
    for snm_ser in snms_serialized.iter() {
      if let Ok(snm_ser_dec) = base64::decode(snm_ser) {
        let res: Result<SerializableNestedMessage, _> =
          bincode::deserialize(&snm_ser_dec);
        if let Ok(x) = res {
          nms.push(NestedMessage::from(x));
          continue;
        }
      }
      serde_errors += 1;
    }
    let res_fms =
      recover_partial_measurements(&nms, epoch, threshold, num_layers);
    let mut output_map = HashMap::new();
    for res in res_fms {
      if let Ok(prm) = res {
        // ignore empty recoveries in output
        if prm.is_empty() {
          continue;
        }
        match output_map.entry(prm.get_measurement_raw()) {
          Entry::Vacant(e) => {
            let om = OutputMeasurement::from(prm);
            e.insert(om);
          }
          Entry::Occupied(mut e) => {
            e.get_mut().increment(prm.get_aux_data(), prm.next_message);
          }
        }
      } else {
        recovery_errors += 1;
      }
    }
    let out_vec: Vec<OutputMeasurement> = output_map.into_values().collect();
    AggregationResult::new(out_vec, serde_errors, recovery_errors)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::randomness::testing::{LocalFetcher, PPOPRF_SERVER};
  use serde_json::Value;

  #[test]
  fn basic_test() {
    let epoch = 0;
    let threshold = 1;
    let measurement =
      vec!["hello".as_bytes().to_vec(), "world".as_bytes().to_vec()];
    let aux = "added_data".as_bytes().to_vec();
    let rsf = client::format_measurement(&measurement, epoch).unwrap();
    let mgf = client::sample_randomness(
      &LocalFetcher::new(),
      rsf,
      &Some(PPOPRF_SERVER.get_public_key()),
    )
    .unwrap();
    let msg = client::construct_message(mgf, &aux, threshold).unwrap();
    let agg_res =
      server::aggregate(&[msg.as_bytes().to_vec()], threshold, epoch, 2);
    let outputs = agg_res.outputs();
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].value(), vec!["world"]);
    assert_eq!(outputs[0].auxiliary_data(), vec![aux]);
    assert_eq!(agg_res.num_recovery_errors(), 0);
    assert_eq!(agg_res.num_serde_errors(), 0);
  }

  #[test]
  // #[should_panic(expected = "called `Option::unwrap()` on a `None` value")]
  fn incompatible_epoch() {
    let c_epoch = 0u8;
    let threshold = 1;
    let measurement =
      vec!["hello".as_bytes().to_vec(), "world".as_bytes().to_vec()];
    let rsf = client::format_measurement(&measurement, c_epoch).unwrap();
    let mgf = client::sample_randomness(
      &LocalFetcher::new(),
      rsf,
      &Some(PPOPRF_SERVER.get_public_key()),
    )
    .unwrap();
    let msg = client::construct_message(mgf, &[], threshold).unwrap();
    let agg_res =
      server::aggregate(&[msg.as_bytes().to_vec()], threshold, 1u8, 2);
    assert_eq!(agg_res.num_recovery_errors(), 1);
    assert_eq!(agg_res.outputs().len(), 0);
  }

  #[test]
  fn incompatible_threshold() {
    let epoch = 0u8;
    let threshold = 3;
    let measurement =
      vec!["hello".as_bytes().to_vec(), "world".as_bytes().to_vec()];
    let messages: Vec<Vec<u8>> = (0..threshold - 1)
      .into_iter()
      .map(|_| {
        let rsf = client::format_measurement(&measurement, epoch).unwrap();
        let mgf = client::sample_randomness(
          &LocalFetcher::new(),
          rsf,
          &Some(PPOPRF_SERVER.get_public_key()),
        )
        .unwrap();
        client::construct_message(mgf, &[], threshold)
          .unwrap()
          .as_bytes()
          .to_vec()
      })
      .collect();
    let agg_res = server::aggregate(&messages, threshold - 1, epoch, 2);
    assert_eq!(agg_res.num_recovery_errors(), 2);
    assert_eq!(agg_res.outputs().len(), 0);
  }

  #[test]
  fn end_to_end_public_api_no_aux() {
    end_to_end_public_api(false, false);
  }

  #[test]
  fn end_to_end_public_api_with_aux() {
    end_to_end_public_api(true, false);
  }

  #[test]
  fn end_to_end_public_api_no_aux_with_errors() {
    end_to_end_public_api(false, true);
  }

  #[test]
  fn end_to_end_public_api_with_aux_with_errors() {
    end_to_end_public_api(true, true);
  }

  fn end_to_end_public_api(include_aux: bool, incl_failures: bool) {
    let threshold: u32 = 10;
    let num_layers = 3;
    let epoch = 0u8;

    // Sampling client measurements
    let total_num_measurements = 7;
    let mut all_measurements = Vec::new();
    let mut counts = Vec::<u32>::new();

    // add complete measurements
    let hello = "hello".as_bytes().to_vec();
    let goodbye = "goodbye".as_bytes().to_vec();
    let dog = "dog".as_bytes().to_vec();
    let cat = "cat".as_bytes().to_vec();
    let germany = "germany".as_bytes().to_vec();
    let france = "france".as_bytes().to_vec();
    all_measurements.push(vec![hello.clone(), dog.clone(), germany.clone()]);
    counts.push(threshold + 2);
    all_measurements.push(vec![hello.clone(), hello.clone(), germany.clone()]);
    counts.push(threshold + 5);

    // add partial measurements
    all_measurements.push(vec![hello.clone(), cat.clone(), france.clone()]);
    counts.push(threshold - 2);
    all_measurements.push(vec![hello.clone(), germany, france.clone()]);
    counts.push(threshold - 1);
    all_measurements.push(vec![hello.clone(), hello.clone(), dog.clone()]);
    counts.push(threshold - 7);
    all_measurements.push(vec![hello.clone(), hello, cat]);
    counts.push(threshold - 8);

    // Add some input that does not satisfy threshold
    all_measurements.push(vec![goodbye, dog, france]);
    counts.push(threshold - 1);
    assert_eq!(all_measurements.len(), total_num_measurements);

    // combine all measurements together
    let measurements: Vec<Vec<Vec<u8>>> = (0..total_num_measurements)
      .into_iter()
      .map(|i| {
        (0..counts[i])
          .into_iter()
          .map(|_| all_measurements[i].to_vec())
          .collect()
      })
      .fold(Vec::new(), |acc, r: Vec<Vec<Vec<u8>>>| {
        [acc, r.to_vec()].concat()
      });

    // generate client_messages
    let mut aux = vec![];
    if include_aux {
      let json_data = r#"
          {
            "score": 98.7,
            "tagline": "some word",
            "other_data": [
            "something",
            "else"
            ]
          }"#;
      aux = json_data.as_bytes().to_vec();
    }
    let mut client_messages: Vec<String> = measurements
      .iter()
      .map(|m| {
        let rsf = client::format_measurement(m, epoch).unwrap();
        let mgf = client::sample_randomness(
          &LocalFetcher::new(),
          rsf,
          &Some(PPOPRF_SERVER.get_public_key()),
        )
        .unwrap();
        client::construct_message(mgf, &aux, threshold).unwrap()
      })
      .collect();

    if incl_failures {
      // Include a single message threshold times. This will cause
      // the server to think that a value should be revealed, but
      // because the shares are identical a failure should occur.
      let rsf = client::format_measurement(
        &[
          "some".as_bytes().to_vec(),
          "bad".as_bytes().to_vec(),
          "input".as_bytes().to_vec(),
        ],
        epoch,
      )
      .unwrap();
      let mgf = client::sample_randomness(
        &LocalFetcher::new(),
        rsf,
        &Some(PPOPRF_SERVER.get_public_key()),
      )
      .unwrap();
      let msg = client::construct_message(mgf, &aux, threshold).unwrap();
      for _ in 0..threshold {
        client_messages.push(msg.clone());
      }

      // Include a client message that cannot be deserialized
      client_messages.push("some_bad_message".to_string());
    }

    // server retrieve outputs
    let serialized: Vec<Vec<u8>> = client_messages
      .iter()
      .map(|s| s.as_bytes().to_vec())
      .collect();
    let agg_res = server::aggregate(&serialized, threshold, epoch, num_layers);

    // check outputs
    let outputs = agg_res.outputs();
    assert_eq!(outputs.len(), 2);
    if incl_failures {
      assert_eq!(agg_res.num_recovery_errors(), threshold as usize);
      assert_eq!(agg_res.num_serde_errors(), 1);
    } else {
      assert_eq!(agg_res.num_recovery_errors(), 0);
      assert_eq!(agg_res.num_serde_errors(), 0);
    }
    for output in outputs.iter() {
      let values: Vec<String> = output.value();
      let occurrences = output.occurrences();
      let mut expected_occurrences = None;
      if values.is_empty() {
        expected_occurrences = Some((threshold - 1) as usize);
      }
      if let Some(expected_occurrences) = expected_occurrences {
        assert_eq!(occurrences, expected_occurrences);
      }

      if include_aux && !values.is_empty() {
        if let Some(expected_occurrences) = expected_occurrences {
          assert_eq!(output.auxiliary_data().len(), expected_occurrences);
        }
        // all aux is the same for now
        let decoded = output.auxiliary_data()[0].clone();
        let object: Value = serde_json::from_slice(&decoded).unwrap();
        assert!(
          (object["score"].as_f64().unwrap() - 98.7).abs() < f64::EPSILON
        );
        assert_eq!(object["tagline"], "some word");
        assert_eq!(object["other_data"][0], "something");
        assert_eq!(object["other_data"][1], "else");
      }
    }
  }
}
