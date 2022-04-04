use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::convert::TryInto;

use serde::{Deserialize, Serialize};
use sta_rs::{
  derive_ske_key, load_bytes, share_recover, AssociatedData, Ciphertext,
  Message, MessageGenerator, Share, SingleMeasurement,
};

use rand_core::{OsRng, RngCore};

use crate::consts::*;
use crate::errors::NestedSTARError;

// Internal consts
const LAYER_ENC_KEY_LEN: usize = 16;
const NESTED_STAR_ENCRYPTION_LABEL: &str = "nested_star_layer_encrypt";

/// The `NestedMeasurement` struct provides a mechanism for submitting
/// measurements as vectors.
#[derive(Clone, Debug, PartialEq)]
pub struct NestedMeasurement(pub Vec<SingleMeasurement>);
impl NestedMeasurement {
  pub fn new(x_list: &[Vec<u8>]) -> Result<Self, NestedSTARError> {
    if x_list.iter().any(|x| x.len() > MAX_MEASUREMENT_LEN) {
      return Err(NestedSTARError::LongMeasurementError);
    }
    let mut measurements = Vec::with_capacity(x_list.len());
    // pad measurements with zeroes to 32 bytes
    let mut buf = vec![0u8; MAX_MEASUREMENT_LEN];
    let padded: Vec<Vec<u8>> = x_list
      .iter()
      .map(|x| {
        let x_len = x.len();
        buf[..x_len].copy_from_slice(x);
        if x_len < MAX_MEASUREMENT_LEN {
          buf[x_len..].copy_from_slice(&vec![0u8; MAX_MEASUREMENT_LEN - x_len]);
        }
        buf.clone()
      })
      .collect();
    // create partial measurements
    for x in padded {
      measurements.push(SingleMeasurement::new(&x));
    }
    Ok(Self(measurements))
  }

  pub fn get_message_generators(
    &self,
    threshold: u32,
    epoch: u8,
  ) -> Vec<MessageGenerator> {
    self
      .0
      .iter()
      .map(|x| {
        MessageGenerator::new(
          x.clone(),
          threshold,
          &String::from(epoch as char),
        )
      })
      .collect()
  }

  pub fn get_layer_as_bytes(&self, i: usize) -> Vec<u8> {
    self.0[i].as_vec()
  }

  pub fn len(&self) -> usize {
    self.0.len()
  }

  fn get_split_layer(&self, i: usize) -> Vec<[u8; MAX_MEASUREMENT_LEN]> {
    let concatenated_measurement = self.get_layer_as_bytes(i);
    let mut output = Vec::new();
    for j in 0..i + 1 {
      let value = concatenated_measurement
        [j * MAX_MEASUREMENT_LEN..(j + 1) * MAX_MEASUREMENT_LEN]
        .to_vec();
      output.push(value.try_into().unwrap());
    }
    output
  }
}

/// An internal struct that allows serializing and deserializing client
/// STAR messages during encryption/decryption.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct SerializableMessage {
  ciphertext: Vec<u8>,
  share: Vec<u8>,
  tag: Vec<u8>,
}
impl From<SerializableMessage> for Message {
  fn from(sm: SerializableMessage) -> Message {
    Message {
      ciphertext: Ciphertext::from(sm.ciphertext),
      share: Share::from_bytes(&sm.share).unwrap(),
      tag: sm.tag,
    }
  }
}
impl From<Message> for SerializableMessage {
  fn from(message: Message) -> Self {
    Self {
      ciphertext: message.ciphertext.to_bytes(),
      share: message.share.to_bytes(),
      tag: message.tag,
    }
  }
}

/// A `NestedMessage` consists of an unencrypted STAR message, plus
/// layers of encrypted STAR messages that can be decrypted only if the
/// previous message layer is decrypted and opened via the standard STAR
/// recovery mechanism.
#[derive(Clone, Debug, PartialEq)]
pub struct NestedMessage {
  pub unencrypted_layer: Message,
  pub encrypted_layers: Vec<Ciphertext>,
}
impl NestedMessage {
  pub fn new(
    gens: &[MessageGenerator],
    rand_bytes: &[[u8; RANDOMNESS_LEN]],
    keys: &[Vec<u8>],
    aux_data: &[u8],
  ) -> Result<Self, NestedSTARError> {
    if gens.len() - 1 != keys.len() {
      return Err(NestedSTARError::LayerEncryptionKeysError(
        keys.len(),
        gens.len() - 1,
      ));
    } else if rand_bytes.len() != gens.len() {
      return Err(NestedSTARError::NumMeasurementLayersError(
        gens.len(),
        rand_bytes.len(),
      ));
    }

    let mut unencrypted_layer: Option<Message> = None;
    let mut encrypted_layers: Vec<Ciphertext> = Vec::with_capacity(keys.len());

    // construct nested star message
    for i in 0..gens.len() {
      let mg = &gens[i];
      let rnd = &rand_bytes[i];

      // set ith encryption key as auxiliary data in layer i
      // (except for last layer)
      let mut key_aux = None;
      if i < gens.len() - 1 {
        key_aux = Some(keys[i].clone());
      }

      // add any extra associated data that has been specified
      let nested_aux = NestedAssociatedData {
        key: key_aux,
        data: aux_data.to_vec(),
      };
      let message_aux = Some(AssociatedData::new(
        &bincode::serialize(&nested_aux).unwrap(),
      ));

      // generate message
      let message = Message::generate(mg, rnd, message_aux);

      // encrypt ith layer with (i-1)th key (except for first
      // layer)
      if i > 0 {
        // serialize message
        let bytes_to_encrypt =
          bincode::serialize(&SerializableMessage::from(message)).unwrap();
        let encrypted_layer = Ciphertext::new(
          &keys[i - 1],
          &bytes_to_encrypt,
          NESTED_STAR_ENCRYPTION_LABEL,
        );
        encrypted_layers.push(encrypted_layer);
      } else {
        unencrypted_layer = Some(message);
      }
    }
    Ok(Self {
      unencrypted_layer: unencrypted_layer.unwrap(),
      encrypted_layers,
    })
  }

  /// The `decrypt_next_layer` function decrypts the next layer of
  /// encrypted messages and sets the unencrypted layer to be equal to
  /// the decrypted message
  pub fn decrypt_next_layer(&mut self, key: &[u8]) {
    if self.encrypted_layers.is_empty() {
      panic!("No more layers to decrypt");
    }
    let decrypted =
      self.encrypted_layers[0].decrypt(key, NESTED_STAR_ENCRYPTION_LABEL);
    let sm: SerializableMessage = bincode::deserialize(&decrypted).unwrap();
    self.unencrypted_layer = sm.into();
    self.encrypted_layers = self.encrypted_layers[1..].to_vec();
  }
}

/// Serialization wrapper for the `NestedMessage` struct
#[derive(Serialize, Deserialize)]
pub struct SerializableNestedMessage {
  unencrypted_layer: SerializableMessage,
  encrypted_layers: Vec<Vec<u8>>,
}
impl From<SerializableNestedMessage> for NestedMessage {
  fn from(sm: SerializableNestedMessage) -> NestedMessage {
    NestedMessage {
      unencrypted_layer: sm.unencrypted_layer.into(),
      encrypted_layers: sm
        .encrypted_layers
        .into_iter()
        .map(Ciphertext::from)
        .collect(),
    }
  }
}
impl From<&SerializableNestedMessage> for NestedMessage {
  fn from(sm: &SerializableNestedMessage) -> NestedMessage {
    NestedMessage {
      unencrypted_layer: sm.unencrypted_layer.clone().into(),
      encrypted_layers: sm
        .encrypted_layers
        .iter()
        .map(|c| Ciphertext::from(c.to_vec()))
        .collect(),
    }
  }
}
impl From<NestedMessage> for SerializableNestedMessage {
  fn from(nm: NestedMessage) -> Self {
    Self {
      unencrypted_layer: nm.unencrypted_layer.into(),
      encrypted_layers: nm
        .encrypted_layers
        .iter()
        .map(|c| c.to_bytes())
        .collect(),
    }
  }
}

/// The `NestedAssociatedData` struct is a serializable struct that
/// accompanies a layer of a `NestedMessage`. The `key` field should
/// contain a symmetric encryption key that decrypts the message at the
/// next layer in the `NestedMessage`. It is optional to allow
/// specifying `None`for the final message layer. The `data` field
/// contains arbitrary encoded data that accompanies the associated
/// measurement, it is empty if none is specified.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NestedAssociatedData {
  key: Option<Vec<u8>>,
  data: Vec<u8>,
}

/// Internal struct that contains the partial measurement at a given
/// layer, plus the encryption key for decrypting the next layer.
#[derive(Clone, Debug)]
pub struct PartialMeasurement {
  measurement: NestedMeasurement,
  aux: NestedAssociatedData,
}
impl PartialMeasurement {
  pub fn get_next_layer_key(&self) -> &Option<Vec<u8>> {
    &self.aux.key
  }
}

/// `FinalMeasurement` contains the measurement data output from a
/// single message, including any additional data included at each
/// layer. Important: The auxiliary data that is included is only taken
/// from the last layer that was opened.
#[derive(Clone, Debug)]
pub struct FinalMeasurement {
  measurement: NestedMeasurement,
  data: Vec<u8>,
}
impl FinalMeasurement {
  pub fn measurement_to_vec(&self) -> Vec<Vec<u8>> {
    let v = self.get_partial_measurement_vector(self.measurement.len() - 1);
    let mut ov = Vec::new();
    for x in v {
      ov.push(x.to_vec());
    }
    ov
  }

  pub fn get_measurement_raw(&self) -> Vec<u8> {
    self.get_partial_measurement_raw(self.measurement.len() - 1)
  }

  pub fn get_aux_data(&self) -> &[u8] {
    &self.data
  }

  fn get_partial_measurement_raw(&self, i: usize) -> Vec<u8> {
    self.measurement.get_layer_as_bytes(i)
  }

  fn get_partial_measurement_vector(
    &self,
    i: usize,
  ) -> Vec<[u8; MAX_MEASUREMENT_LEN]> {
    self.measurement.get_split_layer(i)
  }
}
impl From<&PartialMeasurement> for FinalMeasurement {
  fn from(pm: &PartialMeasurement) -> Self {
    let pm_to_set = pm.measurement.clone();
    Self {
      measurement: pm_to_set,
      data: pm.aux.data.clone(),
    }
  }
}
impl PartialEq for FinalMeasurement {
  fn eq(&self, other: &Self) -> bool {
    self.get_measurement_raw() == other.get_measurement_raw()
  }
}

#[derive(Clone, Debug)]
pub struct PartialRecoveredMessage {
  pub measurement: Option<FinalMeasurement>,
  pub next_message: Option<NestedMessage>,
}
impl PartialRecoveredMessage {
  pub fn get_measurement_raw(&self) -> Vec<u8> {
    match self.measurement.as_ref() {
      Some(m) => m.get_measurement_raw(),
      None => Vec::new(),
    }
  }

  pub fn get_aux_data(&self) -> Vec<u8> {
    match self.measurement.as_ref() {
      Some(m) => m.get_aux_data().to_vec(),
      None => Vec::new(),
    }
  }

  pub fn measurement_to_vec(&self) -> Vec<Vec<u8>> {
    match self.measurement.as_ref() {
      Some(m) => m.measurement_to_vec(),
      None => Vec::new(),
    }
  }
}

/// Internal struct that adds a long-lived identifier to a
/// `NestedMessage` instantiation, for allowing easy traversal of the
/// nesting tree.
#[derive(Clone, Debug)]
struct IdentNestedMessage {
  message: NestedMessage,
  ident: usize,
}
impl IdentNestedMessage {
  fn get_next_layer(&self) -> IdentMessage {
    IdentMessage {
      message: self.message.unencrypted_layer.clone(),
      ident: self.ident,
    }
  }

  fn get_next_layer_message(&self) -> &Message {
    &self.message.unencrypted_layer
  }

  fn decrypt_next_layer(&mut self, key: &[u8]) {
    self.message.decrypt_next_layer(key)
  }
}

/// Internal struct that wraps the unencrypted layer of an
/// `IdentNestedMessage` instantiation.
#[derive(Clone, Debug)]
struct IdentMessage {
  message: Message,
  ident: usize,
}
impl IdentMessage {
  fn get_tag(&self) -> &[u8] {
    &self.message.tag
  }
}

/// `recover_partial_measurement` returns all partial output
/// measurements according to the list of messages that it is provided.
pub fn recover_partial_measurements(
  nested_messages: &[NestedMessage],
  epoch: u8,
  threshold: u32,
  num_layers: usize,
) -> Vec<Result<PartialRecoveredMessage, NestedSTARError>> {
  // Identify each message with a long-term identifier
  let mut ident_nested_messages = Vec::new();
  for (i, nm) in nested_messages.iter().enumerate() {
    ident_nested_messages.push(Some(IdentNestedMessage {
      message: nm.clone(),
      ident: i,
    }));
  }

  // The `current layer` holds all subsets of messages associated with
  // the current layer of nodes in the navigated tree
  let mut current_layer: Vec<Vec<IdentMessage>> = vec![ident_nested_messages
    .iter()
    .map(|m| m.as_ref().unwrap().get_next_layer())
    .collect()];

  // The `measurements` variable will eventually hold the most fine-grained
  // partial measurement  sent by each client
  let mut measurements = vec![Ok(None); ident_nested_messages.len()];

  // refers to the layer that is currently being processed
  let mut layer_idx = 0;

  // loop through each layer in the tree and reveal partial measurment
  while layer_idx < num_layers {
    let mut next_layers = Vec::new();

    // loop through each node within the current layer of the tree
    for node in current_layer {
      // filter the subsets of the current node by all possible
      // leaves in the next layer
      let subsets = filter_node(&node, threshold);

      // loop through each subset of long-term identifiers
      // associated with the next layer of leaves
      for indices in subsets {
        // retrieve indexed messages to perform recovery
        let messages: Vec<&Message> = indices
          .iter()
          .map(|&ident| {
            ident_nested_messages[ident]
              .as_ref()
              .unwrap()
              .get_next_layer_message()
          })
          .collect();

        let key = match key_recover(&messages, epoch) {
          Err(e) => {
            indices
              .iter()
              .for_each(|&idx| measurements[idx] = Err(e.clone()));
            continue;
          }
          Ok(k) => k,
        };
        // returns an ordered vector of partial measurements for
        // the current leaf
        let res_pms = recover(&messages, &key);
        if let Err(e) = res_pms {
          indices
            .iter()
            .for_each(|&idx| measurements[idx] = Err(e.clone()));
          continue;
        }
        let pms = res_pms.unwrap();

        // We may need to decrypt the next layer of STAR
        // messages for those partial measurments which have
        // been recovered
        if layer_idx + 1 < num_layers {
          let decrypted_messages = (0..indices.len())
            .into_iter()
            .map(|i| {
              let ident = indices[i];
              let key = pms[i].get_next_layer_key().as_ref().unwrap();
              let msg = ident_nested_messages[ident].as_mut().unwrap();
              msg.decrypt_next_layer(key);
              msg.get_next_layer()
            })
            .collect();

          // store the decrypted messages for the next layer
          next_layers.push(decrypted_messages);
        } else {
          (0..indices.len())
            .into_iter()
            .for_each(|i| ident_nested_messages[indices[i]] = None);
        }

        // set the current partial outputs
        (0..indices.len()).into_iter().for_each(|j| {
          let idx = indices[j];
          measurements[idx] = Ok(Some(FinalMeasurement::from(&pms[j])));
        });
      }
    }
    current_layer = next_layers;
    layer_idx += 1;
  }

  ident_nested_messages
    .into_iter()
    .zip(measurements.into_iter())
    .map(|(ident_nested_msg, measurement)| match measurement {
      Err(e) => Err(e),
      Ok(msmt) => {
        let msg = match ident_nested_msg {
          None => None,
          Some(m) => Some(m.message),
        };
        Ok(PartialRecoveredMessage {
          measurement: msmt,
          next_message: msg,
        })
      }
    })
    .collect()
}

pub fn sample_layer_enc_keys(num_layers: usize) -> Vec<Vec<u8>> {
  let num_keys = num_layers - 1;
  let mut keys = Vec::with_capacity(num_keys);
  for _ in 0..num_keys {
    let mut enc_key = vec![0u8; LAYER_ENC_KEY_LEN];
    OsRng.fill_bytes(&mut enc_key);
    keys.push(enc_key);
  }
  keys
}

/// Run the standard star recovery procedure for an array of STAR
/// messages
pub fn recover(
  subset: &[&Message],
  key: &[u8],
) -> Result<Vec<PartialMeasurement>, NestedSTARError> {
  let ciphertexts = subset.iter().map(|t| t.ciphertext.clone());
  let plaintexts = ciphertexts.map(|c| c.decrypt(key, "star_encrypt"));

  let splits: Vec<(Vec<u8>, NestedAssociatedData)> = plaintexts
    .map(|slice| {
      // parse all measurement bytes we discard the first four
      // bytes, these give the length, but for now the length of
      // each entry is fixed as 32 bytes
      let bytes = slice[..4 + MAX_MEASUREMENT_LEN].to_vec();
      let measurement_bytes = load_bytes(&bytes).unwrap().to_vec();

      // parse remaining bytes of auxiliary data
      let rem = &slice[4 + measurement_bytes.len() as usize..];
      let aux_bytes = load_bytes(rem).unwrap();
      let aux: NestedAssociatedData = bincode::deserialize(aux_bytes).unwrap();
      (measurement_bytes, aux)
    })
    .collect();

  // check that decrypted measurements all have the same value
  let measurement = &splits[0].0;
  for new_measurement in splits.iter().skip(1) {
    if &new_measurement.0 != measurement {
      return Err(NestedSTARError::ClientMeasurementMismatchError(
        base64::encode(measurement),
        base64::encode(&new_measurement.0),
      ));
    }
  }

  // Output all partial measurements and associated auxiliary data
  Ok(
    splits
      .into_iter()
      .map(|(measurement_bytes, aux)| {
        let y = vec![measurement_bytes];
        let nm = NestedMeasurement::new(&y).unwrap();
        PartialMeasurement {
          measurement: nm,
          aux,
        }
      })
      .collect(),
  )
}

/// Runs the standard STAR key recovery mechanism
pub fn key_recover(
  layer: &[&Message],
  epoch: u8,
) -> Result<Vec<u8>, NestedSTARError> {
  let mut result = vec![0u8; LAYER_ENC_KEY_LEN];
  let shares: Vec<Share> = layer.iter().map(|m| m.share.clone()).collect();
  let res = share_recover(&shares);
  if res.is_err() {
    return Err(NestedSTARError::ShareRecoveryFailedError);
  }
  let message = res.unwrap().get_message();
  derive_ske_key(&message, &[epoch], &mut result);
  Ok(result)
}

/// Filters out subsets of matching STAR messages that are smaller than
/// the threshold
fn filter_node(node: &[IdentMessage], threshold: u32) -> Vec<Vec<usize>> {
  let collected = group_messages(node);
  collected
    .into_iter()
    .filter(|bucket| bucket.len() >= threshold as usize)
    .collect()
}

/// Groups STAR messages by tag
fn group_messages(node: &[IdentMessage]) -> Vec<Vec<usize>> {
  let mut grouped: HashMap<String, Vec<usize>> = HashMap::new();
  for im in node {
    let s = format!("{:x?}", im.get_tag());
    match grouped.entry(s) {
      Entry::Vacant(e) => {
        e.insert(vec![im.ident]);
      }
      Entry::Occupied(mut e) => {
        e.get_mut().push(im.ident);
      }
    }
  }
  grouped.values().cloned().collect()
}

#[cfg(test)]
mod tests {
  use super::*;
  use sta_rs::share_recover;

  #[test]
  fn construct_measurement() {
    let measurement = vec![
      vec![1u8; MAX_MEASUREMENT_LEN],
      vec![2u8; MAX_MEASUREMENT_LEN],
      vec![3u8; MAX_MEASUREMENT_LEN],
    ];
    let nm = NestedMeasurement::new(measurement.as_slice()).unwrap();
    assert_eq!(nm.0[0].as_vec(), measurement[0].to_vec());
    assert_eq!(nm.0[1].as_vec(), measurement[1].to_vec());
    assert_eq!(nm.0[2].as_vec(), measurement[2].to_vec());
  }

  #[test]
  fn construct_too_long_measurement() {
    let measurement = vec![
      vec![55u8; MAX_MEASUREMENT_LEN],
      vec![77u8; MAX_MEASUREMENT_LEN + 1],
      vec![99u8; MAX_MEASUREMENT_LEN + 2],
    ];
    let nm = NestedMeasurement::new(&measurement);
    assert!(nm.is_err());
    assert_eq!(nm, Err(NestedSTARError::LongMeasurementError));
  }

  #[test]
  fn bad_number_of_layer_enc_keys() {
    let threshold = 1;
    let epoch = 0u8;
    let (_, mgs, mut keys) =
      sample_client_measurement(&[1u8, 2u8, 3u8], 3, threshold, epoch);
    keys.pop();
    let rand = sample_randomness(&mgs);
    let nmsg = NestedMessage::new(&mgs, &rand, &keys, &[]);
    assert!(nmsg.is_err());
    assert_eq!(
      nmsg,
      Err(NestedSTARError::LayerEncryptionKeysError(keys.len(), 2))
    );
  }

  #[test]
  fn bad_number_of_randomness_byte_arrays() {
    let threshold = 1;
    let epoch = 0u8;
    let (_, mgs, keys) =
      sample_client_measurement(&[1u8, 2u8, 3u8], 3, threshold, epoch);
    let mut rand = sample_randomness(&mgs);
    rand.pop();
    let nmsg = NestedMessage::new(&mgs, &rand, &keys, &[]);
    assert!(nmsg.is_err());
    assert_eq!(
      nmsg,
      Err(NestedSTARError::NumMeasurementLayersError(
        mgs.len(),
        rand.len()
      ))
    );
  }

  #[test]
  fn construct_and_check_message_without_aux() {
    construct_message(None);
  }

  #[test]
  fn construct_and_check_message_with_aux_1() {
    construct_message(Some(vec![1u8; 3]));
  }

  #[test]
  fn construct_and_check_message_with_aux_2() {
    construct_message(Some(vec![2u8; 15]));
  }

  #[test]
  fn end_to_end_basic_no_aux() {
    end_to_end_basic(None);
  }

  #[test]
  fn end_to_end_basic_with_aux() {
    let aux = Some(vec![1u8; 2]);
    end_to_end_basic(aux);
  }

  #[test]
  fn end_to_end_basic_with_aux_2() {
    let aux = Some(vec![4u8; 5]);
    end_to_end_basic(aux);
  }

  #[test]
  fn end_to_end_advanced_no_aux() {
    end_to_end_advanced(None);
  }

  #[test]
  fn end_to_end_advanced_with_aux() {
    let aux = Some(vec![1u8; 3]);
    end_to_end_advanced(aux);
  }

  #[test]
  fn end_to_end_advanced_with_aux_2() {
    let aux = Some(vec![3u8; 7]);
    end_to_end_advanced(aux);
  }

  fn end_to_end_basic(aux: Option<Vec<u8>>) {
    let threshold: usize = 3;
    let measurement_len = 5;
    let num_clients = 3;
    let (outputs, measurements) = end_to_end(
      (0..num_clients)
        .into_iter()
        .map(|_| vec![1u8, 2u8, 3u8, 4u8, 5u8])
        .collect(),
      &aux,
      threshold,
      measurement_len,
    );
    for i in 0..num_clients {
      let output_layer = &outputs[i];
      assert_measurement_output_equality(
        output_layer,
        &measurements[i],
        true,
        Some(5),
      );
      assert_aux_equality(&aux, output_layer);
    }
  }

  fn end_to_end_advanced(aux: Option<Vec<u8>>) {
    let threshold: usize = 3;
    let measurement_len = 5;
    let mut full_input: Vec<Vec<u8>> = (0..5)
      .into_iter()
      .map(|_| vec![1u8, 2u8, 3u8, 4u8, 5u8])
      .collect();
    full_input.extend(
      (0..3)
        .into_iter()
        .map(|_| vec![1u8, 2u8, 3u8, 5u8, 6u8])
        .collect::<Vec<Vec<u8>>>(),
    );
    full_input.extend(
      (0..1)
        .into_iter()
        .map(|_| vec![1u8, 2u8, 5u8, 6u8, 7u8])
        .collect::<Vec<Vec<u8>>>(),
    );
    full_input.extend(
      (0..2)
        .into_iter()
        .map(|_| vec![2u8, 3u8, 4u8, 5u8, 6u8])
        .collect::<Vec<Vec<u8>>>(),
    );
    full_input.extend(
      (0..3)
        .into_iter()
        .map(|_| vec![3u8, 4u8, 5u8, 6u8, 7u8])
        .collect::<Vec<Vec<u8>>>(),
    );
    full_input.extend(
      (0..1)
        .into_iter()
        .map(|_| vec![3u8, 4u8, 5u8, 7u8, 8u8])
        .collect::<Vec<Vec<u8>>>(),
    );
    let (outputs, measurements) =
      end_to_end(full_input, &aux, threshold, measurement_len);
    for i in 0..outputs.len() {
      let mut revealed_len = measurement_len;
      let output = &outputs[i];
      let measurement = &measurements[i];
      if i > 8 && i < 11 {
        assert_measurement_output_equality(output, measurement, false, None);
        continue;
      } else if i == 8 {
        revealed_len = 2;
      } else if i == 14 {
        revealed_len = 3;
      }
      assert_measurement_output_equality(
        output,
        measurement,
        true,
        Some(revealed_len),
      );
      assert_aux_equality(&aux, output);
    }
  }

  fn end_to_end(
    inputs: Vec<Vec<u8>>,
    aux: &Option<Vec<u8>>,
    threshold: usize,
    measurement_len: usize,
  ) -> (Vec<Option<FinalMeasurement>>, Vec<NestedMeasurement>) {
    let epoch = 0u8;
    let num_clients = inputs.len();
    let mut messages: Vec<NestedMessage> = Vec::new();
    let mut measurements = Vec::new();
    for input in inputs.iter().take(num_clients) {
      let (nested_m, mgs, keys) = sample_client_measurement(
        input,
        measurement_len,
        threshold as u32,
        epoch,
      );
      let mut added_data = &vec![];
      if aux.is_some() {
        added_data = aux.as_ref().unwrap();
      }
      let rand = sample_randomness(&mgs);
      let nested_message =
        NestedMessage::new(&mgs, &rand, &keys, added_data).unwrap();
      messages.push(nested_message);
      measurements.push(nested_m);
    }
    let output_results = recover_partial_measurements(
      &messages,
      epoch,
      threshold as u32,
      measurement_len,
    );
    let outputs = output_results
      .iter()
      .map(|x| x.as_ref().unwrap().measurement.clone())
      .collect();
    (outputs, measurements)
  }

  fn assert_measurement_output_equality(
    output: &Option<FinalMeasurement>,
    measurement: &NestedMeasurement,
    revealed: bool,
    revealed_len: Option<usize>,
  ) {
    if !revealed {
      assert!(output.is_none());
    } else {
      let revealed_output = output.as_ref().unwrap();
      assert_eq!(revealed_output.measurement.len(), 1);
      assert_eq!(
        revealed_output.get_partial_measurement_raw(0),
        measurement.get_layer_as_bytes(revealed_len.unwrap() - 1)
      );
    }
  }

  fn assert_aux_equality(
    aux: &Option<Vec<u8>>,
    output: &Option<FinalMeasurement>,
  ) {
    if output.is_some() {
      let no_aux = aux.is_none();
      if !no_aux {
        let aux_check = aux.as_ref().unwrap();
        assert_eq!(&output.as_ref().unwrap().data, aux_check);
      }
    }
  }

  fn sample_client_measurement(
    vals: &[u8],
    measurement_len: usize,
    threshold: u32,
    epoch: u8,
  ) -> (NestedMeasurement, Vec<MessageGenerator>, Vec<Vec<u8>>) {
    let mut measurement: Vec<Vec<u8>> = Vec::new();
    for &x in vals.iter().take(measurement_len) {
      measurement.push(vec![x; MAX_MEASUREMENT_LEN]);
    }
    let nm = NestedMeasurement::new(&measurement).unwrap();
    let mgs = nm.get_message_generators(threshold, epoch);
    let keys = sample_layer_enc_keys(nm.len());
    (nm, mgs, keys)
  }

  fn construct_message(aux: Option<Vec<u8>>) {
    let threshold = 1;
    let epoch = 0u8;
    let (nm, mgs, keys) =
      sample_client_measurement(&[1u8, 2u8, 3u8], 3, threshold, epoch);

    // check tags and measurement in each layer
    let mut added_data = &vec![];
    if aux.is_some() {
      added_data = aux.as_ref().unwrap();
    }
    let rand = sample_randomness(&mgs);
    let mut nested_message =
      NestedMessage::new(&mgs, &rand, &keys, added_data).unwrap();
    let checks = vec![
      vec![
        171, 38, 129, 158, 77, 71, 82, 131, 243, 52, 6, 92, 214, 67, 67, 126,
        65, 245, 244, 10, 227, 83, 71, 88, 151, 34, 13, 132, 202, 224, 160,
        119,
      ],
      vec![
        129, 108, 92, 224, 25, 162, 44, 213, 211, 31, 134, 212, 156, 119, 130,
        46, 209, 216, 171, 70, 143, 75, 110, 77, 196, 200, 176, 20, 135, 114,
        218, 44,
      ],
      vec![
        105, 219, 117, 161, 102, 198, 138, 73, 23, 173, 68, 241, 95, 64, 247,
        158, 201, 69, 253, 121, 216, 163, 75, 38, 33, 196, 46, 186, 77, 53,
        203, 136,
      ],
    ];
    let aux_ref = aux.as_ref();
    for i in 0..3 {
      assert_eq!(checks[i], nested_message.unencrypted_layer.tag);
      let value =
        share_recover(&[nested_message.unencrypted_layer.share.clone()])
          .unwrap()
          .get_message();
      let mut star_key = vec![0u8; LAYER_ENC_KEY_LEN];
      derive_ske_key(&value, &[epoch], &mut star_key);
      let res = nested_message
        .unencrypted_layer
        .ciphertext
        .decrypt(&star_key, "star_encrypt");

      // check measurement value first 4 bytes are just for length
      let res_measurement = res[4..4 + MAX_MEASUREMENT_LEN].to_vec();
      assert_eq!(res_measurement, nm.get_layer_as_bytes(i));

      // check aux data
      let res_aux = res[4 + MAX_MEASUREMENT_LEN..].to_vec();
      let mut add_data = NestedAssociatedData {
        key: None,
        data: vec![],
      };
      if i < 2 {
        add_data.key = Some(keys[i].clone());
      }
      if aux.is_some() {
        add_data.data = aux_ref.unwrap().to_vec();
      } else {
        add_data.data = vec![];
      }
      let aux_check_bytes = load_bytes(&res_aux).unwrap();
      let serialized_aux = bincode::serialize(&add_data).unwrap();
      assert_eq!(aux_check_bytes.len() as usize, serialized_aux.len());
      assert_eq!(aux_check_bytes, serialized_aux);
      let add_data_unserialized: NestedAssociatedData =
        bincode::deserialize(&serialized_aux).unwrap();
      assert_eq!(add_data_unserialized.key, add_data.key);
      assert_eq!(add_data_unserialized.data, add_data.data);

      // decrypt next layer
      if i < 2 {
        nested_message.decrypt_next_layer(&keys[i]);
      }
    }
  }

  fn sample_randomness(mgs: &[MessageGenerator]) -> Vec<[u8; RANDOMNESS_LEN]> {
    let mut rnd_buf = [0u8; 32];
    let mut rand = Vec::new();
    for mg in mgs.iter() {
      mg.sample_local_randomness(&mut rnd_buf);
      rand.push(rnd_buf);
    }
    rand
  }
}
