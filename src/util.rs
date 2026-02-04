#[cfg(all(feature = "cbor", feature = "bincode"))]
compile_error!("Features 'cbor' and 'bincode' are mutually exclusive");

#[cfg(not(any(feature = "cbor", feature = "bincode")))]
compile_error!("One of 'cbor' or 'bincode' feature must be enabled");

use serde::{de::DeserializeOwned, Serialize};

use crate::Error;

pub fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
  #[cfg(feature = "bincode")]
  {
    bincode::serialize(value).map_err(|e| Error::Serialization(e.to_string()))
  }
  #[cfg(feature = "cbor")]
  {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
      .map_err(|e| Error::Serialization(e.to_string()))?;
    Ok(buf)
  }
  #[cfg(not(any(feature = "cbor", feature = "bincode")))]
  {
    panic!("No serialization feature enabled. Enable either 'cbor' or 'bincode' feature.");
  }
}

pub fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
  #[cfg(feature = "bincode")]
  {
    bincode::deserialize(bytes).map_err(|e| Error::Serialization(e.to_string()))
  }
  #[cfg(feature = "cbor")]
  {
    ciborium::from_reader(bytes)
      .map_err(|e| Error::Serialization(e.to_string()))
  }
  #[cfg(not(any(feature = "cbor", feature = "bincode")))]
  {
    panic!("No serialization feature enabled. Enable either 'cbor' or 'bincode' feature.");
  }
}
