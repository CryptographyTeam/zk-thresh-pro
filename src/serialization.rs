//! **serialisation module**
//!
//! This module implements hex serialisation and deserialisation of Scalar and RistrettoPoint for easy data exchange and persistent storage with external systems.

use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use hex;
use serde::{Deserialize, Serialize, Serializer};

/// Encapsulates the serialisation of Scalar (using hex encoding).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SerScalar(pub Scalar);

impl Serialize for SerScalar {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.0.to_bytes();
        serializer.serialize_str(&hex::encode(bytes))
    }
}

impl<'de> Deserialize<'de> for SerScalar {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Invalid scalar length"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        match Scalar::from_canonical_bytes(arr).into() {
            Some(scalar) => Ok(SerScalar(scalar)),
            None => Err(serde::de::Error::custom("Invalid scalar canonical bytes")),
        }
    }
}

/// Encapsulates the serialisation of RistrettoPoint (using hex encoding).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SerRistrettoPoint(pub RistrettoPoint);

impl Serialize for SerRistrettoPoint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let comp = self.0.compress();
        serializer.serialize_str(&hex::encode(comp.as_bytes()))
    }
}

impl<'de> Deserialize<'de> for SerRistrettoPoint {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Invalid point length")); // length error
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let comp = CompressedRistretto(arr);
        match comp.decompress() {
            Some(point) => {
                // Add point legality check: deserialization to identity elements is not allowed
                if !point.is_identity() {
                    Ok(SerRistrettoPoint(point))
                } else {
                    Err(serde::de::Error::custom("Invalid point: identity"))
                }
            }
            None => Err(serde::de::Error::custom("Invalid compressed point")),
        }
    }
}

/// Provide helper functions for serde to use
pub mod serialize_scalar_helpers {
    use super::SerScalar;
    use curve25519_dalek::scalar::Scalar;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(scalar: &Scalar, serializer: S) -> Result<S::Ok, S::Error> {
        SerScalar(scalar.clone()).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Scalar, D::Error> {
        Ok(SerScalar::deserialize(deserializer)?.0)
    }
}

pub mod serialize_ristretto_point_helpers {
    use super::SerRistrettoPoint;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        point: &RistrettoPoint,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        SerRistrettoPoint(point.clone()).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<RistrettoPoint, D::Error> {
        Ok(SerRistrettoPoint::deserialize(deserializer)?.0)
    }
}
