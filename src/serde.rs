#![cfg(any(test, feature = "serde"))]

use super::{MaybePoint, MaybeScalar, Point, Scalar};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

impl Serialize for Scalar {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serdect::array::serialize_hex_lower_or_bin(&self.serialize(), serializer)
    }
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let maybe_scalar = MaybeScalar::deserialize(deserializer)?;
        maybe_scalar.not_zero().map_err(|_| {
            serde::de::Error::invalid_value(
                serde::de::Unexpected::Other("zero scalar"),
                &"a non-zero scalar",
            )
        })
    }
}

impl Serialize for MaybeScalar {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serdect::array::serialize_hex_lower_or_bin(&self.serialize(), serializer)
    }
}

impl<'de> Deserialize<'de> for MaybeScalar {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut bytes = [0; 32];
        serdect::array::deserialize_hex_or_bin(&mut bytes, deserializer)?;
        MaybeScalar::try_from(bytes).map_err(|_| {
            serde::de::Error::invalid_value(
                serde::de::Unexpected::Bytes(&bytes),
                &"a 32-byte array representing a scalar",
            )
        })
    }
}

impl Serialize for Point {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serdect::array::serialize_hex_lower_or_bin(&self.serialize(), serializer)
    }
}

impl<'de> Deserialize<'de> for Point {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let maybe_point = MaybePoint::deserialize(deserializer)?;
        maybe_point.not_inf().map_err(|_| {
            serde::de::Error::invalid_value(
                serde::de::Unexpected::Other("infinity curve point"),
                &"a non-infinity curve point",
            )
        })
    }
}

impl Serialize for MaybePoint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serdect::array::serialize_hex_lower_or_bin(&self.serialize(), serializer)
    }
}

impl<'de> Deserialize<'de> for MaybePoint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut buffer = [0; 65];
        let bytes = serdect::slice::deserialize_hex_or_bin(&mut buffer, deserializer)?;
        MaybePoint::try_from(bytes).map_err(|_| {
            serde::de::Error::invalid_value(
                serde::de::Unexpected::Bytes(&bytes),
                &"a 33-byte array representing a compressed curve point or infinity",
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_serialize() {
        let scalar = "b21643ba6bd9b6ca2e1f6da85561092ad44949835519d71dd837be8a8c67fe7f"
            .parse::<Scalar>()
            .unwrap();

        // Serialize a `Scalar`
        let serialized = serde_json::to_string(&scalar).unwrap();
        assert_eq!(
            &serialized,
            "\"b21643ba6bd9b6ca2e1f6da85561092ad44949835519d71dd837be8a8c67fe7f\""
        );

        // Deserialize a `Scalar`
        let deserialized: Scalar =
            serde_json::from_str(&serialized).expect("error deserializing Scalar");
        assert_eq!(deserialized, scalar);

        // Deserialize a `MaybeScalar`
        let maybe_deserialized: MaybeScalar =
            serde_json::from_str(&serialized).expect("error deserializing MaybeScalar");
        assert_eq!(maybe_deserialized, MaybeScalar::Valid(scalar));

        // Serialize a `MaybeScalar`
        assert_eq!(
            &serde_json::to_string(&MaybeScalar::Valid(scalar))
                .expect("failed to serialize MaybeScalar"),
            &serialized
        );

        // Deserialize zero
        let zero_deserialized: MaybeScalar = serde_json::from_str(
            "\"0000000000000000000000000000000000000000000000000000000000000000\"",
        )
        .expect("error deserializing zero");

        assert_eq!(zero_deserialized, MaybeScalar::Zero);

        // Serialize zero
        assert_eq!(
            serde_json::to_string(&MaybeScalar::Zero).expect("failed to serialize zero"),
            "\"0000000000000000000000000000000000000000000000000000000000000000\""
        );
    }

    #[test]
    fn point_serialize() {
        let point = "02d4d12f80d7e01f09322198408b4302716b5b8e9c7587e5c022cf65054d7cf722"
            .parse::<Point>()
            .unwrap();

        // Serialize a `Point`
        let serialized = serde_json::to_string(&point).expect("failed to serialize Point");
        assert_eq!(
            &serialized,
            "\"02d4d12f80d7e01f09322198408b4302716b5b8e9c7587e5c022cf65054d7cf722\""
        );

        // Deserialize a `Point`
        let deserialized: Point =
            serde_json::from_str(&serialized).expect("error deserializing Point");
        assert_eq!(deserialized, point);

        // Deserialize a `MaybePoint`
        let maybe_deserialized: MaybePoint =
            serde_json::from_str(&serialized).expect("error deserializing Point");
        assert_eq!(maybe_deserialized, MaybePoint::Valid(point));

        // Serialize a `MaybePoint`
        assert_eq!(
            &serde_json::to_string(&maybe_deserialized).expect("failed to serialize MaybePoint"),
            &serialized,
        );

        // Deserialize infinity
        let inf_deserialized: MaybePoint = serde_json::from_str(
            "\"000000000000000000000000000000000000000000000000000000000000000000\"",
        )
        .expect("failed to deserialize infinity point");

        assert_eq!(inf_deserialized, MaybePoint::Infinity);

        // Serialize infinity
        let inf_serialized =
            serde_json::to_string(&MaybePoint::Infinity).expect("failed to serialize zero");
        assert_eq!(
            inf_serialized,
            "\"000000000000000000000000000000000000000000000000000000000000000000\""
        );

        // Can deserialize uncompressed points as well.
        let uncompressed_hex = concat!(
            "\"04",
            "fdbf1eee1ffc22505dd284e866a3b16006e218f130c20c0bbf455d4b2c063acf",
            "aa031ac5f64874895ffa5c17b4b9f06cfa63407e34a2c8017a630651f8e8bd9d\"",
        );
        let uncompressed_deserialized: Point = serde_json::from_str(&uncompressed_hex)
            .expect("failed to deserialize uncompressed point");

        assert_eq!(
            uncompressed_deserialized,
            "03fdbf1eee1ffc22505dd284e866a3b16006e218f130c20c0bbf455d4b2c063acf"
                .parse::<Point>()
                .unwrap()
        );
    }
}
