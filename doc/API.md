# API

The `secp` crate's primary export is four types which can be used to represent elliptic curve points (e.g. public keys) and scalars (e.g. private keys).

- [`Scalar`] for non-zero scalar values.
- [`Point`] for non-infinity curve points
- [`MaybeScalar`] for possibly-zero scalars.
- [`MaybePoint`] for possibly-infinity curve points.

Depending on which features of this crate are enabled, we implement various conversion traits between these types and higher-level types such as [`secp256k1::PublicKey`] or [`k256::SecretKey`].

<!-- TODO more docs needed -->
