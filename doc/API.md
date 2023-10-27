# Features

| Feature | Description | Dependencies | Enabled by Default |
|---------|-------------|--------------|:------------------:|
| `secp256k1` | Use [`libsecp256k1`](https://github.com/bitcoin-core/secp256k1) bindings for elliptic curve math. Include trait implementations for converting to and from types in [the `secp256k1` crate][secp256k1]. This feature supercedes the `k256` feature if that one is enabled. | [`secp256k1`] | ✅ |
| `k256` | Use [the `k256` crate][k256] for elliptic curve math. This enables a pure-rust build. Include trait implementations for types from `k256`. If the `secp256k1` feature is enabled, then `k256` will still be brought in and trait implementations will be included, but the actual curve math will be done by `libsecp256k1`. | [`k256`] | ❌ |
| `serde` | Implement serialization and deserialization for types in this crate. | [`serde`](https://docs.rs/serde) | ❌ |
| `rand` | Enable support for random scalar sampling with a CSPRNG, via [the `rand` crate](https://crates.io/crates/rand) | [`rand`] | ❌ |
| `secp256k1-invert` | `libsecp256k1` doesn't expose any functionality to invert scalars modulo the curve order (i.e. to compute t<sup>-1</sup> for some scalar t, so that t(t<sup>-1</sup>) = 1 mod n). Inversion is useful for certain cryptographic operations, such as ECDSA signing, or OPRFs. <br> <br> Enable this feature if you need to invert scalars but you only have the `secp256k1` feature enabled. This feature is only useful if the `secp256k1` feature is enabled but `k256` is not, as the [`k256`] crate provides scalar inversion methods. This feature pulls in [the `crypto-bigint` crate][crypto_bigint] to perform the inversion. | [`crypto_bigint`] | ❌ |

# Usage

The `secp` crate's primary export is four types which can be used to represent elliptic curve points (e.g. public keys) and scalars (e.g. private keys).

- [`Scalar`] for non-zero scalar values.
- [`Point`] for non-infinity curve points
- [`MaybeScalar`] for possibly-zero scalars.
- [`MaybePoint`] for possibly-infinity curve points.

Depending on which features of this crate are enabled, we implement various conversion traits between these types and higher-level types such as [`secp256k1::PublicKey`] or [`k256::SecretKey`].

```rust
# #[cfg(all(feature = "secp256k1", feature = "rand"))]
# {
let seckey = secp256k1::SecretKey::new(&mut rand::rngs::OsRng);
let scalar = secp::Scalar::from(seckey);
secp256k1::SecretKey::from(scalar);
secp256k1::Scalar::from(scalar);

let point: secp::Point = scalar.base_point_mul();
secp256k1::PublicKey::from(point);
# }

# #[cfg(feature = "k256")]
# {
let seckey = k256::SecretKey::random(&mut rand::rngs::OsRng);
let scalar = secp::Scalar::from(seckey);
k256::SecretKey::from(scalar);
k256::Scalar::from(scalar);
k256::NonZeroScalar::from(scalar);
k256::Scalar::from(secp::MaybeScalar::Valid(scalar));
assert!(k256::NonZeroScalar::try_from(secp::MaybeScalar::Valid(scalar)).is_ok());
assert!(k256::NonZeroScalar::try_from(secp::MaybeScalar::Zero).is_err());

let point: secp::Point = scalar.base_point_mul();
k256::PublicKey::from(point);
k256::AffinePoint::from(point);
# }
```

# Scalars

A [`Scalar`] can represent any integers in the range `[1, n)`, while a [`MaybeScalar`] represents any integer in the range `[0, n)`, where `n` is the secp256k1 elliptic curve order (the number of possible points on the curve). As [`Scalar`] is never zero it doesn't implement [`Default`]). [`MaybeScalar::Zero`] represents the integer zero.

```rust
# use secp::Scalar;
pub enum MaybeScalar {
    Zero,
    Valid(Scalar),
}
```

## Arithmetic

Addition, subtract, and multiplication operators are supported by default between the two scalar types. All operations are done in the finite field modulo `n`.

```rust
use secp::{MaybeScalar, Scalar};

assert_eq!(
    (Scalar::one() + Scalar::two()) * Scalar::max(),
    Scalar::max() - Scalar::two()
);

// Addition or subtraction of two non-zero [`Scalar`] instances will
// output a [`MaybeScalar`], since the sum of two non-zero numbers
// could be zero in a finite field.
assert_eq!(Scalar::one() + Scalar::one(), MaybeScalar::two());

// Arithmetic works across commutatively both scalar types.
assert_eq!(
    MaybeScalar::from(20) * Scalar::two() - Scalar::try_from(10).unwrap(),
    MaybeScalar::from(30)
);

// Zero acts like zero.
assert_eq!(MaybeScalar::Zero + Scalar::two(), MaybeScalar::two());
assert_eq!(MaybeScalar::Zero * Scalar::two(), MaybeScalar::Zero);
```

Division is supported via [modular multiplicative inversion](https://en.wikipedia.org/wiki/Modular_multiplicative_inverse). Since libsecp256k1 does not support this out of the box, scalar inversion requires either the `k256` feature or the `secp256k1-invert` feature to be enabled.

```rust
# #[cfg(any(feature = "k256", feature = "secp256k1-invert"))]
# {
# use secp::Scalar;
let x = "0000000000000000000000000000000000000000000000000000000000000aae"
    .parse::<Scalar>()
    .unwrap();

assert_eq!(
    x / Scalar::two(),
    "0000000000000000000000000000000000000000000000000000000000000557"
        .parse()
        .unwrap()
);

// Since `0xAAF` is an odd number, this would be a fraction if we were
// operating in the real numbers. Since we're operating in a finite field,
// there does exist an integer solution to the equation `x * 2 = 0xAAF`
assert_eq!(
    (x + Scalar::one()) / Scalar::two(),
    "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b25f8"
        .parse()
        .unwrap()
);
# }
```

Division by a `MaybeScalar` is not defined, since the divisor might be zero.

```compile_fail
# use secp::{MaybeScalar, Scalar};
Scalar::two() / MaybeScalar::two();
```

## Formatting

To reduce the risk of accidental exposure of private keys, signatures, or other secret scalar values, `Scalar` does not implement [`Display`][std::fmt::Display].

```compile_fail
println!("{}", Scalar::max());
```

Instead, `Scalar`s can be formatted as hex strings explicitly by using `{:x}` or `{:X}` format directives, via the [`LowerHex`][std::fmt::LowerHex] or [`UpperHex`][std::fmt::UpperHex] trait implementations on `Scalar`. Conversion to hex is done in constant-time, but we can't make any guarantees about side-channel leakage beyond that point.

```rust
# use secp::{MaybeScalar, Scalar};
let hex = "e2df7e885217c19c42a8159fd02633f0dc463fadfafc09a71af20bfa2b9036c6";
let scalar = hex.parse::<Scalar>().unwrap();

assert_eq!(format!("{:x}", scalar), hex);
assert_eq!(format!("{:X}", scalar), hex.to_uppercase());
assert_eq!(format!("{:x}", MaybeScalar::Valid(scalar)), hex);
assert_eq!(format!("{:X}", MaybeScalar::Valid(scalar)), hex.to_uppercase());
assert_eq!(
    format!("{:x}", MaybeScalar::Zero),
    "0000000000000000000000000000000000000000000000000000000000000000"
);
```

# Points

Valid elliptic curve points are represented by the [`Point`] type. There is a special curve point called _infinity,_ or the _identity point,_ or the _zero point,_ which we represent as [`MaybePoint::Infinity`].

```rust
# use secp::Point;
pub enum MaybePoint {
    Infinity,
    Valid(Point),
}
```

## Arithmetic

Points can be added and subtracted from one-another.

```rust
use secp::{MaybePoint, Point};

let P1 = "02b435092055e2dc9a1474dac777302c172dde0a40323f0879bff48d002575b685"
    .parse::<Point>()
    .unwrap();
let P2 = "0375663d8ea90563709204f1b1ff4822220cfb257ed5602609282314ba4e7d492c"
    .parse::<Point>()
    .unwrap();

let P3 = "02bc0b73e8233f4fbaa30bcfa540f76d517d385383dd8c9a13ba6dad097f8ea9db"
    .parse::<Point>()
    .unwrap();

// Similar to `Scalar`, adding and subtracting non-infinity points
// results in a `MaybePoint`, because point addition is cyclic just
// like scalar addition.
assert_eq!(P1 + P2, MaybePoint::Valid(P3));
assert_eq!(P3 - P2, MaybePoint::Valid(P1));

// Iterators of points can be summed like any other number-like type.
// Prefer this over manually implementing a summation reducer, as
// we offload most of the work to libsecp256k1.
assert_eq!(
    [P1, P2].into_iter().sum::<MaybePoint>(),
    MaybePoint::Valid(P3)
);
```

And of course, the most important operation in elliptic curve cryptography, **scalar-point multiplication** is also supported.

```rust
use secp::{MaybePoint, Point, Scalar};

let P = "02b435092055e2dc9a1474dac777302c172dde0a40323f0879bff48d002575b685"
    .parse::<Point>()
    .unwrap();

let d = Scalar::try_from(3).unwrap();

// Multiplying by one is a no-op.
assert_eq!(P * Scalar::one(), P);

// Multiplying by a non-zero scalar guarantees a non-zero
// point is the output.
assert_eq!(
    P * d,
    (P + P + P).unwrap()
);

// Multiplying by the secp256k1 base point `G` is easy.
assert_eq!(
    d.base_point_mul(),
    d * Point::generator()
);

// We provide a static shortcut to the generator point `G`
// which works with arithemtic operators.
use secp::G;
assert_eq!(
    G * d,
    (G + G + G).unwrap()
);
assert_eq!(G - G, MaybePoint::Infinity);

// Point-scalar division works if scalar inversion is enabled
// by the feature set.
# #[cfg(any(feature = "k256", feature = "secp256k1-invert"))]
assert_eq!(d * G / d, (*G));
```

## Formatting

Like the scalars, [`Point`] and [`MaybePoint`] can be formatted compressed form as hex strings explicitly using `{:x}` and `{:X}` directives. They also implement [`Display`][std::fmt::Display]. The default displayable string value of [`Point`] and [`MaybePoint`] is the compressed lower-case hex encoding. Uncompressed keys can be formatted by adding the `+` flag to the directive, i.e. by formatting as `{:+}` or `{:+x}`.

```rust
# use secp::{MaybePoint, Point};
// Compressed
let point_hex = "02bc0b73e8233f4fbaa30bcfa540f76d517d385383dd8c9a13ba6dad097f8ea9db";
let point: Point = point_hex.parse().unwrap();
assert_eq!(point.to_string(), point_hex);
assert_eq!(format!("{}", point), point_hex);
assert_eq!(format!("{:x}", point), point_hex);
assert_eq!(format!("{:X}", point), point_hex.to_uppercase());
assert_eq!(format!("{:x}", MaybePoint::Valid(point)), point_hex);
assert_eq!(format!("{:X}", MaybePoint::Valid(point)), point_hex.to_uppercase());
assert_eq!(
    format!("{:x}", MaybePoint::Infinity),
    "000000000000000000000000000000000000000000000000000000000000000000"
);

// Uncompressed
let point_hex_uncompressed =
    "04bc0b73e8233f4fbaa30bcfa540f76d517d385383dd8c9a13ba6dad097f8ea9db\
     6c11d8da7d251e5756c297147a40767bd21d3cd18a830bf79dd4d17ba26fc546";
let point: Point = point_hex_uncompressed.parse().unwrap();
assert_eq!(format!("{:+}", point), point_hex_uncompressed);
assert_eq!(format!("{:+x}", point), point_hex_uncompressed);
assert_eq!(format!("{:+X}", point), point_hex_uncompressed.to_uppercase());
assert_eq!(format!("{:+x}", MaybePoint::Valid(point)), point_hex_uncompressed);
assert_eq!(format!("{:+X}", MaybePoint::Valid(point)), point_hex_uncompressed.to_uppercase());
assert_eq!(
    format!("{:+x}", MaybePoint::Infinity),
    "000000000000000000000000000000000000000000000000000000000000000000\
     0000000000000000000000000000000000000000000000000000000000000000"
);
```
