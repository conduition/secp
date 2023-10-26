# `secp`

A flexible and secure secp256k1 elliptic curve math library, with constant-time support, and superb ergonomics.

`secp` takes full advantage of Rust's `std::ops` traits to make elliptic curve cryptography code easy to read, easy to write, succinct, readable, and secure.

## Example

Here's an implementation of simple Schnorr signatures using the `secp` crate.

```rust
use secp::{MaybeScalar, Point, Scalar};
use sha2::{Digest, Sha256};

fn compute_challenge(nonce_point: &Point, pubkey: &Point, msg: &[u8]) -> MaybeScalar {
    let hash: [u8; 32] = Sha256::new()
        .chain_update(&nonce_point.serialize())
        .chain_update(&pubkey.serialize())
        .chain_update(msg)
        .finalize()
        .into();
    MaybeScalar::reduce_from(&hash)
}

fn random_scalar() -> Scalar {
    // In an actual implementation this would produce a scalar value
    // sampled from a CSPRNG.
    Scalar::two()
}

fn schnorr_sign(secret_key: Scalar, message: &[u8]) -> (Point, MaybeScalar) {
    let nonce = random_scalar();
    let nonce_point = nonce.base_point_mul();
    let pubkey = secret_key.base_point_mul();

    let e = compute_challenge(&nonce_point, &pubkey, message);
    let s = nonce + secret_key * e;
    (nonce_point, s)
}

fn schnorr_verify(public_key: Point, signature: (Point, MaybeScalar), message: &[u8]) -> bool {
    let (r, s) = signature;
    let e = compute_challenge(&r, &public_key, message);
    s.base_point_mul() == r + e * public_key
}

let secret_key: Scalar = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    .parse()
    .unwrap();
let public_key = secret_key.base_point_mul();

let message = b"I am the dragon!";

let signature = schnorr_sign(secret_key, message);
assert!(schnorr_verify(public_key, signature, message));
```

## Choice of Backbone

This crate does not implement elliptic curve point math directly. Instead we depend on one of two reputable elliptic curve cryptography libraries:

- C bindings to [`libsecp256k1`](https://github.com/bitcoin-core/secp256k1), via [the `secp256k1` crate](https::crates.io/crates/secp256k1), maintained by the Bitcoin Core team.
- A pure-rust implementation via [the `k256` crate](https://crates.io/crates/k256), maintained by the [RustCrypto](https://github.com/RustCrypto) team.

**One or the other can be used.** By default, this crate prefers to rely on `libsecp256k1`, as this is the most vetted and publicly trusted implementation of secp256k1 curve math available anywhere. However, if you need a pure-rust implementation, you can install this crate without it, and use the pure-rust `k256` crate instead.

```notrust
cargo add secp --no-default-features --features k256
```

If both `k256` and `secp256k1` features are enabled, then we default to using `libsecp256k1` bindings for the actual math, but still provide trait implementations to make this crate interoperable with `k256`.

## API

To see the API documentation, [head on over to docs.rs](https://docs.rs/secp).
