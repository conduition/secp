use once_cell::sync::Lazy;
use subtle::{ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};

use super::errors::{InvalidScalarBytes, InvalidScalarString, ZeroScalarError};
use super::{MaybePoint, Point};

#[cfg(feature = "secp256k1")]
pub(crate) const LIBSECP256K1_CTX: Lazy<secp256k1::Secp256k1<secp256k1::All>> =
    Lazy::new(secp256k1::Secp256k1::new);

static SCALAR_ONE: Lazy<Scalar> = Lazy::new(|| {
    Scalar::try_from(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1u8,
    ])
    .unwrap()
});

static SCALAR_TWO: Lazy<Scalar> = Lazy::new(|| {
    Scalar::try_from(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 2u8,
    ])
    .unwrap()
});

static SCALAR_HALF_ORDER: Lazy<Scalar> = Lazy::new(|| {
    Scalar::try_from(&[
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0u8,
    ])
    .unwrap()
});

static SCALAR_MAX: Lazy<Scalar> =
    Lazy::new(|| Scalar::try_from(&CURVE_ORDER_MINUS_ONE_BYTES).unwrap());

/// This is a big-endian representation of the secp256k1 curve order `n`.
const CURVE_ORDER_BYTES: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// This is a big-endian representation of the secp256k1 curve order `n` minus one.
const CURVE_ORDER_MINUS_ONE_BYTES: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40,
];

/// The largest possible 256-bit integer, represented as a byte array.
const MAX_U256: [u8; 32] = [0xFF; 32];

/// Represents a non-zero scalar in the range `[1, n)` where `n` is the order
/// of the secp256k1 curve. A `Scalar` can be:
///
/// - added, negated, subtracted, and multiplied with other `Scalar` instances.
/// - added, negated, subtracted, and multiplied with [`MaybeScalar`].
/// - multiplied with [`Point`].
/// - multiplied with [`MaybePoint`].
///
/// ...using the normal Rust arithemtic operators `+`, `-` and `*`. Such operations
/// are commutative, i.e. `a * b = b * a` and `a + b = b + a` in call cases.
///
/// Depending on the types involved in an operation, certain operators will produce
/// different result types which should be handled depending on your use case. For
/// instance, adding two `Scalar`s results in a [`MaybeScalar`], because the two
/// `Scalar`s may be additive inverses of each other and their output would result
/// in [`MaybeScalar::Zero`] when taken mod `n`.
#[derive(Copy, Clone)]
#[cfg_attr(feature = "secp256k1", derive(PartialEq))]
pub struct Scalar {
    #[cfg(feature = "secp256k1")]
    pub(crate) inner: secp256k1::SecretKey,

    #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
    pub(crate) inner: k256::NonZeroScalar,
}

impl Scalar {
    /// Returns a valid `Scalar` with a value of 1.
    pub fn one() -> Scalar {
        *SCALAR_ONE
    }

    /// Returns a valid `Scalar` with a value of two.
    pub fn two() -> Scalar {
        *SCALAR_TWO
    }

    /// Returns half of the curve order `n`, specifically `n >> 1`.
    pub fn half_order() -> Scalar {
        *SCALAR_HALF_ORDER
    }

    /// Returns a valid `Scalar` with the maximum possible value less
    /// than the curve order, `n - 1`.
    pub fn max() -> Scalar {
        *SCALAR_MAX
    }

    /// Returns `subtle::Choice::from(1)` if this scalar is strictly greater
    /// than half the curve order; i.e if `self > (n >> 1)`.
    ///
    /// This is used to reduce malleability of ECDSA signatures, whose `s` values
    /// could be considered valid if they are either `s` or `n - s`. Converting
    /// the `s` value using [`Scalar::to_low`] and checking it using
    /// [`Scalar::is_high`] upon verification fixes this ambiguity.
    ///
    /// Beware that leaking timing information about this bit may expose a bit
    /// of information about the scalar.
    pub fn is_high(&self) -> subtle::Choice {
        self.ct_gt(&Self::half_order())
    }

    /// If [`self.is_high()`][Self::is_high], this returns `-self`. Otherwise, returns
    /// the scalar unchanged.
    ///
    /// This is used to reduce malleability of ECDSA signatures, whose `s` values
    /// could be considered valid if they are either `s` or `n - s`. Converting
    /// the `s` value using [`Scalar::to_low`] and checking it using
    /// [`Scalar::is_high`] upon verification fixes this ambiguity.
    pub fn to_low(self) -> Scalar {
        let choice = self.ct_gt(&Self::half_order());
        Scalar::conditional_select(&self, &(-self), choice)
    }

    /// Generates a new random scalar from the given CSPRNG.
    #[cfg(feature = "rand")]
    pub fn random<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> Scalar {
        #[cfg(feature = "secp256k1")]
        let inner = secp256k1::SecretKey::new(rng);

        #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
        let inner = k256::NonZeroScalar::random(rng);

        Scalar::from(inner)
    }

    /// Serializes the scalar to a big-endian byte array representation.
    ///
    /// # Warning
    ///
    /// Use cautiously. Non-constant time operations on these bytes
    /// could reveal secret key material.
    pub fn serialize(&self) -> [u8; 32] {
        #[cfg(feature = "secp256k1")]
        return self.inner.secret_bytes();

        #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
        return self.inner.to_bytes().into();
    }

    /// Parses a non-zero scalar in the range `[1, n)` from a given byte slice,
    /// which must be exactly 32-byte long and must represent the scalar in
    /// big-endian format.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, InvalidScalarBytes> {
        Self::try_from(bytes)
    }

    /// Parses a `Scalar` from a 32-byte hex string representation.
    pub fn from_hex(hex: &str) -> Result<Self, InvalidScalarString> {
        hex.parse()
    }

    /// Multiplies the secp256k1 base point by this scalar. This is how
    /// public keys (points) are derived from private keys (scalars).
    /// Since this scalar is non-zero, the point derived from base-point
    /// multiplication is also guaranteed to be valid.
    pub fn base_point_mul(&self) -> Point {
        #[cfg(feature = "secp256k1")]
        let inner = self.inner.public_key(&LIBSECP256K1_CTX);

        #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
        let inner = k256::PublicKey::from_secret_scalar(&self.inner);

        Point::from(inner)
    }

    /// Negates the scalar in constant-time if the given parity bit is a 1.
    pub fn negate_if(self, parity: subtle::Choice) -> Scalar {
        Scalar::conditional_select(&self, &(-self), parity)
    }

    /// Inverts a scalar modulo the curve order `n` in constant time. This
    /// outputs a scalar such that `self * self.inverse() == Scalar::one()` for
    /// all non-zero scalars.
    #[cfg(any(feature = "k256", feature = "secp256k1-invert"))]
    pub fn invert(self) -> Scalar {
        // Simplest case: we have a k256::NonZeroScalar available.
        #[cfg(feature = "k256")]
        return {
            use k256::elliptic_curve::ops::Invert as _;
            let inverted = k256::NonZeroScalar::from(self).invert();
            Self::from(inverted)
        };

        // Aw jeez we gotta compute the multiplicative inverse ourselves using
        // crypto_bigint. Strange that libsecp256k1 doesn't expose this feature.
        #[cfg(not(feature = "k256"))]
        return {
            use crypto_bigint::modular::constant_mod::ResidueParams as _;
            use crypto_bigint::Encoding as _;
            use crypto_bigint::Invert as _;

            crypto_bigint::impl_modulus!(
                CurveModulus,
                crypto_bigint::U256,
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141" // curve order
            );

            let bigint = crypto_bigint::U256::from_be_bytes(self.serialize());
            let residue = crypto_bigint::const_residue!(bigint, CurveModulus);
            let nz_residue: crypto_bigint::NonZero<_> =
                crypto_bigint::NonZero::new(residue).unwrap();
            let inverted_bytes = nz_residue.invert().retrieve().to_be_bytes();

            Self::try_from(&inverted_bytes).unwrap()
        };
    }

    /// Converts a 32-byte array into a `Scalar` by interpreting it as a big-endian
    /// integer `z` and returning `(z % (n-1)) + 1`, where `n` is the secp256k1
    /// curve order. This always returns a valid non-zero scalar in the range `[1, n)`.
    /// All operations are constant-time, except if `z` works out to be zero.
    ///
    /// The probability that `z_bytes` represents an integer `z` larger than the
    /// curve order is only about 1 in 2^128, but nonetheless this function makes a
    /// best-effort attempt to parse all inputs in constant time and reduce them to
    /// an integer in the range `[1, n)`.
    pub fn reduce_from(z_bytes: &[u8; 32]) -> Self {
        let reduced = MaybeScalar::reduce_from_internal(z_bytes, &CURVE_ORDER_MINUS_ONE_BYTES);

        // this will never be zero, because `z` is in the range `[0, n-1)`
        (reduced + Scalar::one()).unwrap()
    }
}

mod nonzero_conversions {
    use super::*;

    #[cfg(feature = "secp256k1")]
    impl AsRef<secp256k1::SecretKey> for Scalar {
        fn as_ref(&self) -> &secp256k1::SecretKey {
            &self.inner
        }
    }

    #[cfg(feature = "secp256k1")]
    impl From<Scalar> for secp256k1::SecretKey {
        fn from(scalar: Scalar) -> secp256k1::SecretKey {
            scalar.inner
        }
    }

    #[cfg(feature = "secp256k1")]
    impl From<Scalar> for secp256k1::Scalar {
        fn from(scalar: Scalar) -> Self {
            secp256k1::Scalar::from(scalar.inner)
        }
    }

    #[cfg(feature = "k256")]
    impl From<Scalar> for k256::NonZeroScalar {
        fn from(scalar: Scalar) -> Self {
            // TODO maybe there's a better method to parse NonZeroScalar?
            #[cfg(feature = "secp256k1")]
            return k256::NonZeroScalar::try_from(scalar.serialize().as_ref()).unwrap();

            #[cfg(not(feature = "secp256k1"))]
            return scalar.inner;
        }
    }

    #[cfg(feature = "k256")]
    impl From<Scalar> for k256::SecretKey {
        fn from(scalar: Scalar) -> Self {
            k256::SecretKey::from(k256::NonZeroScalar::from(scalar))
        }
    }
}

mod std_traits {
    use super::*;

    /// This implementation was duplicated from the [`secp256k1`] crate, because
    /// [`k256::NonZeroScalar`] doesn't implement `Debug`.
    impl std::fmt::Debug for Scalar {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            use std::hash::Hasher as _;
            const DEBUG_HASH_TAG: &[u8] = &[
                0x66, 0xa6, 0x77, 0x1b, 0x9b, 0x6d, 0xae, 0xa1, 0xb2, 0xee, 0x4e, 0x07, 0x49, 0x4a,
                0xac, 0x87, 0xa9, 0xb8, 0x5b, 0x4b, 0x35, 0x02, 0xaa, 0x6d, 0x0f, 0x79, 0xcb, 0x63,
                0xe6, 0xf8, 0x66, 0x22,
            ]; // =SHA256(b"rust-secp256k1DEBUG");

            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            hasher.write(DEBUG_HASH_TAG);
            hasher.write(DEBUG_HASH_TAG);
            hasher.write(&self.serialize());
            let hash = hasher.finish();

            f.debug_tuple(stringify!(Scalar))
                .field(&format_args!("#{:016x}", hash))
                .finish()
        }
    }

    /// Reimplemented manually, because [`k256::NonZeroScalar`] doesn't implement
    /// `PartialEq`.
    #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
    impl PartialEq for Scalar {
        fn eq(&self, rhs: &Self) -> bool {
            self.inner.ct_eq(&rhs.inner).into()
        }
    }

    impl Eq for Scalar {}
}

// Perform elementwise XOR on two arrays and return the resulting output array.
fn xor_arrays<T, const SIZE: usize>(arr1: &[T; SIZE], arr2: &[T; SIZE]) -> [T; SIZE]
where
    T: Copy + Default + std::ops::BitXor<Output = T>,
{
    let mut xored = [T::default(); SIZE];
    for i in 0..SIZE {
        xored[i] = arr1[i] ^ arr2[i];
    }
    xored
}

/// Compares two slices lexicographically in constant time whose
/// elements can be ordered in constant time.
///
/// Returns:
///
/// - `Ordering::Less` if `lhs < rhs`
/// - `Ordering::Equal` if `lhs == rhs`
/// - `Ordering::Greater` if `lhs > rhs`
///
/// Duplicated from [This PR](https://github.com/dalek-cryptography/subtle/pull/116).
fn ct_slice_lex_cmp<T>(lhs: &[T], rhs: &[T]) -> std::cmp::Ordering
where
    T: ConstantTimeEq + ConstantTimeGreater,
{
    let mut whole_slice_is_eq = subtle::Choice::from(1);
    let mut whole_slice_is_gt = subtle::Choice::from(0);

    // Zip automatically stops iterating once one of the zipped
    // iterators has been exhausted.
    for (v1, v2) in lhs.iter().zip(rhs.iter()) {
        // If the previous elements in the array were all equal, but `v1 > v2` in this
        // position, then `lhs` is deemed to be greater than `rhs`.
        //
        // We want `whole_slice_is_gt` to remain true if we ever found this condition,
        // but since we're aiming for constant-time, we cannot break the loop.
        whole_slice_is_gt |= whole_slice_is_eq & v1.ct_gt(&v2);

        // Track whether all elements in the slices up to this point are equal.
        whole_slice_is_eq &= v1.ct_eq(&v2);
    }

    let l_len = lhs.len() as u64;
    let r_len = rhs.len() as u64;
    let lhs_is_longer = l_len.ct_gt(&r_len);
    let rhs_is_longer = r_len.ct_gt(&l_len);

    // Fallback: lhs < rhs
    let mut order = std::cmp::Ordering::Less;

    // both slices up to `min(l_len, r_len)` were equal.
    order.conditional_assign(&std::cmp::Ordering::Equal, whole_slice_is_eq);

    // `rhs` is a prefix of `lhs`. `lhs` is lexicographically greater.
    order.conditional_assign(
        &std::cmp::Ordering::Greater,
        whole_slice_is_eq & lhs_is_longer,
    );

    // `lhs` is a prefix of `rhs`. `rhs` is lexicographically greater.
    order.conditional_assign(&std::cmp::Ordering::Less, whole_slice_is_eq & rhs_is_longer);

    // `lhs` contains the earliest strictly-greater element.
    order.conditional_assign(&std::cmp::Ordering::Greater, whole_slice_is_gt);

    order
}

/// Represents an elliptic curve scalar value which might be zero.
/// Supports all the same constant-time arithmetic operators supported
/// by [`Scalar`].
///
/// `MaybeScalar` should only be used in cases where it is possible for
/// an input to be zero. In all possible cases, using [`Scalar`] is more
/// appropriate. The output of arithmetic operations with non-zero `Scalar`s
/// can result in a `MaybeScalar` - for example, adding two scalars together
/// linearly.
///
/// ```
/// use secp::{MaybeScalar, Scalar};
///
/// let maybe_scalar: MaybeScalar = Scalar::one() + Scalar::one();
/// ```
///
/// This is because the two scalars might represent values which are additive
/// inverses of each other (i.e. `x + (-x)`), so the output of their addition
/// can result in zero, which must be checked for by the caller where
/// appropriate.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MaybeScalar {
    Zero,
    Valid(Scalar),
}

use MaybeScalar::*;

impl MaybeScalar {
    /// Returns a valid `MaybeScalar` with a value of 1.
    pub fn one() -> MaybeScalar {
        Valid(Scalar::one())
    }

    /// Returns a valid `MaybeScalar` with a value of two.
    pub fn two() -> MaybeScalar {
        Valid(Scalar::two())
    }

    /// Returns half of the curve order `n`, specifically `n >> 1`.
    pub fn half_order() -> MaybeScalar {
        Valid(Scalar::half_order())
    }

    /// Returns a valid `MaybeScalar` with the maximum possible value less
    /// than the curve order, `n - 1`.
    pub fn max() -> MaybeScalar {
        Valid(Scalar::max())
    }

    /// Returns true if this scalar represents zero.
    pub fn is_zero(&self) -> bool {
        self == &Zero
    }

    /// Returns `subtle::Choice::from(1)` if this scalar is strictly greater
    /// than half the curve order; i.e if `self > (n >> 1)`.
    ///
    /// This is used to reduce malleability of ECDSA signatures, whose `s` values
    /// could be considered valid if they are either `s` or `n - s`. Converting
    /// the `s` value using [`MaybeScalar::to_low`] and checking it using
    /// [`MaybeScalar::is_high`] upon verification fixes this ambiguity.
    ///
    /// Beware that leaking timing information about this bit may expose a bit
    /// of information about the scalar.
    pub fn is_high(&self) -> subtle::Choice {
        self.ct_gt(&Self::half_order())
    }

    /// If [`self.is_high()`][Self::is_high], this returns `-self`. Otherwise,
    /// returns the original scalar unchanged.
    ///
    /// This is used to reduce malleability of ECDSA signatures, whose `s` values
    /// could be considered valid if they are either `s` or `n - s`. Converting
    /// the `s` value using [`MaybeScalar::to_low`] and checking it using
    /// [`MaybeScalar::is_high`] upon verification fixes this ambiguity.
    pub fn to_low(self) -> MaybeScalar {
        let choice = self.ct_gt(&Self::half_order());
        MaybeScalar::conditional_select(&self, &(-self), choice)
    }

    /// Serializes the scalar to a big-endian byte array representation.
    ///
    /// # Warning
    ///
    /// Use cautiously. Non-constant time operations on these bytes
    /// could reveal secret key material.
    pub fn serialize(&self) -> [u8; 32] {
        match self {
            Valid(scalar) => scalar.serialize(),
            Zero => [0; 32],
        }
    }

    /// Parses a non-zero scalar in the range `[1, n)` from a given byte slice,
    /// which must be exactly 32-byte long and must represent the scalar in
    /// big-endian format.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, InvalidScalarBytes> {
        Self::try_from(bytes)
    }

    /// Parses a `MaybeScalar` from a 32-byte hex string representation.
    pub fn from_hex(hex: &str) -> Result<Self, InvalidScalarString> {
        hex.parse()
    }

    /// Returns an option which is `None` if `self == MaybeScalar::Zero`,
    /// or a `Some(Scalar)` otherwise.
    pub fn into_option(self) -> Option<Scalar> {
        Option::from(self)
    }

    /// Converts the `MaybeScalar` into a `Result<Scalar, ZeroScalarError>`,
    /// returning `Ok(Scalar)` if the scalar is a valid non-zero number, or
    /// `Err(ZeroScalarError)` if `maybe_scalar == MaybeScalar::Zero`.
    pub fn not_zero(self) -> Result<Scalar, ZeroScalarError> {
        Scalar::try_from(self)
    }

    /// Coerces the `MaybeScalar` into a [`Scalar`]. Panics if `self == MaybeScalar::Zero`.
    pub fn unwrap(self) -> Scalar {
        match self {
            Valid(point) => point,
            Zero => panic!("called unwrap on MaybeScalar::Zero"),
        }
    }

    /// Converts a 32-byte array into a `MaybeScalar` by interpreting it as
    /// a big-endian integer `z` and reducing `z` modulo some given `modulus`
    /// in constant time. This modulus must less than or equal to the secp256k1
    /// curve order `n`.
    ///
    /// Unfortunately libsecp256k1 does not expose this functionality, so we have done
    /// our best to reimplement modular reduction in constant time using only scalar
    /// arithmetic on numbers in the  range `[0, n)`.
    ///
    /// Instead of taking the remainder `z % modulus` directly (which we can't do with
    /// libsecp256k1), we use XOR to compute the relative distances from `z` and `modulus`
    /// to some independent constant, specifically `MAX_U256`. We denote the distances as:
    ///
    /// - `q = MAX_U256 - z` and
    /// - `r = MAX_U256 - modulus`
    ///
    /// As long as both distances are guaranteed to be smaller than the curve order `n`, this
    /// gives us a way to compute `z % modulus` safely in constant time: by computing the
    /// difference of the two relative distances:
    ///
    /// ```notrust
    /// r - q = (MAX_U256 - modulus) - (MAX_U256 - z)
    ///       = z - modulus
    /// ```
    ///
    /// The above is only needed when `z` might be greater than the `modulus`. If instead
    /// `z < modulus`, we set `q = z` and return `q` in constant time, throwing away the
    /// result of subtracting `r - q`.
    fn reduce_from_internal(z_bytes: &[u8; 32], modulus: &[u8; 32]) -> MaybeScalar {
        // Modulus must be less than or equal to `n`, as `n-1` is the largest number we can represent.
        debug_assert!(modulus <= &CURVE_ORDER_BYTES);

        let modulus_neg_bytes = xor_arrays(&modulus, &MAX_U256);

        // Modulus must not be too small either, or we won't be able
        // to represent the distance to MAX_U256.
        debug_assert!(modulus_neg_bytes <= CURVE_ORDER_BYTES);

        // Although we cannot operate arithmetically on numbers larger than `n-1`, we can
        // still use XOR to subtract from a number represented by all one-bits, such as
        // MAX_U256.
        let z_bytes_neg = xor_arrays(z_bytes, &MAX_U256);

        let z_needs_reduction = ct_slice_lex_cmp(z_bytes, modulus).ct_gt(&std::cmp::Ordering::Less);

        let q_bytes = <[u8; 32]>::conditional_select(
            z_bytes,      // `z < modulus`; set `q = z`
            &z_bytes_neg, // `z >= modulus`; set `q = MAX_U256 - z` (implies q <= modulus)
            z_needs_reduction,
        );

        // By this point, we know for sure that `q_bytes` represents an integer less than `n`,
        // so `try_from` should always work here.
        let q = MaybeScalar::try_from(&q_bytes).unwrap();

        // Modulus distance `r` should also always be less than the curve order.
        let r = MaybeScalar::try_from(&modulus_neg_bytes).unwrap();

        // if z < modulus
        //   return q = z
        //
        // else
        //  return r - q = (MAX_U256 - modulus) - (MAX_U256 - z)
        //               = MAX_U256 - modulus - MAX_U256 + z
        //               = z - modulus
        MaybeScalar::conditional_select(&q, &(r - q), z_needs_reduction)
    }

    /// Converts a 32-byte array into a `MaybeScalar` by interpreting it as
    /// a big-endian integer `z` and reducing `z` modulo the secp256k1 curve
    /// order `n` in constant time.
    ///
    /// The probability that `z_bytes` represents an integer `z` larger than the
    /// curve order is only about 1 in 2^128, but nonetheless this function makes a
    /// best-effort attempt to parse all inputs in constant time and reduce them to
    /// an integer in the range `[0, n)`.
    pub fn reduce_from(z_bytes: &[u8; 32]) -> Self {
        Self::reduce_from_internal(z_bytes, &CURVE_ORDER_BYTES)
    }

    /// Multiplies the secp256k1 base point by this scalar. This is how
    /// public keys (points) are derived from private keys (scalars).
    ///
    /// If this scalar is [`MaybeScalar::Zero`], this method returns [`MaybePoint::Infinity`].
    pub fn base_point_mul(&self) -> MaybePoint {
        match self {
            Valid(scalar) => MaybePoint::Valid(scalar.base_point_mul()),
            Zero => MaybePoint::Infinity,
        }
    }

    /// Negates the scalar in constant-time if the given parity bit is a 1.
    pub fn negate_if(self, parity: subtle::Choice) -> MaybeScalar {
        MaybeScalar::conditional_select(&self, &(-self), parity)
    }
}

impl Default for MaybeScalar {
    /// Returns [`MaybeScalar::Zero`].
    fn default() -> Self {
        MaybeScalar::Zero
    }
}

#[cfg(feature = "secp256k1")]
mod as_ref_conversions {
    use super::*;

    impl AsRef<[u8; 32]> for Scalar {
        /// Returns a reference to the underlying secret bytes of this scalar.
        ///
        /// # Warning
        ///
        /// Use cautiously. Non-constant time operations on these bytes
        /// could reveal secret key material.
        fn as_ref(&self) -> &[u8; 32] {
            return self.inner.as_ref();
        }
    }

    impl AsRef<[u8; 32]> for MaybeScalar {
        /// Returns a reference to the underlying secret bytes of this scalar.
        ///
        /// # Warning
        ///
        /// Use cautiously. Non-constant time operations on these bytes
        /// could reveal secret key material.
        fn as_ref(&self) -> &[u8; 32] {
            const EMPTY: [u8; 32] = [0; 32];
            match self {
                Valid(ref scalar) => scalar.as_ref(),
                Zero => &EMPTY,
            }
        }
    }

    impl AsRef<[u8]> for Scalar {
        /// Returns a reference to the underlying secret bytes of this scalar.
        ///
        /// # Warning
        ///
        /// Use cautiously. Non-constant time operations on these bytes
        /// could reveal secret key material.
        fn as_ref(&self) -> &[u8] {
            <Self as AsRef<[u8; 32]>>::as_ref(self) as &[u8]
        }
    }

    impl AsRef<[u8]> for MaybeScalar {
        /// Returns a reference to the underlying secret bytes of this scalar.
        ///
        /// # Warning
        ///
        /// Use cautiously. Non-constant time operations on these bytes
        /// could reveal secret key material.
        fn as_ref(&self) -> &[u8] {
            <Self as AsRef<[u8; 32]>>::as_ref(self) as &[u8]
        }
    }
}

mod conversions {
    use super::*;

    impl From<MaybeScalar> for Option<Scalar> {
        /// Converts [`MaybeScalar::Zero`] into `None` and a valid [`Scalar`] into `Some`.
        fn from(maybe_scalar: MaybeScalar) -> Self {
            match maybe_scalar {
                Valid(scalar) => Some(scalar),
                Zero => None,
            }
        }
    }

    impl TryFrom<MaybeScalar> for Scalar {
        type Error = ZeroScalarError;

        /// Converts the `MaybeScalar` into a `Result<Scalar, ZeroScalarError>`,
        /// returning `Ok(Scalar)` if the scalar is a valid non-zero number,
        /// or `Err(ZeroScalarError)` if `maybe_scalar == MaybeScalar::Zero`.
        fn try_from(maybe_scalar: MaybeScalar) -> Result<Self, Self::Error> {
            match maybe_scalar {
                Valid(scalar) => Ok(scalar),
                Zero => Err(ZeroScalarError),
            }
        }
    }

    impl From<Scalar> for MaybeScalar {
        /// Converts the scalar into [`MaybeScalar::Valid`] instance.
        fn from(scalar: Scalar) -> Self {
            MaybeScalar::Valid(scalar)
        }
    }

    #[cfg(feature = "secp256k1")]
    impl From<secp256k1::SecretKey> for Scalar {
        fn from(inner: secp256k1::SecretKey) -> Self {
            Scalar { inner }
        }
    }

    #[cfg(feature = "secp256k1")]
    impl From<secp256k1::SecretKey> for MaybeScalar {
        fn from(sk: secp256k1::SecretKey) -> Self {
            MaybeScalar::Valid(Scalar::from(sk))
        }
    }

    #[cfg(feature = "k256")]
    impl From<k256::NonZeroScalar> for Scalar {
        fn from(nz_scalar: k256::NonZeroScalar) -> Self {
            #[cfg(feature = "secp256k1")]
            return Scalar::try_from(<[u8; 32]>::from(nz_scalar.to_bytes())).unwrap();

            #[cfg(not(feature = "secp256k1"))]
            return Scalar { inner: nz_scalar };
        }
    }

    #[cfg(feature = "k256")]
    impl From<k256::NonZeroScalar> for MaybeScalar {
        fn from(nz_scalar: k256::NonZeroScalar) -> Self {
            MaybeScalar::Valid(Scalar::from(nz_scalar))
        }
    }

    #[cfg(feature = "k256")]
    impl From<k256::SecretKey> for Scalar {
        fn from(seckey: k256::SecretKey) -> Self {
            #[cfg(feature = "secp256k1")]
            return Scalar::try_from(<[u8; 32]>::from(seckey.to_bytes())).unwrap();

            #[cfg(not(feature = "secp256k1"))]
            return Scalar {
                inner: k256::NonZeroScalar::from(seckey),
            };
        }
    }
}

pub(crate) const SCALAR_ZERO_STR: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

mod encodings {
    use super::*;

    impl std::fmt::LowerHex for Scalar {
        /// Formats the scalar as a hex string in lower case.
        ///
        /// # Warning
        ///
        /// This method may expose private data if the scalar represents a secret key.
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            let mut buffer = [0; 64];
            let encoded = base16ct::lower::encode_str(&self.serialize(), &mut buffer).unwrap();
            f.write_str(encoded)
        }
    }

    impl std::fmt::LowerHex for MaybeScalar {
        /// Formats the scalar as a hex string in lower case.
        ///
        /// # Warning
        ///
        /// This method may expose private data if the scalar represents a secret key.
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                Valid(scalar) => scalar.fmt(f),
                Zero => f.write_str(SCALAR_ZERO_STR),
            }
        }
    }

    #[cfg(feature = "scalar-display")]
    impl std::fmt::Display for Scalar {
        /// Formats a scalar into a 32-byte hex string representation.
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "{:x}", self)
        }
    }

    #[cfg(feature = "scalar-display")]
    impl std::fmt::Display for MaybeScalar {
        /// Formats a scalar into a 32-byte hex string representation.
        /// Prints 64 zero characters if `self == MaybeScalar::Zero`.
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                Valid(ref scalar) => write!(f, "{:x}", scalar),
                Zero => f.write_str(SCALAR_ZERO_STR),
            }
        }
    }

    impl std::str::FromStr for Scalar {
        type Err = InvalidScalarString;

        /// Parses a `Scalar` from a 32-byte hex string representation.
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let inner = s.parse().map_err(|_| InvalidScalarString)?;
            Ok(Scalar { inner })
        }
    }

    impl std::str::FromStr for MaybeScalar {
        type Err = InvalidScalarString;

        /// Parses a scalar from a 32-byte hex string representation.
        ///
        /// If the string is a hex-encoded 32 byte array of zeros, this
        /// will return [`MaybeScalar::Zero`].
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            // Make sure this comparison is executed in constant time to avoid
            // leaking information about secret scalars during deserialization.
            if bool::from(s.as_bytes().ct_eq(SCALAR_ZERO_STR.as_bytes())) {
                return Ok(MaybeScalar::Zero);
            }

            let scalar = Scalar::from_str(s)?;
            Ok(Valid(scalar))
        }
    }

    impl TryFrom<&[u8]> for Scalar {
        type Error = InvalidScalarBytes;
        /// Attempts to parse a 32-byte slice as a scalar in the range `[1, n)`
        /// in constant time, where `n` is the curve order.
        ///
        /// Returns [`InvalidScalarBytes`] if the integer represented by the bytes
        /// is greater than or equal to the curve order, or if the bytes are all zero.
        ///
        /// Fails if `bytes.len() != 32`.
        fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
            #[cfg(feature = "secp256k1")]
            let inner = secp256k1::SecretKey::from_slice(bytes).map_err(|_| InvalidScalarBytes)?;

            #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
            let inner = k256::NonZeroScalar::try_from(bytes).map_err(|_| InvalidScalarBytes)?;

            Ok(Scalar::from(inner))
        }
    }

    impl TryFrom<&[u8]> for MaybeScalar {
        type Error = InvalidScalarBytes;

        /// Attempts to parse a 32-byte slice as a scalar in the range `[0, n)`
        /// in constant time, where `n` is the curve order. Timing information
        /// may be leaked if `bytes` is all zeros or not the right length.
        ///
        /// Returns [`InvalidScalarBytes`] if the integer represented by the bytes
        /// is greater than or equal to the curve order, or if `bytes.len() != 32`.
        fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
            Scalar::try_from(bytes).map(Valid).or_else(|e| {
                if bool::from(bytes.ct_eq(&[0; 32])) {
                    Ok(MaybeScalar::Zero)
                } else {
                    Err(e)
                }
            })
        }
    }

    impl TryFrom<&[u8; 32]> for MaybeScalar {
        type Error = InvalidScalarBytes;

        /// Attempts to parse a 32-byte array as a scalar in the range `[0, n)`
        /// in constant time, where `n` is the curve order. Timing information
        /// may be leaked if `bytes` is the zero array, but then that's not a
        /// very secret value, is it?
        ///
        /// Returns [`InvalidScalarBytes`] if the integer represented by the bytes
        /// is greater than or equal to the curve order.
        fn try_from(bytes: &[u8; 32]) -> Result<Self, Self::Error> {
            Self::try_from(bytes as &[u8])
        }
    }

    impl TryFrom<&[u8; 32]> for Scalar {
        type Error = InvalidScalarBytes;

        /// Attempts to parse a 32-byte array as a scalar in the range `[1, n)`
        /// in constant time, where `n` is the curve order.
        ///
        /// Returns [`InvalidScalarBytes`] if the integer represented by the bytes
        /// is greater than or equal to the curve order, or if the bytes are all zero.
        fn try_from(bytes: &[u8; 32]) -> Result<Self, Self::Error> {
            Self::try_from(bytes as &[u8])
        }
    }

    impl TryFrom<[u8; 32]> for MaybeScalar {
        type Error = InvalidScalarBytes;

        /// Attempts to parse a 32-byte array as a scalar in the range `[0, n)`
        /// in constant time, where `n` is the curve order.
        ///
        /// Returns [`InvalidScalarBytes`] if the integer represented by the bytes
        /// is greater than or equal to the curve order.
        fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
            Self::try_from(&bytes)
        }
    }

    impl TryFrom<[u8; 32]> for Scalar {
        type Error = InvalidScalarBytes;

        /// Attempts to parse a 32-byte array as a scalar in the range `[1, n)`
        /// in constant time, where `n` is the curve order.
        ///
        /// Returns [`InvalidScalarBytes`] if the integer represented by the bytes
        /// is greater than or equal to the curve order, or if the bytes are all zero.
        fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
            Self::try_from(&bytes)
        }
    }

    impl From<Scalar> for [u8; 32] {
        /// Serializes the scalar to a big-endian byte array representation.
        fn from(scalar: Scalar) -> Self {
            scalar.serialize()
        }
    }

    impl From<MaybeScalar> for [u8; 32] {
        /// Serializes the scalar to a big-endian byte array representation.
        fn from(maybe_scalar: MaybeScalar) -> Self {
            maybe_scalar.serialize()
        }
    }
}

mod subtle_traits {
    use super::*;

    impl ConditionallySelectable for Scalar {
        /// Conditionally selects one of two scalars in constant time. No timing
        /// information about the value of either scalar will be leaked.
        #[inline]
        fn conditional_select(&a: &Self, &b: &Self, choice: subtle::Choice) -> Self {
            #[cfg(feature = "secp256k1")]
            return {
                let mut output_bytes: [u8; 32] = a.serialize();
                output_bytes.conditional_assign(&b.serialize(), choice);
                Scalar::try_from(&output_bytes).unwrap()
            };

            #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
            return {
                let mut inner = a.inner;
                inner.conditional_assign(&b.inner, choice);
                Scalar::from(inner)
            };
        }
    }

    impl ConditionallySelectable for MaybeScalar {
        /// Conditionally selects one of two scalars in constant time. The exception is if
        /// either `a` or `b` are [`MaybeScalar::Zero`], in which case timing information
        /// about this fact may be leaked. No timing information about the value
        /// of a non-zero scalar will be leaked.
        fn conditional_select(&a: &Self, &b: &Self, choice: subtle::Choice) -> Self {
            #[cfg(feature = "secp256k1")]
            return {
                let mut output_bytes: [u8; 32] = a.serialize();
                output_bytes.conditional_assign(&b.serialize(), choice);
                MaybeScalar::try_from(&output_bytes).unwrap()
            };

            #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
            return {
                let a_inner = a
                    .into_option()
                    .map(|scalar| scalar.inner.as_ref().clone())
                    .unwrap_or(k256::Scalar::ZERO);
                let b_inner = b
                    .into_option()
                    .map(|scalar| scalar.inner.as_ref().clone())
                    .unwrap_or(k256::Scalar::ZERO);

                let inner_scalar = k256::Scalar::conditional_select(&a_inner, &b_inner, choice);

                Option::<k256::NonZeroScalar>::from(k256::NonZeroScalar::new(inner_scalar))
                    .map(MaybeScalar::from)
                    .unwrap_or(MaybeScalar::Zero)
            };
        }
    }

    impl ConstantTimeEq for Scalar {
        /// Compares this scalar against another in constant time.
        /// Returns `subtle::Choice::from(1)` if and only if the
        /// two scalars represent the same integer.
        #[inline]
        fn ct_eq(&self, other: &Self) -> subtle::Choice {
            self.serialize().ct_eq(&other.serialize())
        }
    }

    impl ConstantTimeEq for MaybeScalar {
        /// Compares this scalar against another in constant time.
        /// Returns `subtle::Choice::from(1)` if and only if the
        /// two scalars represent the same integer.
        #[inline]
        fn ct_eq(&self, other: &Self) -> subtle::Choice {
            self.serialize().ct_eq(&other.serialize())
        }
    }

    impl ConstantTimeGreater for Scalar {
        /// Compares this scalar against another in constant time.
        /// Returns `subtle::Choice::from(1)` if `self` is strictly
        /// lexicographically greater than `other`.
        #[inline]
        fn ct_gt(&self, other: &Self) -> subtle::Choice {
            ct_slice_lex_cmp(&self.serialize(), &other.serialize())
                .ct_eq(&std::cmp::Ordering::Greater)
        }
    }

    impl ConstantTimeGreater for MaybeScalar {
        /// Compares this scalar against another in constant time.
        /// Returns `subtle::Choice::from(1)` if `self` is strictly
        /// lexicographically greater than `other`.
        #[inline]
        fn ct_gt(&self, other: &Self) -> subtle::Choice {
            ct_slice_lex_cmp(&self.serialize(), &other.serialize())
                .ct_eq(&std::cmp::Ordering::Greater)
        }
    }

    impl subtle::ConstantTimeLess for Scalar {}
    impl subtle::ConstantTimeLess for MaybeScalar {}
}

/// This implementation allows iterators of [`Scalar`] or [`MaybeScalar`]
/// to be summed with [`Iterator::sum`].
///
/// Here the type `S` may be either [`Scalar`] or [`MaybeScalar`], or
/// any other type which can be summed with a [`MaybeScalar`].
///
/// ```
/// use secp::{Scalar, MaybeScalar};
///
/// let scalars = [
///   Scalar::one(),
///   Scalar::one(),
///   Scalar::one(),
/// ];
/// let expected = "0000000000000000000000000000000000000000000000000000000000000003"
///     .parse::<MaybeScalar>()
///     .unwrap();
///
/// assert_eq!(scalars.into_iter().sum::<MaybeScalar>(), expected);
/// assert_eq!(
///     scalars
///         .into_iter()
///         .map(MaybeScalar::Valid)
///         .sum::<MaybeScalar>(),
///     expected
/// );
/// ```
impl<S> std::iter::Sum<S> for MaybeScalar
where
    MaybeScalar: std::ops::Add<S, Output = MaybeScalar>,
{
    fn sum<I: Iterator<Item = S>>(iter: I) -> Self {
        let mut sum = MaybeScalar::Zero;
        for scalar in iter {
            sum = sum + scalar;
        }
        sum
    }
}

/// This implementation allows iterators of [`Scalar`]
/// to be multiplied together with [`Iterator::product`].
///
/// Since all scalars in the iterator are guaranteed to
/// be non-zero, the resulting product is also guaranteed
/// to be non-zero.
///
/// ```
/// use secp::Scalar;
///
/// let scalars = [
///   Scalar::two(),
///   Scalar::two(),
///   Scalar::two(),
/// ];
/// let expected = "0000000000000000000000000000000000000000000000000000000000000008"
///     .parse::<Scalar>()
///     .unwrap();
///
/// assert_eq!(scalars.into_iter().product::<Scalar>(), expected);
/// ```
///
/// Returns `Scalar::one()` if the iterator is empty.
impl std::iter::Product<Scalar> for Scalar {
    fn product<I: Iterator<Item = Scalar>>(iter: I) -> Self {
        let mut product = Scalar::one();
        for scalar in iter {
            product = product * scalar;
        }
        product
    }
}

/// This implementation allows iterators of [`Scalar`] or [`MaybeScalar`]
/// to be multiplied together with [`Iterator::product`].
///
/// Here the type `S` may be either [`Scalar`] or [`MaybeScalar`], or
/// any other type which can be multiplied with a [`MaybeScalar`].
///
/// ```
/// use secp::{Scalar, MaybeScalar};
///
/// let scalars = [
///   Scalar::two(),
///   Scalar::two(),
///   Scalar::two(),
/// ];
/// let expected = "0000000000000000000000000000000000000000000000000000000000000008"
///     .parse::<MaybeScalar>()
///     .unwrap();
///
/// assert_eq!(scalars.into_iter().product::<MaybeScalar>(), expected);
/// assert_eq!(
///     scalars
///         .into_iter()
///         .map(MaybeScalar::Valid)
///         .product::<MaybeScalar>(),
///     expected
/// );
/// ```
///
/// Returns `MaybeScalar::one()` if the iterator is empty.
impl<S> std::iter::Product<S> for MaybeScalar
where
    MaybeScalar: std::ops::Mul<S, Output = MaybeScalar>,
{
    fn product<I: Iterator<Item = S>>(iter: I) -> Self {
        let mut product = MaybeScalar::one();
        for scalar in iter {
            product = product * scalar;
        }
        product
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl From<u128> for Scalar {
        fn from(value: u128) -> Self {
            assert!(value > 0);
            let mut arr = [0; 32];
            arr[16..].clone_from_slice(&value.to_be_bytes());

            #[cfg(feature = "secp256k1")]
            let inner = secp256k1::SecretKey::from_slice(&arr).unwrap();

            #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
            let inner = k256::NonZeroScalar::from_repr(arr.into()).unwrap();

            Scalar::from(inner)
        }
    }

    impl From<u128> for MaybeScalar {
        fn from(value: u128) -> Self {
            if value == 0 {
                return Zero;
            }
            Valid(Scalar::from(value))
        }
    }

    #[test]
    fn test_curve_order() {
        #[cfg(feature = "secp256k1")]
        assert_eq!(CURVE_ORDER_BYTES, secp256k1::constants::CURVE_ORDER);
    }

    #[test]
    fn test_scalar_parsing() {
        let valid_scalar_hex = [
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        ];

        for scalar_hex in valid_scalar_hex {
            let parsed = scalar_hex
                .parse::<Scalar>()
                .expect(&format!("failed to parse valid Scalar: {}", scalar_hex));
            let maybe_parsed = scalar_hex.parse::<MaybeScalar>().expect(&format!(
                "failed to parse valid MaybeScalar: {}",
                scalar_hex
            ));

            let bytes = <[u8; 32]>::try_from(hex::decode(scalar_hex).unwrap())
                .expect("failed to parse hex as 32-byte array");

            assert_eq!(
                Scalar::try_from(&bytes).expect("failed to parse 32-byte array as Scalar"),
                parsed
            );
            assert_eq!(
                MaybeScalar::try_from(&bytes)
                    .expect("failed to parse 32-byte array as MaybeScalar"),
                maybe_parsed
            );
        }

        // Invalid scalars
        let invalid_scalar_hex = [
            "nonsense",                                                           // not hex
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",   // curve order
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaax",   // non-hex char
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",  // too long
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabb", // too long
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",     // too short
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",    // too short
            "",                                                                   // too short
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ",  // spaces
        ];

        for scalar_hex in invalid_scalar_hex {
            scalar_hex.parse::<Scalar>().expect_err(&format!(
                "should not have parsed invalid hex as Scalar: {}",
                scalar_hex
            ));
            scalar_hex.parse::<MaybeScalar>().expect_err(&format!(
                "should not have parsed invalid hex as MaybeScalar: {}",
                scalar_hex
            ));

            match hex::decode(scalar_hex) {
                Err(_) => {} // Ignore
                Ok(decoded) => match <[u8; 32]>::try_from(decoded) {
                    Err(_) => {} // Ignore
                    Ok(bytes) => {
                        Scalar::try_from(bytes).expect_err(&format!(
                            "should have failed to decode invalid byte array {}",
                            scalar_hex,
                        ));
                    }
                },
            };
        }

        "0000000000000000000000000000000000000000000000000000000000000000"
            .parse::<Scalar>()
            .expect_err("cannot parse zero as Scalar");

        assert_eq!(
            "0000000000000000000000000000000000000000000000000000000000000000"
                .parse::<MaybeScalar>()
                .expect("parses zero as MaybeScalar::Zero"),
            MaybeScalar::Zero,
        );
    }

    fn curve_order_plus(b: i8) -> [u8; 32] {
        let mut bytes = CURVE_ORDER_BYTES;

        let carry: bool;
        (bytes[31], carry) = bytes[31].overflowing_add_signed(b);

        if carry {
            if b >= 0 {
                bytes[30] += 1;
            } else {
                bytes[30] -= 1;
            }
        }
        bytes
    }

    #[test]
    fn test_scalar_from_bytes() {
        assert_eq!(
            Scalar::try_from([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 29,
            ])
            .unwrap(),
            Scalar::from(29),
        );
        assert_eq!(
            Scalar::try_from([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1,
            ])
            .unwrap(),
            Scalar::one(),
        );
        assert_eq!(
            MaybeScalar::try_from([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 29,
            ])
            .unwrap(),
            MaybeScalar::from(29),
        );
        assert_eq!(
            MaybeScalar::try_from([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1,
            ])
            .unwrap(),
            MaybeScalar::from(1),
        );

        assert_eq!(
            Scalar::try_from(curve_order_plus(-1)).unwrap(),
            Scalar::max()
        );
        assert_eq!(
            Scalar::try_from(curve_order_plus(-2)).unwrap(),
            (Scalar::max() - Scalar::one()).unwrap()
        );

        assert_eq!(
            MaybeScalar::try_from(curve_order_plus(-1)).unwrap(),
            MaybeScalar::max()
        );
        assert_eq!(
            MaybeScalar::try_from(curve_order_plus(-2)).unwrap(),
            MaybeScalar::max() - MaybeScalar::one()
        );

        assert_eq!(MaybeScalar::try_from(&[0; 32]).unwrap(), MaybeScalar::Zero);
        assert_eq!(Scalar::try_from(&[0; 32]).unwrap_err(), InvalidScalarBytes);

        assert_eq!(
            Scalar::try_from(curve_order_plus(1)).unwrap_err(),
            InvalidScalarBytes
        );
        assert_eq!(
            Scalar::try_from(curve_order_plus(2)).unwrap_err(),
            InvalidScalarBytes
        );
        assert_eq!(
            Scalar::try_from(CURVE_ORDER_BYTES).unwrap_err(),
            InvalidScalarBytes
        );

        assert_eq!(
            MaybeScalar::try_from(curve_order_plus(1)).unwrap_err(),
            InvalidScalarBytes
        );
        assert_eq!(
            MaybeScalar::try_from(curve_order_plus(2)).unwrap_err(),
            InvalidScalarBytes
        );
        assert_eq!(
            MaybeScalar::try_from(CURVE_ORDER_BYTES).unwrap_err(),
            InvalidScalarBytes
        );
    }

    #[test]
    fn test_scalar_addition() {
        // test scalar addition

        // Scalar + Scalar
        assert_eq!(Scalar::from(28) + Scalar::from(2), MaybeScalar::from(30));

        // MaybeScalar + Scalar
        assert_eq!(MaybeScalar::from(1) + Scalar::from(2), MaybeScalar::from(3));

        // Scalar + MaybeScalar
        assert_eq!(
            Scalar::from(88) + MaybeScalar::from(12),
            MaybeScalar::from(100)
        );

        // Scalar + MaybeScalar
        assert_eq!(
            MaybeScalar::from(88) + MaybeScalar::from(12),
            MaybeScalar::from(100)
        );

        // Zero + Scalar
        assert_eq!(MaybeScalar::Zero + Scalar::from(20), MaybeScalar::from(20));

        // Zero + MaybeScalar
        assert_eq!(
            MaybeScalar::Zero + MaybeScalar::from(20),
            MaybeScalar::from(20)
        );

        // Scalar + Zero
        assert_eq!(Scalar::from(20) + MaybeScalar::Zero, MaybeScalar::from(20));

        // MaybeScalar + Zero
        assert_eq!(
            MaybeScalar::from(20) + MaybeScalar::Zero,
            MaybeScalar::from(20)
        );

        // MaybeScalar + MaybeScalar
        assert_eq!(
            MaybeScalar::from(4) + MaybeScalar::from(20),
            MaybeScalar::from(24)
        );

        // Test overflow
        assert_eq!(
            Scalar::try_from(curve_order_plus(-1)).unwrap() + MaybeScalar::Zero,
            MaybeScalar::max()
        );
        assert_eq!(
            Scalar::try_from(curve_order_plus(-1)).unwrap() + Scalar::from(1),
            MaybeScalar::Zero
        );
        assert_eq!(
            Scalar::try_from(curve_order_plus(-1)).unwrap() + Scalar::from(2),
            MaybeScalar::one()
        );
        assert_eq!(
            Scalar::try_from(curve_order_plus(-1)).unwrap() + Scalar::from(3),
            MaybeScalar::two()
        );
    }

    #[test]
    fn test_scalar_negation() {
        assert_eq!(
            -Scalar::from(1),
            Scalar::try_from(curve_order_plus(-1)).unwrap(),
        );
        assert_eq!(
            -Scalar::from(2),
            Scalar::try_from(curve_order_plus(-2)).unwrap(),
        );
        assert_eq!(
            -Scalar::try_from(curve_order_plus(-1)).unwrap(),
            Scalar::from(1),
        );
        assert_eq!(
            -Scalar::try_from(curve_order_plus(-2)).unwrap(),
            Scalar::from(2),
        );

        assert_eq!(
            -MaybeScalar::try_from(curve_order_plus(-1)).unwrap(),
            MaybeScalar::from(1),
        );
        assert_eq!(
            -MaybeScalar::try_from(curve_order_plus(-2)).unwrap(),
            MaybeScalar::from(2),
        );

        assert_eq!(-MaybeScalar::Zero, MaybeScalar::Zero);
    }

    #[test]
    fn test_scalar_subtraction() {
        // Scalar - Scalar
        assert_eq!(Scalar::from(5) - Scalar::from(3), MaybeScalar::from(2));
        assert_eq!(
            Scalar::from(1) - Scalar::from(5),
            MaybeScalar::try_from(curve_order_plus(-4)).unwrap(),
        );
        assert_eq!(Scalar::from(4) - Scalar::from(4), MaybeScalar::Zero);

        // Scalar - MaybeScalar
        assert_eq!(
            Scalar::from(10) - MaybeScalar::from(3),
            MaybeScalar::from(7),
        );
        assert_eq!(
            Scalar::from(3) - MaybeScalar::from(8),
            MaybeScalar::try_from(curve_order_plus(-5)).unwrap(),
        );
        assert_eq!(Scalar::from(9) - MaybeScalar::from(9), MaybeScalar::Zero);

        // MaybeScalar - Scalar
        assert_eq!(
            MaybeScalar::from(13) - Scalar::from(2),
            MaybeScalar::from(11),
        );
        assert_eq!(
            MaybeScalar::from(4) - Scalar::from(9),
            MaybeScalar::try_from(curve_order_plus(-5)).unwrap(),
        );
        assert_eq!(
            MaybeScalar::Zero - Scalar::from(5),
            MaybeScalar::try_from(curve_order_plus(-5)).unwrap(),
        );

        // MaybeScalar - MaybeScalar
        assert_eq!(
            MaybeScalar::from(13) - MaybeScalar::from(2),
            MaybeScalar::from(11),
        );
        assert_eq!(
            MaybeScalar::from(4) - MaybeScalar::from(9),
            MaybeScalar::try_from(curve_order_plus(-5)).unwrap(),
        );
        assert_eq!(
            MaybeScalar::Zero - MaybeScalar::from(5),
            MaybeScalar::try_from(curve_order_plus(-5)).unwrap(),
        );
    }

    #[test]
    fn test_scalar_multiplication() {
        // Scalar * Scalar
        assert_eq!(Scalar::from(28) * Scalar::from(3), Scalar::from(84));

        // Scalar * ONE
        assert_eq!(Scalar::from(45) * Scalar::one(), Scalar::from(45));

        // Scalar * MaybeScalar
        assert_eq!(Scalar::from(45) * MaybeScalar::Zero, MaybeScalar::Zero);

        // MaybeScalar * Scalar
        assert_eq!(
            MaybeScalar::from(3) * Scalar::from(25),
            MaybeScalar::from(75)
        );

        // Zero * Scalar
        assert_eq!(MaybeScalar::Zero * Scalar::from(45), MaybeScalar::Zero);

        // Zero * MaybeScalar
        assert_eq!(MaybeScalar::Zero * MaybeScalar::from(45), MaybeScalar::Zero);

        // Scalar * Zero
        assert_eq!(Scalar::from(30) * MaybeScalar::Zero, MaybeScalar::Zero);

        // MaybeScalar * Zero
        assert_eq!(MaybeScalar::from(30) * MaybeScalar::Zero, MaybeScalar::Zero);

        // MaybeScalar * MaybeScalar
        assert_eq!(
            MaybeScalar::from(3) * MaybeScalar::from(3),
            MaybeScalar::from(9)
        );
    }

    #[test]
    #[cfg(any(feature = "k256", feature = "secp256k1-invert"))]
    fn test_scalar_division() {
        // Scalar / Scalar
        assert_eq!(Scalar::from(9) / Scalar::from(3), Scalar::from(3));
        assert_eq!(Scalar::one() / Scalar::one(), Scalar::one());
        assert_eq!(Scalar::from(2) / Scalar::one(), Scalar::from(2));
        assert_eq!(Scalar::one() / Scalar::max(), Scalar::max());

        // t * t^-1 = 1
        assert_eq!(
            Scalar::from(3514) * (Scalar::one() / Scalar::from(3514)),
            Scalar::one()
        );

        // MaybeScalar / Scalar
        assert_eq!(
            MaybeScalar::from(10) / Scalar::from(2),
            MaybeScalar::from(5)
        );
        assert_eq!(MaybeScalar::Zero / Scalar::from(3), MaybeScalar::Zero);
    }

    #[test]
    fn test_scalar_assign_ops() {
        // (20 + 2 + 1) * 3 - 5 = 64
        let mut scalar = MaybeScalar::Valid(Scalar::from(20));
        scalar += Scalar::two();
        scalar += Scalar::one();
        scalar *= Scalar::from(3);
        scalar -= Scalar::from(5);
        assert_eq!(scalar, MaybeScalar::Valid(Scalar::from(64)));

        // (20 + 2 + 1) * 3 - 5 = 64
        let mut scalar = MaybeScalar::Valid(Scalar::from(20));
        scalar += MaybeScalar::two();
        scalar += MaybeScalar::one();
        scalar *= MaybeScalar::Valid(Scalar::from(3));
        scalar -= MaybeScalar::Valid(Scalar::from(5));
        assert_eq!(scalar, MaybeScalar::Valid(Scalar::from(64)));

        // 20 * 5 = 100
        let mut scalar = Scalar::from(20);
        scalar *= Scalar::from(5);
        assert_eq!(scalar, Scalar::from(100));

        #[cfg(any(feature = "k256", feature = "secp256k1-invert"))]
        {
            // 100 / 5 = 20
            scalar /= Scalar::from(5);
            assert_eq!(scalar, Scalar::from(20));
        }
    }

    #[test]
    fn test_scalar_reduction() {
        let reduction_tests = vec![
            (
                CURVE_ORDER_BYTES,
                [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
            ),
            (
                curve_order_plus(0),
                [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
            ),
            (
                curve_order_plus(1),
                [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                ],
            ),
            (
                curve_order_plus(-1),
                [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2,
                    0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40,
                ],
            ),
            (
                curve_order_plus(5),
                [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
                ],
            ),
            (
                curve_order_plus(-5),
                [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2,
                    0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x3c,
                ],
            ),
            (
                [
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                ],
                xor_arrays(&CURVE_ORDER_BYTES, &MAX_U256),
            ),
            (
                [
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                ],
                [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01, 0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4, 0x40, 0x2d,
                    0xa1, 0x73, 0x2f, 0xc9, 0xbe, 0xbd,
                ],
            ),
            (
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 54,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 54,
                ],
            ),
        ];

        for (input, expected) in reduction_tests {
            assert_eq!(
                &MaybeScalar::reduce_from(&input).serialize(),
                &expected,
                "{} mod n != {}",
                hex::encode(input),
                hex::encode(expected),
            );

            #[cfg(feature = "k256")]
            {
                use crypto_bigint::U256;
                use k256::elliptic_curve::ops::{Reduce, ReduceNonZero};

                let input_field_bytes = k256::FieldBytes::from(input);
                let expected =
                    <[u8; 32]>::from(k256::FieldBytes::from(
                        <k256::Scalar as Reduce<U256>>::reduce_bytes(&input_field_bytes),
                    ));
                let nonzero_expected = <[u8; 32]>::from(k256::FieldBytes::from(
                    <k256::NonZeroScalar as ReduceNonZero<U256>>::reduce_nonzero_bytes(
                        &input_field_bytes,
                    ),
                ));

                assert_eq!(MaybeScalar::reduce_from(&input).serialize(), expected);

                assert_eq!(Scalar::reduce_from(&input).serialize(), nonzero_expected);
            }
        }
    }

    #[test]
    fn test_scalar_ordering() {
        let mut scalars: [Scalar; 20] = [
            "44477400e59c41025e4e18c4de244b90b14554dcdcbfa396ead4659aa6343249"
                .parse()
                .unwrap(),
            "bee6529c72b7655e47cc1ffaf6f9ceeecce7fee2e99d093aa658ce6ec5d03a6a"
                .parse()
                .unwrap(),
            "33c17c36c25f156828d4f15f8a4131570625342e76b3e5f60a69baac6f4ca7d3"
                .parse()
                .unwrap(),
            "6ae373f53d30121ccce571aa2ff8413d5643938005e1b36f4cb8dd94e93db3cd"
                .parse()
                .unwrap(),
            "d2647f5821eeaad342e4008edd7fa5086ebcb73bde386dac06fec437050cf771"
                .parse()
                .unwrap(),
            "6f2781b0e3f11d4911486d1e8ce405c84eeb05f4cf62b14d6d258cc265ffec0a"
                .parse()
                .unwrap(),
            "1aeeb3548154f5ee09116c8a61af0b8543157e7a75949c71d1dab788852e0b22"
                .parse()
                .unwrap(),
            "0a557df2fee78ed14cc78870511cf35e6a73459bb1a2273edeb14e4c1290932d"
                .parse()
                .unwrap(),
            "ea55f89ba4debf7a6815fb977919f417782928b7ec4f69d645a1ef57bafbe732"
                .parse()
                .unwrap(),
            "e23265f6a6e97e9c4d2af4ecea844eb83eeb81cb4c6f86d34c3a5074396009bd"
                .parse()
                .unwrap(),
            "88a23adeff10f0a90cc8a598cfe4c6339c9afc03042ea9d7dfac6f031ef4e497"
                .parse()
                .unwrap(),
            "01238f0b0f9b11e5edaed8c1fcc47d4c879bc27aa735572fdd92db8f3119676b"
                .parse()
                .unwrap(),
            "f505ef52fbf0ecb0c4103728241f711ad27dad8cdb1ce29de769cfd3da5fecd9"
                .parse()
                .unwrap(),
            "8dbea02c7e0ae34fe9040ac3bb97678c4e77e5f8820520a5beaa8fe0d36922a7"
                .parse()
                .unwrap(),
            "ae94a02018ea6b54ec0c773c9f188cd6eb411bb3379331002239954f56443386"
                .parse()
                .unwrap(),
            "8e96840200c19bcc3d4342ca7bdbab9f96a0fb5dcc88eb0278d073ed7f4891d5"
                .parse()
                .unwrap(),
            "dad344a73abfe216af680186ca908e89b9ad54d7115a449c5c393e45632f2d76"
                .parse()
                .unwrap(),
            "851faf8fbe7d6054d051ac88d94048428d35c9f2918f09e4db452e926a6420be"
                .parse()
                .unwrap(),
            "c20bfccc406545448ec501cd909b655062fe8ac087c21817a8dd2d4574cab657"
                .parse()
                .unwrap(),
            "416c0e50cab9251e5a0f63f9be7b93ab4f8162a4d0598c7f9f79b9ab4b0ece02"
                .parse()
                .unwrap(),
        ];

        let mut expected_sorting = scalars.clone();
        expected_sorting.sort_by(|a, b| a.serialize().cmp(&b.serialize()));

        scalars.sort_by(|a, b| {
            if bool::from(a.ct_gt(b)) {
                std::cmp::Ordering::Greater
            } else if bool::from(a.ct_eq(b)) {
                std::cmp::Ordering::Equal
            } else {
                std::cmp::Ordering::Less
            }
        });

        assert_eq!(scalars, expected_sorting);
    }
}
