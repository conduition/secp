use once_cell::sync::Lazy;
use subtle::ConditionallySelectable;

use super::errors::{InfinityPointError, InvalidPointBytes, InvalidPointString};

#[cfg(feature = "secp256k1")]
use super::{MaybeScalar, Scalar};

use subtle::ConstantTimeEq as _;

#[cfg(all(feature = "k256", not(feature = "secp256k1")))]
use k256::elliptic_curve::point::{AffineCoordinates as _, DecompactPoint as _};

#[cfg(feature = "k256")]
use k256::elliptic_curve::sec1::ToEncodedPoint as _;

const GENERATOR_POINT_BYTES: [u8; 65] = [
    0x04, // The DER encoding tag
    //
    // The X coordinate of the generator.
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    //
    // The Y coordinate of the generator.
    0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
    0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
];

static GENERATOR_POINT: Lazy<Point> =
    Lazy::new(|| Point::try_from(&GENERATOR_POINT_BYTES).unwrap());

/// This struct type represents the secp256k1 generator point, and can be
/// used for scalar-point multiplication.
///
/// ```
/// use secp::{G, Scalar};
///
/// let privkey = Scalar::try_from([0xAB; 32]).unwrap();
/// assert_eq!(privkey * G, privkey.base_point_mul());
/// ```
///
/// `G` dereferences as [`Point`], allowing reuse of `Point` methods and traits.
///
/// ```
/// # use secp::G;
/// assert!(G.has_even_y());
/// assert_eq!(
///     G.serialize_uncompressed(),
///     [
///         0x04, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
///         0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
///         0x5b, 0x16, 0xf8, 0x17, 0x98, 0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d,
///         0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54,
///         0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
///     ]
/// );
/// ```
#[derive(Debug, Default)]
pub struct G;

impl std::ops::Deref for G {
    type Target = Point;
    fn deref(&self) -> &Self::Target {
        &GENERATOR_POINT
    }
}

/// Represents a valid non-infinity point on the secp256k1 curve.
/// Internally this wraps either [`secp256k1::PublicKey`] or [`k256::PublicKey`]
/// depending on which feature set is enabled.
///
/// `Point` supports constant time arithmetic operations using addition,
/// subtraction, negation, and multiplication with other types in this crate.
///
/// Curve arithmetic is performed using traits from [`std::ops`].
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "secp256k1", derive(Ord, PartialOrd))]
pub struct Point {
    #[cfg(feature = "secp256k1")]
    pub(crate) inner: secp256k1::PublicKey,

    #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
    pub(crate) inner: k256::PublicKey,
}

impl Point {
    /// Returns the secp256k1 generator base point `G`.
    pub fn generator() -> Point {
        *GENERATOR_POINT
    }

    /// Serializes the point into compressed DER encoding. This consists of a parity
    /// byte at the beginning, which is either `0x02` (even parity) or `0x03` (odd parity),
    /// followed by the big-endian encoding of the point's X-coordinate.
    pub fn serialize(&self) -> [u8; 33] {
        #[cfg(feature = "secp256k1")]
        return self.inner.serialize();

        #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
        return {
            let encoded_point = self.inner.to_encoded_point(true);
            <[u8; 33]>::try_from(encoded_point.as_bytes()).unwrap()
        };
    }

    /// Serializes the point into uncompressed DER encoding. This consists of a static tag
    /// byte `0x04`, followed by the point's  X-coordinate and Y-coordinate encoded sequentially
    /// (X then Y) as big-endian integers.
    pub fn serialize_uncompressed(&self) -> [u8; 65] {
        #[cfg(feature = "secp256k1")]
        return self.inner.serialize_uncompressed();

        #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
        return {
            let encoded_point = self.inner.to_encoded_point(false);
            <[u8; 65]>::try_from(encoded_point.as_bytes()).unwrap()
        };
    }

    /// Serializes the point into BIP340 X-only representation. This consists solely of the
    /// big-endian encoding of the point's X-coordinate.
    pub fn serialize_xonly(&self) -> [u8; 32] {
        #[cfg(feature = "secp256k1")]
        return self.inner.x_only_public_key().0.serialize();

        #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
        return <[u8; 32]>::from(self.inner.as_affine().x());
    }

    /// Parses a non-infinity point from a given byte slice, which can be either 33 or 65
    /// bytes long, depending on whether it represents a compressed or uncompressed point.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, InvalidPointBytes> {
        Self::try_from(bytes)
    }

    /// Parses a non-infinity point from a given hex string, which can be
    /// in compressed or uncompressed format.
    pub fn from_hex(hex: &str) -> Result<Self, InvalidPointString> {
        let mut bytes = [0; 65];
        let slice = base16ct::mixed::decode(hex, &mut bytes).map_err(|_| InvalidPointString)?;
        Point::try_from(slice).map_err(|_| InvalidPointString)
    }

    /// Returns `subtle::Choice::from(0)` if the point's Y-coordinate is even, or
    /// `subtle::Choice::from(1)` if the Y-coordinate is odd.
    pub fn parity(&self) -> subtle::Choice {
        #[cfg(feature = "secp256k1")]
        return self.inner.x_only_public_key().1.to_u8().into();

        #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
        return self.inner.as_affine().y_is_odd();
    }

    /// Returns `true` if the point's Y-coordinate is even, or `false` if the Y-coordinate is odd.
    pub fn has_even_y(&self) -> bool {
        bool::from(!self.parity())
    }

    /// Returns `true` if the point's Y-coordinate is odd, or `false` if the Y-coordinate is even.
    pub fn has_odd_y(&self) -> bool {
        bool::from(self.parity())
    }

    /// Returns a point with the same X-coordinate but with the Y-coordinate's parity set
    /// to the given parity, with `subtle::Choice::from(1)` indicating odd parity and
    /// `subtle::Choice::from(0)` indicating even parity.
    pub fn with_parity(self, parity: subtle::Choice) -> Self {
        #[cfg(feature = "secp256k1")]
        let inner = secp256k1::PublicKey::from_x_only_public_key(
            self.inner.x_only_public_key().0,
            secp256k1::Parity::from_u8(parity.unwrap_u8())
                .expect("subtle::Choice should only represent parity of either 0 or 1"),
        );

        #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
        let inner = {
            let mut affine = self.inner.as_affine().clone();
            let should_negate = affine.y_is_odd() ^ parity;
            affine.conditional_assign(&(-affine), should_negate);
            k256::PublicKey::from_affine(affine).unwrap()
        };

        Point::from(inner)
    }

    /// Returns a new point with the Y-coordinate coerced flipped to be even.
    pub fn to_even_y(self) -> Self {
        self.with_parity(subtle::Choice::from(0))
    }

    /// Returns a new point with the Y-coordinate coerced flipped to be odd.
    pub fn to_odd_y(self) -> Self {
        self.with_parity(subtle::Choice::from(1))
    }

    /// Parses a point with even parity from a BIP340 X-only public-key serialization representation.
    ///
    /// Every possible non-zero X-coordinate on the secp256k1 curve has exactly
    /// two corresponding Y-coordinates: one even, and one odd. This function computes
    /// the point for which the X-coordinate is represented by `x_bytes`, and the Y-coordinate
    /// is even.
    pub fn lift_x(x_bytes: &[u8; 32]) -> Result<Point, InvalidPointBytes> {
        #[cfg(feature = "secp256k1")]
        return secp256k1::XOnlyPublicKey::from_byte_array(x_bytes)
            .map(|xonly| Point::from((xonly, secp256k1::Parity::Even)))
            .map_err(|_| InvalidPointBytes);

        #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
        return {
            let point_opt = k256::AffinePoint::decompact(x_bytes.into())
                .and_then(k256::elliptic_curve::point::NonIdentity::new);

            Option::<k256::elliptic_curve::point::NonIdentity<_>>::from(point_opt)
                .map(k256::PublicKey::from)
                .map(Point::from)
                .ok_or(InvalidPointBytes)
        };
    }

    /// Parses a point from a BIP340 X-only public-key hex serialization.
    ///
    /// Every possible non-zero X-coordinate on the secp256k1 curve has exactly
    /// two corresponding Y-coordinates: one even, and one odd. This function computes
    /// the point for which the X-coordinate is represented by `x_bytes_hex`, and the
    /// Y-coordinate is even.
    pub fn lift_x_hex(x_bytes_hex: &str) -> Result<Point, InvalidPointString> {
        #[cfg(feature = "secp256k1")]
        return x_bytes_hex
            .parse::<secp256k1::XOnlyPublicKey>()
            .map(|xonly| Point::from((xonly, secp256k1::Parity::Even)))
            .map_err(|_| InvalidPointString);

        #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
        return {
            let mut x_bytes = [0; 32];
            base16ct::mixed::decode(x_bytes_hex, &mut x_bytes).map_err(|_| InvalidPointString)?;
            Point::lift_x(&x_bytes).map_err(|_| InvalidPointString)
        };
    }

    /// Aggregate an iterator of points together by simple summation.
    /// The iterator item type `T` can be any type that borrows as a
    /// `Point`, including `Point` itself, or `&Point`.
    ///
    /// `Point::sum(points)` should be preferred over summing up the `points`
    /// one at a time. This function offloads most of the work to `libsecp256k1`,
    /// reducing overhead if the `secp256k1` crate feature is enabled.
    pub fn sum<T>(points: impl IntoIterator<Item = T>) -> MaybePoint
    where
        T: std::borrow::Borrow<Point>,
    {
        #[cfg(feature = "secp256k1")]
        return {
            let points_vec: Vec<T> = points.into_iter().collect();

            let pubkeys_vec: Vec<&secp256k1::PublicKey> = points_vec
                .iter()
                .map(|point| &point.borrow().inner)
                .collect();

            secp256k1::PublicKey::combine_keys(&pubkeys_vec)
                .map(MaybePoint::from)
                .unwrap_or(MaybePoint::Infinity)
        };

        #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
        return {
            let affine = points
                .into_iter()
                .map(|p| p.borrow().inner.to_projective())
                .sum::<k256::ProjectivePoint>()
                .to_affine();

            k256::PublicKey::try_from(affine)
                .map(MaybePoint::from)
                .unwrap_or(MaybePoint::Infinity)
        };
    }

    /// Negates the point, returning the point `P` such that `self + P = MaybePoint::Infinity`.
    /// Always returns a non-infinity point.
    ///
    /// This method uses a specific `libsecp256k1` context object instead of the global
    /// context used by the `std::ops` implementations.
    #[cfg(feature = "secp256k1")]
    pub fn negate<C: secp256k1::Verification>(self, secp: &secp256k1::Secp256k1<C>) -> Point {
        Point::from(self.inner.negate(secp))
    }

    /// Subtracts two points, returning `self - other`. This computes the point `P` such
    /// that `self + P = other`. Returns `MaybePoint::Infinity` if `self == other`.
    ///
    /// This method uses a specific `libsecp256k1` context object instead of the global
    /// context used by the `std::ops` implementations.
    #[cfg(feature = "secp256k1")]
    pub fn sub<C: secp256k1::Verification>(
        self,
        secp: &secp256k1::Secp256k1<C>,
        other: Point,
    ) -> MaybePoint {
        self + other.negate(secp)
    }

    /// Subtracts two points, returning `self - other`. This computes the point `P` such
    /// that `self + P = other`. Returns [`MaybePoint::Infinity`] if `self == other`.
    /// Returns `self` if `other == MaybePoint::Infinity`.
    ///
    /// This method uses a specific `libsecp256k1` context object instead of the global
    /// context used by the `std::ops` implementations.
    #[cfg(feature = "secp256k1")]
    pub fn sub_maybe<C: secp256k1::Verification>(
        self,
        secp: &secp256k1::Secp256k1<C>,
        other: MaybePoint,
    ) -> MaybePoint {
        self + other.negate(secp)
    }

    /// Multiplies the point by the given scalar. Always returns a non-infinity point.
    ///
    /// This method uses a specific `libsecp256k1` context object instead of the global
    /// context used by the `std::ops` implementations.
    #[cfg(feature = "secp256k1")]
    pub fn mul<C: secp256k1::Verification>(
        self,
        secp: &secp256k1::Secp256k1<C>,
        scalar: Scalar,
    ) -> Point {
        Point::from(
            self.inner
                .mul_tweak(secp, &secp256k1::Scalar::from(scalar))
                .unwrap(), // point multiplication by a non-zero scalar never fails or hits infinity.
        )
    }

    /// Multiplies the point by the given scalar. Returns [`MaybePoint::Infinity`]
    /// if `scalar == MaybeScalar::Zero`.
    ///
    /// This method uses a specific `libsecp256k1` context object instead of the global
    /// context used by the `std::ops` implementations.
    #[cfg(feature = "secp256k1")]
    pub fn mul_maybe<C: secp256k1::Verification>(
        self,
        secp: &secp256k1::Secp256k1<C>,
        scalar: MaybeScalar,
    ) -> MaybePoint {
        match scalar.into_option() {
            Some(scalar) => Valid(self.mul(secp, scalar)),
            None => Infinity,
        }
    }

    /// Negates the point in constant-time if the given parity bit is a 1.
    pub fn negate_if(self, parity: subtle::Choice) -> Point {
        Point::conditional_select(&self, &(-self), parity)
    }
}

/// This type is effectively the same as [`Point`], except it can also
/// represent the point at infinity, exposed as [`MaybePoint::Infinity`].
/// This is the special 'zero-point', or 'identity element' on the curve
/// for which `MaybePoint::Infinity + X = X`  and
/// `MaybePoint::Infinity * X = MaybePoint::Infinity` for any other point `X`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MaybePoint {
    /// Represents the point at infinity, for which `MaybePoint::Infinity + X = X`
    /// and `MaybePoint::Infinity * X = MaybePoint::Infinity` for any other point `X`.
    Infinity,

    /// Represents a valid non-infinity curve point.
    Valid(Point),
}

use MaybePoint::*;

impl MaybePoint {
    /// Serializes the point into compressed DER encoding. This consists of a parity
    /// byte at the beginning, which is either `0x02` (even parity) or `0x03` (odd parity),
    /// followed by the big-endian encoding of the point's X-coordinate.
    ///
    /// If `self == MaybePoint::Infinity`, this returns 33 zero bytes.
    pub fn serialize(&self) -> [u8; 33] {
        match self {
            Valid(point) => point.serialize(),
            Infinity => [0; 33],
        }
    }

    /// Serializes the point into uncompressed DER encoding. This consists of a static tag
    /// byte `0x04`, followed by the point's  X-coordinate and Y-coordinate encoded sequentially
    /// (X then Y) as big-endian integers.
    ///
    /// If `self == MaybePoint::Infinity`, this returns 65 zero bytes.
    pub fn serialize_uncompressed(&self) -> [u8; 65] {
        match self {
            Valid(point) => point.serialize_uncompressed(),
            Infinity => [0; 65],
        }
    }

    /// Serializes the point into BIP340 X-only representation. This consists solely of the
    /// big-endian encoding of the point's X-coordinate.
    ///
    /// If `self == MaybePoint::Infinity`, this returns 32 zero bytes.
    pub fn serialize_xonly(&self) -> [u8; 32] {
        match self {
            Valid(point) => point.serialize_xonly(),
            Infinity => [0; 32],
        }
    }

    /// Parses a point from a given byte slice, which can be either 33 or 65 bytes
    /// long, depending on whether it represents a compressed or uncompressed point.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, InvalidPointBytes> {
        Self::try_from(bytes)
    }

    /// Parses a point from a given hex string, which can be in compressed
    /// or uncompressed format.
    ///
    /// Returns [`MaybePoint::Infinity`] if the input is 33-hex-encoded zero bytes.
    pub fn from_hex(hex: &str) -> Result<Self, InvalidPointString> {
        let is_compressed_inf = hex
            .as_bytes()
            .ct_eq(POINT_INFINITY_COMPRESSED_STR.as_bytes());
        let is_uncompressed_inf = hex
            .as_bytes()
            .ct_eq(POINT_INFINITY_UNCOMPRESSED_STR.as_bytes());

        if bool::from(is_compressed_inf | is_uncompressed_inf) {
            return Ok(MaybePoint::Infinity);
        }

        Ok(MaybePoint::Valid(Point::from_hex(hex)?))
    }

    /// Returns `subtle::Choice::from(0)` if the point's Y-coordinate is even or infinity.
    /// Returns `subtle::Choice::from(1)` if the Y-coordinate is odd.
    pub fn parity(&self) -> subtle::Choice {
        match self {
            Infinity => subtle::Choice::from(0),
            Valid(p) => p.parity(),
        }
    }

    /// Returns `true` if the point's Y-coordinate is even, or `false` if the Y-coordinate is odd.
    /// Also returns true if the point is [`Infinity`].
    pub fn has_even_y(&self) -> bool {
        bool::from(!self.parity())
    }

    /// Returns `true` if the point's Y-coordinate is odd, or `false` if the Y-coordinate is even.
    /// Returns false if the point is [`Infinity`].
    pub fn has_odd_y(&self) -> bool {
        bool::from(self.parity())
    }

    /// Returns a point with the same X-coordinate but with the Y-coordinate's parity set
    /// to the given parity, with `subtle::Choice::from(1)` indicating odd parity and
    /// `subtle::Choice::from(0)` indicating even parity.
    ///
    /// The [`Infinity`] point is returned unchanged.
    pub fn with_parity(self, parity: subtle::Choice) -> Self {
        match self {
            Infinity => self,
            Valid(p) => Valid(p.with_parity(parity)),
        }
    }

    /// Returns a new point with the Y-coordinate coerced flipped to be even.
    /// The [`Infinity`] point is returned unchanged.
    pub fn to_even_y(self) -> Self {
        self.with_parity(subtle::Choice::from(0))
    }

    /// Returns a new point with the Y-coordinate coerced flipped to be odd.
    /// The [`Infinity`] point is returned unchanged.
    pub fn to_odd_y(self) -> Self {
        self.with_parity(subtle::Choice::from(1))
    }

    /// Aggregate an iterator of points together by simple summation.
    /// The iterator item type `T` can be any type that borrows as a
    /// [`MaybePoint`], including `MaybePoint` itself, or `&MaybePoint`.
    ///
    /// `MaybePoint::sum(maybe_points)` should be preferred over summing up
    /// the `maybe_points` one at a time. This function offloads most of the
    /// work to libsecp256k1, reducing overhead if the `secp256k1` crate feature
    /// is enabled.
    ///
    /// This logic is also used in the implementation of `std::iter::Sum<S>`.
    pub fn sum<T>(maybe_points: impl IntoIterator<Item = T>) -> MaybePoint
    where
        T: std::borrow::Borrow<MaybePoint>,
    {
        let points_vec: Vec<Point> = maybe_points
            .into_iter()
            .filter_map(|maybe_point| maybe_point.borrow().into_option()) // filter out points at infinity
            .collect();
        Point::sum(points_vec)
    }

    /// Negates the point, returning the point `P` such that `self + P = MaybePoint::Infinity`
    /// Returns [`MaybePoint::Infinity`] if `self == MaybePoint::Infinity`.
    ///
    /// This method uses a specific `libsecp256k1` context object instead of the global
    /// context used by the `std::ops` implementations.
    #[cfg(feature = "secp256k1")]
    pub fn negate<C: secp256k1::Verification>(self, secp: &secp256k1::Secp256k1<C>) -> MaybePoint {
        match self {
            Valid(point) => Valid(point.negate(secp)),
            Infinity => Infinity,
        }
    }

    /// Subtracts two points, returning `self - other`. This computes the point `P` such
    /// that `self + P = other`. Returns [`MaybePoint::Infinity`] if `self == other`.
    /// Returns `-other` if `self == MaybePoint::Infinity`.
    ///
    /// This method uses a specific `libsecp256k1` context object instead of the global
    /// context used by the `std::ops` implementations.
    #[cfg(feature = "secp256k1")]
    pub fn sub<C: secp256k1::Verification>(
        self,
        secp: &secp256k1::Secp256k1<C>,
        other: Point,
    ) -> MaybePoint {
        self + other.negate(secp)
    }

    /// Subtracts two points, returning `self - other`. This computes the point `P` such
    /// that `self + P = other`. Returns [`MaybePoint::Infinity`] if `self == other`.
    /// Returns `self` if `other == MaybePoint::Infinity`.
    ///
    /// This method uses a specific `libsecp256k1` context object instead of the global
    /// context used by the `std::ops` implementations.
    #[cfg(feature = "secp256k1")]
    pub fn sub_maybe<C: secp256k1::Verification>(
        self,
        secp: &secp256k1::Secp256k1<C>,
        other: MaybePoint,
    ) -> MaybePoint {
        self + other.negate(secp)
    }

    /// Multiplies the point by the given scalar. Returns[ `MaybePoint::Infinity`]
    /// if `self == MaybePoint::Infinity`.
    ///
    /// This method uses a specific `libsecp256k1` context object instead of the global
    /// context used by the `std::ops` implementations.
    #[cfg(feature = "secp256k1")]
    pub fn mul<C: secp256k1::Verification>(
        self,
        secp: &secp256k1::Secp256k1<C>,
        scalar: Scalar,
    ) -> MaybePoint {
        match self {
            Valid(point) => Valid(point.mul(secp, scalar)),
            Infinity => Infinity,
        }
    }

    /// Multiplies the point by a scalar. Returns [`MaybePoint::Infinity`] if
    /// `self == MaybePoint::Infinity || scalar == MaybeScalar::Zero`.
    ///
    /// This method uses a specific `libsecp256k1` context object instead of the global
    /// context used by the `std::ops` implementations.
    #[cfg(feature = "secp256k1")]
    pub fn mul_maybe<C: secp256k1::Verification>(
        self,
        secp: &secp256k1::Secp256k1<C>,
        scalar: MaybeScalar,
    ) -> MaybePoint {
        match self {
            Valid(point) => point.mul_maybe(secp, scalar),
            Infinity => Infinity,
        }
    }

    /// Returns an option which is `None` if `self == MaybePoint::Infinity`,
    /// or a `Some(Point)` otherwise.
    pub fn into_option(self) -> Option<Point> {
        Option::from(self)
    }

    /// Returns `Ok(Point)` if the `MaybePoint` is a valid point or `Err(InfinityPointError)`
    /// if `self == MaybePoint::Infinity`.
    ///
    /// Also see `impl TryFrom<MaybePoint> for Point`.
    pub fn not_inf(self) -> Result<Point, InfinityPointError> {
        Point::try_from(self)
    }

    /// Coerces the `MaybePoint` into a valid [`Point`]. Panics if `self == MaybePoint::Infinity`.
    pub fn unwrap(self) -> Point {
        match self {
            Valid(point) => point,
            Infinity => panic!("called unwrap on MaybePoint::Infinity"),
        }
    }

    /// Returns true if `self == MaybePoint::Infinity`.
    pub fn is_infinity(&self) -> bool {
        self == &Infinity
    }

    /// Negates the point in constant-time if the given parity bit is a 1.
    pub fn negate_if(self, parity: subtle::Choice) -> MaybePoint {
        MaybePoint::conditional_select(&self, &(-self), parity)
    }
}

mod std_traits {
    use super::*;

    /// Need to implement this manually because [`k256::PublicKey`] does not implement `Hash`.
    impl std::hash::Hash for Point {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            self.serialize().hash(state);
        }
    }

    impl std::fmt::Debug for Point {
        /// Formats the point into a string like `"Point(025fa83ed...)"`.
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "Point({:x})", self)
        }
    }

    impl Default for MaybePoint {
        /// Returns the point at infinity, which acts as an
        /// identity element in the additive curve group.
        fn default() -> Self {
            MaybePoint::Infinity
        }
    }

    #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
    mod pubkey_ord {
        use super::*;

        impl Ord for Point {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                // The `k256` crate implements `Ord` based on uncompressed encoding.
                // To match BIP327, we must sort keys based on their compressed encoding.
                self.inner
                    .to_encoded_point(true)
                    .cmp(&other.inner.to_encoded_point(true))
            }
        }

        impl PartialOrd for Point {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }
    }
}

mod conversions {
    use super::*;

    mod as_ref_conversions {
        use super::*;

        #[cfg(feature = "secp256k1")]
        impl AsRef<secp256k1::PublicKey> for Point {
            fn as_ref(&self) -> &secp256k1::PublicKey {
                &self.inner
            }
        }

        #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
        impl AsRef<k256::PublicKey> for Point {
            fn as_ref(&self) -> &k256::PublicKey {
                &self.inner
            }
        }
    }

    mod internal_conversions {
        use super::*;

        impl From<MaybePoint> for Option<Point> {
            /// Converts the `MaybePoint` into an `Option`, returning `None` if
            /// `maybe_point == MaybePoint::Infinity` or `Some(p)` if
            /// `maybe_point == MaybePoint::Valid(p)`.
            fn from(maybe_point: MaybePoint) -> Self {
                match maybe_point {
                    Valid(point) => Some(point),
                    Infinity => None,
                }
            }
        }

        impl From<Point> for MaybePoint {
            /// Converts the point into a [`MaybePoint::Valid`] instance.
            fn from(point: Point) -> MaybePoint {
                MaybePoint::Valid(point)
            }
        }

        impl TryFrom<MaybePoint> for Point {
            type Error = InfinityPointError;

            /// Converts the `MaybePoint` into a `Result<Point, InfinityPointError>`,
            /// returning `Ok(Point)` if the point is a valid non-infinity point,
            /// or `Err(InfinityPointError)` if `maybe_point == MaybePoint::Infinity`.
            fn try_from(maybe_point: MaybePoint) -> Result<Self, Self::Error> {
                match maybe_point {
                    Valid(point) => Ok(point),
                    Infinity => Err(InfinityPointError),
                }
            }
        }
    }

    #[cfg(feature = "secp256k1")]
    mod secp256k1_conversions {
        use super::*;

        mod public_key {
            use super::*;

            impl From<secp256k1::PublicKey> for Point {
                fn from(pubkey: secp256k1::PublicKey) -> Self {
                    Point { inner: pubkey }
                }
            }

            impl From<secp256k1::PublicKey> for MaybePoint {
                fn from(pubkey: secp256k1::PublicKey) -> Self {
                    MaybePoint::Valid(Point::from(pubkey))
                }
            }

            impl From<Point> for secp256k1::PublicKey {
                fn from(point: Point) -> Self {
                    point.inner
                }
            }

            impl TryFrom<MaybePoint> for secp256k1::PublicKey {
                type Error = InfinityPointError;
                fn try_from(maybe_point: MaybePoint) -> Result<Self, Self::Error> {
                    Ok(maybe_point.not_inf()?.inner)
                }
            }
        }

        mod xonly_public_key {
            use super::*;

            type KeyAndParity = (secp256k1::XOnlyPublicKey, secp256k1::Parity);

            impl From<KeyAndParity> for Point {
                /// Converts an X-only public key with a given parity into a [`Point`].
                fn from((xonly, parity): KeyAndParity) -> Self {
                    let pk = secp256k1::PublicKey::from_x_only_public_key(xonly, parity);
                    Point::from(pk)
                }
            }

            impl From<KeyAndParity> for MaybePoint {
                fn from((xonly, parity): KeyAndParity) -> Self {
                    MaybePoint::Valid(Point::from((xonly, parity)))
                }
            }

            impl From<Point> for KeyAndParity {
                fn from(point: Point) -> Self {
                    point.inner.x_only_public_key()
                }
            }

            impl TryFrom<MaybePoint> for KeyAndParity {
                type Error = InfinityPointError;
                fn try_from(maybe_point: MaybePoint) -> Result<Self, Self::Error> {
                    Ok(KeyAndParity::from(maybe_point.not_inf()?))
                }
            }

            impl From<Point> for secp256k1::XOnlyPublicKey {
                fn from(point: Point) -> Self {
                    let (x, _) = point.inner.x_only_public_key();
                    x
                }
            }

            impl TryFrom<MaybePoint> for secp256k1::XOnlyPublicKey {
                type Error = InfinityPointError;
                fn try_from(maybe_point: MaybePoint) -> Result<Self, Self::Error> {
                    Ok(secp256k1::XOnlyPublicKey::from(maybe_point.not_inf()?))
                }
            }
        }
    }

    #[cfg(feature = "k256")]
    mod k256_conversions {
        use super::*;

        mod public_key {
            use super::*;

            impl From<k256::PublicKey> for Point {
                fn from(pubkey: k256::PublicKey) -> Self {
                    #[cfg(feature = "secp256k1")]
                    let inner = {
                        let encoded_point = pubkey.to_encoded_point(false);
                        secp256k1::PublicKey::from_slice(encoded_point.as_bytes()).unwrap()
                    };

                    #[cfg(not(feature = "secp256k1"))]
                    let inner = pubkey;

                    Point { inner }
                }
            }

            impl From<k256::PublicKey> for MaybePoint {
                fn from(pubkey: k256::PublicKey) -> Self {
                    MaybePoint::Valid(Point::from(pubkey))
                }
            }

            impl From<Point> for k256::PublicKey {
                fn from(point: Point) -> Self {
                    #[cfg(feature = "secp256k1")]
                    return k256::PublicKey::from_sec1_bytes(&point.serialize()).unwrap();

                    #[cfg(not(feature = "secp256k1"))]
                    return point.inner;
                }
            }

            impl TryFrom<MaybePoint> for k256::PublicKey {
                type Error = InfinityPointError;

                fn try_from(maybe_point: MaybePoint) -> Result<Self, Self::Error> {
                    Ok(k256::PublicKey::from(maybe_point.not_inf()?))
                }
            }
        }

        mod encoded_point {
            use super::*;

            impl TryFrom<k256::EncodedPoint> for Point {
                type Error = InvalidPointBytes;
                fn try_from(encoded_point: k256::EncodedPoint) -> Result<Self, Self::Error> {
                    Self::from_slice(encoded_point.as_bytes())
                }
            }

            impl TryFrom<k256::EncodedPoint> for MaybePoint {
                type Error = InvalidPointBytes;
                fn try_from(encoded_point: k256::EncodedPoint) -> Result<Self, Self::Error> {
                    Self::from_slice(encoded_point.as_bytes())
                }
            }

            impl From<Point> for k256::EncodedPoint {
                fn from(point: Point) -> Self {
                    k256::EncodedPoint::from(MaybePoint::Valid(point))
                }
            }

            impl From<MaybePoint> for k256::EncodedPoint {
                fn from(maybe_point: MaybePoint) -> Self {
                    let uncompressed = maybe_point.serialize_uncompressed();
                    k256::EncodedPoint::from_bytes(&uncompressed[1..]).unwrap()
                }
            }
        }

        mod affine_point {
            use super::*;

            impl TryFrom<k256::AffinePoint> for Point {
                type Error = InfinityPointError;
                fn try_from(affine_point: k256::AffinePoint) -> Result<Self, Self::Error> {
                    MaybePoint::from(affine_point).not_inf()
                }
            }

            impl From<k256::AffinePoint> for MaybePoint {
                fn from(affine_point: k256::AffinePoint) -> Self {
                    #[cfg(feature = "secp256k1")]
                    return MaybePoint::try_from(affine_point.to_encoded_point(false)).unwrap();

                    #[cfg(not(feature = "secp256k1"))]
                    return Point::try_from(affine_point)
                        .map(MaybePoint::Valid)
                        .unwrap_or(MaybePoint::Infinity);
                }
            }

            impl From<Point> for k256::AffinePoint {
                fn from(point: Point) -> Self {
                    return k256::AffinePoint::from(k256::PublicKey::from(point));
                }
            }

            impl From<MaybePoint> for k256::AffinePoint {
                fn from(point: MaybePoint) -> Self {
                    match point {
                        MaybePoint::Infinity => k256::AffinePoint::IDENTITY,
                        MaybePoint::Valid(point) => k256::AffinePoint::from(point),
                    }
                }
            }
        }
    }
}

const POINT_INFINITY_COMPRESSED_STR: &str =
    "000000000000000000000000000000000000000000000000000000000000000000";
const POINT_INFINITY_UNCOMPRESSED_STR: &str =
    "000000000000000000000000000000000000000000000000000000000000000000\
     0000000000000000000000000000000000000000000000000000000000000000";

mod encodings {
    use super::*;

    impl std::fmt::LowerHex for Point {
        /// Formats the Point as a DER-compressed hex string in lower case.
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            if f.sign_plus() {
                let mut buffer = [0; 130];
                let encoded =
                    base16ct::lower::encode_str(&self.serialize_uncompressed(), &mut buffer)
                        .unwrap();
                f.write_str(encoded)
            } else {
                let mut buffer = [0; 66];
                let encoded = base16ct::lower::encode_str(&self.serialize(), &mut buffer).unwrap();
                f.write_str(encoded)
            }
        }
    }
    impl std::fmt::UpperHex for Point {
        /// Formats the Point as a DER-compressed hex string in upper case.
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            if f.sign_plus() {
                let mut buffer = [0; 130];
                let encoded =
                    base16ct::upper::encode_str(&self.serialize_uncompressed(), &mut buffer)
                        .unwrap();
                f.write_str(encoded)
            } else {
                let mut buffer = [0; 66];
                let encoded = base16ct::upper::encode_str(&self.serialize(), &mut buffer).unwrap();
                f.write_str(encoded)
            }
        }
    }

    impl std::fmt::LowerHex for MaybePoint {
        /// Formats the Point as a DER-compressed hex string in lower case.
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                Valid(point) => point.fmt(f),
                Infinity => {
                    if f.sign_plus() {
                        f.write_str(POINT_INFINITY_UNCOMPRESSED_STR)
                    } else {
                        f.write_str(POINT_INFINITY_COMPRESSED_STR)
                    }
                }
            }
        }
    }

    impl std::fmt::UpperHex for MaybePoint {
        /// Formats the Point as a DER-compressed hex string in upper case.
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                Valid(point) => point.fmt(f),
                Infinity => <Self as std::fmt::LowerHex>::fmt(self, f),
            }
        }
    }

    impl std::fmt::Display for Point {
        /// Serializes and displays the point as a compressed point
        /// in hex format.
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            <Self as std::fmt::LowerHex>::fmt(self, f)
        }
    }

    impl std::fmt::Display for MaybePoint {
        /// Serializes and displays the point as a compressed point
        /// in hex format.
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            <Self as std::fmt::LowerHex>::fmt(self, f)
        }
    }

    impl std::str::FromStr for Point {
        type Err = InvalidPointString;

        /// Parses a point from a compressed or uncompressed DER encoded hex string.
        /// The input string should be either 33 or 65 bytes, hex-encoded.
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Self::from_hex(s)
        }
    }

    impl std::str::FromStr for MaybePoint {
        type Err = InvalidPointString;

        /// Parses a point from a compressed or uncompressed DER encoded hex string.
        /// The input string should be either 33 or 65 bytes, hex-encoded.
        ///
        /// Returns [`MaybePoint::Infinity`] if the input is 33-hex-encoded zero bytes.
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Self::from_hex(s)
        }
    }

    impl TryFrom<&[u8]> for Point {
        type Error = InvalidPointBytes;

        /// Parses a compressed or uncompressed DER encoding of a point. See
        /// [`Point::serialize`] and [`Point::serialize_uncompressed`]. The slice
        /// length should be either 33 or 65 for compressed and uncompressed
        /// encodings respectively.
        ///
        /// Returns [`InvalidPointBytes`] if the bytes do not represent a valid
        /// non-infinity curve point.
        fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
            #[cfg(feature = "secp256k1")]
            let decode_result = secp256k1::PublicKey::from_slice(bytes);

            #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
            let decode_result = k256::PublicKey::from_sec1_bytes(bytes);

            decode_result
                .map(Point::from)
                .map_err(|_| InvalidPointBytes)
        }
    }

    impl TryFrom<&[u8]> for MaybePoint {
        type Error = InvalidPointBytes;

        /// Parses a compressed or uncompressed DER encoding of a point. See
        /// [`MaybePoint::serialize`] and [`MaybePoint::serialize_uncompressed`].
        ///
        /// Returns [`InvalidPointBytes`] if the bytes do not represent a valid
        /// curve point, or if `bytes.len()` is neither 33 nor 65.
        ///
        /// Also accepts 33 or 65 zero bytes, which is interpreted as the point
        /// at infinity.
        fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
            if bool::from(bytes.ct_eq(&[0; 33]) | bytes.ct_eq(&[0; 65])) {
                return Ok(MaybePoint::Infinity);
            }
            Point::try_from(bytes).map(Valid)
        }
    }

    impl TryFrom<&[u8; 33]> for Point {
        type Error = InvalidPointBytes;

        /// Parses a compressed DER encoding of a point. See [`Point::serialize`].
        /// Returns [`InvalidPointBytes`] if the bytes do not represent a valid
        /// non-infinity curve point.
        fn try_from(bytes: &[u8; 33]) -> Result<Self, Self::Error> {
            Self::try_from(bytes as &[u8])
        }
    }

    impl TryFrom<&[u8; 33]> for MaybePoint {
        type Error = InvalidPointBytes;

        /// Parses a compressed DER encoding of a point. See [`MaybePoint::serialize`].
        /// Returns [`InvalidPointBytes`] if the bytes do not represent a valid
        /// curve point.
        ///
        /// Also accepts 33 zero bytes, which is interpreted as the point at infinity.
        fn try_from(bytes: &[u8; 33]) -> Result<Self, Self::Error> {
            if bool::from(bytes.ct_eq(&[0; 33])) {
                return Ok(MaybePoint::Infinity);
            }
            Point::try_from(bytes).map(Valid)
        }
    }

    impl TryFrom<[u8; 33]> for Point {
        type Error = InvalidPointBytes;

        /// Parses a compressed DER encoding of a point. See [`Point::serialize`].
        /// Returns [`InvalidPointBytes`] if the bytes do not represent a valid
        /// non-infinity curve point.
        fn try_from(bytes: [u8; 33]) -> Result<Self, Self::Error> {
            Self::try_from(&bytes)
        }
    }

    impl TryFrom<[u8; 33]> for MaybePoint {
        type Error = InvalidPointBytes;

        /// Parses a compressed DER encoding of a point. See [`MaybePoint::serialize`].
        /// Returns [`InvalidPointBytes`] if the bytes do not represent a valid
        /// curve point.
        ///
        /// Also accepts 33 zero bytes, which is interpreted as the point at infinity.
        fn try_from(bytes: [u8; 33]) -> Result<Self, Self::Error> {
            Self::try_from(&bytes)
        }
    }

    impl From<Point> for [u8; 33] {
        /// Serializes the point to DER-compressed format.
        fn from(point: Point) -> Self {
            point.serialize()
        }
    }

    impl From<MaybePoint> for [u8; 33] {
        /// Serializes the point to DER-compressed format.
        ///
        /// Returns 33 zero bytes if `maybe_point == MaybePoint::Infinity`.
        fn from(maybe_point: MaybePoint) -> Self {
            maybe_point.serialize()
        }
    }

    impl TryFrom<&[u8; 65]> for Point {
        type Error = InvalidPointBytes;

        /// Parses an uncompressed DER encoding of a point. See [`Point::serialize_uncompressed`].
        /// Returns [`InvalidPointBytes`] if the bytes do not represent a valid
        /// non-infinity curve point.
        fn try_from(bytes: &[u8; 65]) -> Result<Self, Self::Error> {
            Self::try_from(bytes as &[u8])
        }
    }

    impl TryFrom<&[u8; 65]> for MaybePoint {
        type Error = InvalidPointBytes;

        /// Parses an uncompressed DER encoding of a point. See [`MaybePoint::serialize_uncompressed`].
        /// Returns [`InvalidPointBytes`] if the bytes do not represent a valid
        /// curve point.
        ///
        /// Also accepts 65 zero bytes, which is interpreted as the point at infinity.
        fn try_from(bytes: &[u8; 65]) -> Result<Self, Self::Error> {
            if bool::from(bytes.ct_eq(&[0; 65])) {
                return Ok(MaybePoint::Infinity);
            }
            Point::try_from(bytes).map(Valid)
        }
    }

    impl TryFrom<[u8; 65]> for Point {
        type Error = InvalidPointBytes;
        /// Parses an uncompressed DER encoding of a point. See [`Point::serialize_uncompressed`].
        /// Returns [`InvalidPointBytes`] if the bytes do not represent a valid
        /// non-infinity curve point.
        fn try_from(bytes: [u8; 65]) -> Result<Self, Self::Error> {
            Self::try_from(&bytes)
        }
    }

    impl TryFrom<[u8; 65]> for MaybePoint {
        type Error = InvalidPointBytes;
        /// Parses an uncompressed DER encoding of a point. See [`MaybePoint::serialize_uncompressed`].
        /// Returns [`InvalidPointBytes`] if the bytes do not represent a valid
        /// curve point.
        ///
        /// Also accepts 65 zero bytes, which is interpreted as the point at infinity.
        fn try_from(bytes: [u8; 65]) -> Result<Self, Self::Error> {
            Self::try_from(&bytes)
        }
    }

    impl From<Point> for [u8; 65] {
        /// Serializes the point to DER-uncompressed format.
        fn from(point: Point) -> Self {
            point.serialize_uncompressed()
        }
    }

    impl From<MaybePoint> for [u8; 65] {
        /// Serializes the point to DER-uncompressed format.
        ///
        /// Returns an array of 65 zero bytes if `maybe_point == MaybePoint::Infinity`.
        fn from(maybe_point: MaybePoint) -> Self {
            maybe_point.serialize_uncompressed()
        }
    }
}

impl ConditionallySelectable for Point {
    /// Conditionally selects one of two points in constant time. No timing
    /// information about the value of either point will be leaked.
    #[inline]
    fn conditional_select(&a: &Self, &b: &Self, choice: subtle::Choice) -> Self {
        #[cfg(feature = "secp256k1")]
        return {
            let mut output_bytes = a.serialize_uncompressed();
            output_bytes.conditional_assign(&b.serialize_uncompressed(), choice);
            Point::try_from(&output_bytes).unwrap()
        };

        #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
        return {
            let mut nonidentity = a.inner.to_nonidentity();
            nonidentity.conditional_assign(&b.inner.to_nonidentity(), choice);
            let inner = k256::PublicKey::from(nonidentity);
            Point { inner }
        };
    }
}

impl ConditionallySelectable for MaybePoint {
    /// Conditionally selects one of two points in constant time. This may operate
    /// in non-constant time if one of the two points is infinity, but no timing
    /// information about the content of a non-infinity point will be leaked
    #[inline]
    fn conditional_select(&a: &Self, &b: &Self, choice: subtle::Choice) -> Self {
        #[cfg(feature = "secp256k1")]
        return {
            let mut output_bytes = a.serialize_uncompressed();
            output_bytes.conditional_assign(&b.serialize_uncompressed(), choice);
            MaybePoint::try_from(&output_bytes).unwrap()
        };

        #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
        return {
            let mut affine = match a {
                MaybePoint::Infinity => k256::AffinePoint::IDENTITY,
                MaybePoint::Valid(point) => point.inner.as_affine().clone(),
            };
            let b_affine = match b {
                MaybePoint::Infinity => k256::AffinePoint::IDENTITY,
                MaybePoint::Valid(point) => point.inner.as_affine().clone(),
            };
            affine.conditional_assign(&b_affine, choice);

            let maybe_point_opt = Option::<k256::elliptic_curve::point::NonIdentity<_>>::from(
                k256::elliptic_curve::point::NonIdentity::new(affine),
            );

            maybe_point_opt
                .map(k256::PublicKey::from)
                .map(MaybePoint::from)
                .unwrap_or(MaybePoint::Infinity)
        };
    }
}

/// The type `P` can be either [`Point`] or [`MaybePoint`], or any type
/// that converts to [`MaybePoint`]. This allows iterators of this type
/// `P` to be summed to an elliptic curve point efficiently.
impl<P> std::iter::Sum<P> for MaybePoint
where
    MaybePoint: From<P>,
{
    fn sum<I>(mut iter: I) -> Self
    where
        I: Iterator<Item = P>,
    {
        let mut sum = MaybePoint::Infinity;
        let mut chunk = [MaybePoint::Infinity; 2048];
        let mut next: usize;

        loop {
            next = 0;
            while next < chunk.len() {
                if let Some(point) = iter.next() {
                    chunk[next] = MaybePoint::from(point);
                    next += 1;
                } else {
                    break;
                }
            }

            sum += MaybePoint::sum(&chunk[..next]);
            if next < chunk.len() {
                return sum;
            }
        }
    }
}

#[cfg(feature = "num-traits")]
impl num_traits::Zero for MaybePoint {
    fn zero() -> Self {
        Infinity
    }
    fn is_zero(&self) -> bool {
        self == &Infinity
    }
}

#[cfg(test)]
mod tests {
    #![allow(non_snake_case)]
    use super::*;
    use crate::{MaybeScalar, Scalar};

    #[test]
    fn validate_generator() {
        assert_eq!(
            Point::generator().serialize_uncompressed(),
            GENERATOR_POINT_BYTES
        );

        #[cfg(feature = "k256")]
        assert_eq!(
            GENERATOR_POINT_BYTES,
            k256::AffinePoint::GENERATOR
                .to_encoded_point(false)
                .as_bytes(),
        );

        #[cfg(feature = "secp256k1")]
        assert_eq!(GENERATOR_POINT_BYTES, {
            let mut arr = [0; 65];
            arr[0] = 0x04;
            arr[1..33].clone_from_slice(&secp256k1::constants::GENERATOR_X);
            arr[33..].clone_from_slice(&secp256k1::constants::GENERATOR_Y);
            arr
        });
    }

    #[test]
    fn point_serialize_and_parse() {
        let point: Point = "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
            .parse()
            .unwrap();

        let compressed_bytes = [
            0x02, 0xF9, 0x30, 0x8A, 0x01, 0x92, 0x58, 0xC3, 0x10, 0x49, 0x34, 0x4F, 0x85, 0xF8,
            0x9D, 0x52, 0x29, 0xB5, 0x31, 0xC8, 0x45, 0x83, 0x6F, 0x99, 0xB0, 0x86, 0x01, 0xF1,
            0x13, 0xBC, 0xE0, 0x36, 0xF9,
        ];
        assert_eq!(point.serialize(), compressed_bytes);
        assert_eq!(Point::try_from(&compressed_bytes).unwrap(), point);
        assert_eq!(Point::try_from(compressed_bytes).unwrap(), point);

        let uncompressed_bytes = [
            0x04, 0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3, 0x10, 0x49, 0x34, 0x4f, 0x85, 0xf8,
            0x9d, 0x52, 0x29, 0xb5, 0x31, 0xc8, 0x45, 0x83, 0x6f, 0x99, 0xb0, 0x86, 0x01, 0xf1,
            0x13, 0xbc, 0xe0, 0x36, 0xf9, 0x38, 0x8f, 0x7b, 0x0f, 0x63, 0x2d, 0xe8, 0x14, 0x0f,
            0xe3, 0x37, 0xe6, 0x2a, 0x37, 0xf3, 0x56, 0x65, 0x00, 0xa9, 0x99, 0x34, 0xc2, 0x23,
            0x1b, 0x6c, 0xb9, 0xfd, 0x75, 0x84, 0xb8, 0xe6, 0x72,
        ];
        assert_eq!(point.serialize_uncompressed(), uncompressed_bytes);
        assert_eq!(Point::try_from(&uncompressed_bytes).unwrap(), point);
        assert_eq!(Point::try_from(uncompressed_bytes).unwrap(), point);

        let xonly_bytes = [
            0xF9, 0x30, 0x8A, 0x01, 0x92, 0x58, 0xC3, 0x10, 0x49, 0x34, 0x4F, 0x85, 0xF8, 0x9D,
            0x52, 0x29, 0xB5, 0x31, 0xC8, 0x45, 0x83, 0x6F, 0x99, 0xB0, 0x86, 0x01, 0xF1, 0x13,
            0xBC, 0xE0, 0x36, 0xF9,
        ];
        assert_eq!(point.serialize_xonly(), xonly_bytes);
        assert_eq!(Point::lift_x(&xonly_bytes).unwrap(), point);

        assert_eq!(
            "020000000000000000000000000000000000000000000000000000000000000000"
                .parse::<MaybePoint>(),
            Err(InvalidPointString)
        );
        assert_eq!(
            "000000000000000000000000000000000000000000000000000000000000000000".parse::<Point>(),
            Err(InvalidPointString)
        );
        assert_eq!(
            "000000000000000000000000000000000000000000000000000000000000000000"
                .parse::<MaybePoint>(),
            Ok(MaybePoint::Infinity)
        );

        assert_eq!(
            "04F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9".parse::<Point>(),
            Err(InvalidPointString)
        );

        // Parsing x-only keys must be done explicitly.
        assert_eq!(
            "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9".parse::<Point>(),
            Err(InvalidPointString)
        );
        assert_eq!(
            Point::lift_x_hex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"),
            Ok(point)
        );
    }

    #[test]
    fn point_addition_subtraction() {
        let point_hex_fixtures = [
            (
                "029a167a1116f081185036ec7c4d06022fb173bbb5f825c075eeb8737a193fc252",
                "028c02a23649adf06635db4d8fd093f106c5a0c7f3643c023a2a3ef23325043e3b",
                "02a55fb23de9aa817fcaaf6676c104dfe69c942e7a92a1d49876b18eeb11e84a0d",
            ),
            (
                "02c1a4892280e30af2e43c7db3d60c3b9c5c413a4ad9dc67fac2d0a2fbf378f451",
                "03b547403b4fe6da07913daaa8e2ab7db65836349435d5e74ec25e2b0092cf52ac",
                "02b1c3aef1cbe5b6533d281d272feec9c1307d29547e57be5ae77522b1e97a7189",
            ),
            (
                "020000000000000000000000000000000000000000000000000000000000000001",
                "030000000000000000000000000000000000000000000000000000000000000002",
                "02f23a2d865c24c99cc9e7b99bd907fb93ebd6ccce106bcccb0082acf8315e67be",
            ),
            (
                "000000000000000000000000000000000000000000000000000000000000000000",
                "030000000000000000000000000000000000000000000000000000000000000002",
                "030000000000000000000000000000000000000000000000000000000000000002",
            ),
            (
                "030000000000000000000000000000000000000000000000000000000000000002",
                "000000000000000000000000000000000000000000000000000000000000000000",
                "030000000000000000000000000000000000000000000000000000000000000002",
            ),
            (
                "02b1c3aef1cbe5b6533d281d272feec9c1307d29547e57be5ae77522b1e97a7189",
                "000000000000000000000000000000000000000000000000000000000000000000",
                "02b1c3aef1cbe5b6533d281d272feec9c1307d29547e57be5ae77522b1e97a7189",
            ),
            (
                "02b1c3aef1cbe5b6533d281d272feec9c1307d29547e57be5ae77522b1e97a7189",
                "03b1c3aef1cbe5b6533d281d272feec9c1307d29547e57be5ae77522b1e97a7189",
                "000000000000000000000000000000000000000000000000000000000000000000",
            ),
        ];

        for (p1_str, p2_str, sum_str) in point_hex_fixtures {
            let P1: MaybePoint = p1_str
                .parse()
                .unwrap_or_else(|_| panic!("failed to parse P1 fixture point {}", p1_str));
            let P2: MaybePoint = p2_str
                .parse()
                .unwrap_or_else(|_| panic!("failed to parse P2 fixture point {}", p2_str));
            let sum: MaybePoint = sum_str
                .parse()
                .unwrap_or_else(|_| panic!("failed to parse sum fixture point {}", sum_str));

            assert_eq!(P1 + P2, sum, "\n{} \n+ {} \n= {}", P1, P2, sum);
            assert_eq!(sum - P1, P2, "\n{} \n- {} \n= {}", sum, P1, P2);
            assert_eq!(sum - P2, P1, "\n{} \n- {} \n= {}", sum, P2, P1);
            assert_eq!(P2 - sum, -P1, "\n{} \n- {} \n= -{}", P2, sum, P1);
            assert_eq!(P1 - sum, -P2, "\n{} \n- {} \n= -{}", P1, sum, P2);

            match P1 {
                Valid(p1_valid) => match P2 {
                    Valid(p2_valid) => {
                        assert_eq!(p1_valid + p2_valid, sum); // `Point` + `Point`
                        assert_eq!(p2_valid + p1_valid, sum); // `Point` + `Point`
                        assert_eq!(sum - p1_valid, P2); // `MaybePoint` - `Point`
                        assert_eq!(sum - p2_valid, P1); // `MaybePoint` - `Point`
                        assert_eq!(p1_valid - p1_valid, Infinity); // `Point` - `Point`
                        assert_eq!(p2_valid - p2_valid, Infinity); // `Point` - `Point`
                    }
                    Infinity => {
                        assert_eq!(P1 + P2, P1);
                        assert_eq!(P2 + P1, P1);
                    }
                },
                Infinity => match P2 {
                    Valid(p2_valid) => {
                        assert_eq!(P1 + p2_valid, P2); // `Infinity` + `Point`
                        assert_eq!(p2_valid + P1, P2); // `Point` + `Infinity`
                        assert_eq!(P1 - p2_valid, -P2); // `Infinity` - `Point`
                        assert_eq!(p2_valid - P1, P2); // `Point` - `Infinity`
                        assert_eq!(p2_valid - p2_valid, Infinity); // `Point` - `Point`
                    }
                    Infinity => {
                        assert_eq!(P1 + P2, Infinity); // `Infinity` + `Infinity`
                        assert_eq!(P1 - P2, Infinity); // `Infinity` - `Infinity`
                        assert_eq!(-P1, Infinity); // -`Infinity`
                        assert_eq!(-P2, Infinity); // -`Infinity`
                    }
                },
            };
        }
    }

    #[test]
    fn point_multiplication() {
        // `Point` * `Scalar`
        assert_eq!(
            "02c1a4892280e30af2e43c7db3d60c3b9c5c413a4ad9dc67fac2d0a2fbf378f451"
                .parse::<Point>()
                .unwrap()
                * Scalar::one(),
            "02c1a4892280e30af2e43c7db3d60c3b9c5c413a4ad9dc67fac2d0a2fbf378f451"
                .parse::<Point>()
                .unwrap()
        );

        // `Scalar` * `Point`
        assert_eq!(
            Scalar::one()
                * "02c1a4892280e30af2e43c7db3d60c3b9c5c413a4ad9dc67fac2d0a2fbf378f451"
                    .parse::<Point>()
                    .unwrap(),
            "02c1a4892280e30af2e43c7db3d60c3b9c5c413a4ad9dc67fac2d0a2fbf378f451"
                .parse::<Point>()
                .unwrap(),
        );

        // `Point` * `MaybeScalar`
        assert_eq!(
            Point::generator()
                * "6407352af47835f53c660963534e33a090b3073861c95a63d194850503803577"
                    .parse::<MaybeScalar>()
                    .unwrap(),
            "023c27be1938d5614bbde4501d040cf2955a60564392cc87248f141ad3c7fc1a78"
                .parse::<MaybePoint>()
                .unwrap()
        );

        // `MaybeScalar` * `Point`
        assert_eq!(
            "6407352af47835f53c660963534e33a090b3073861c95a63d194850503803577"
                .parse::<MaybeScalar>()
                .unwrap()
                * Point::generator(),
            "023c27be1938d5614bbde4501d040cf2955a60564392cc87248f141ad3c7fc1a78"
                .parse::<MaybePoint>()
                .unwrap()
        );

        // `MaybeScalar` * `MaybePoint`
        assert_eq!(
            "6407352af47835f53c660963534e33a090b3073861c95a63d194850503803577"
                .parse::<MaybeScalar>()
                .unwrap()
                * Valid(Point::generator()),
            "023c27be1938d5614bbde4501d040cf2955a60564392cc87248f141ad3c7fc1a78"
                .parse::<MaybePoint>()
                .unwrap()
        );

        // `MaybePoint` * `MaybeScalar`
        assert_eq!(
            Valid(Point::generator())
                * "6407352af47835f53c660963534e33a090b3073861c95a63d194850503803577"
                    .parse::<MaybeScalar>()
                    .unwrap(),
            "023c27be1938d5614bbde4501d040cf2955a60564392cc87248f141ad3c7fc1a78"
                .parse::<MaybePoint>()
                .unwrap()
        );

        // `Infinity` * `Scalar`
        assert_eq!(
            Infinity
                * "6407352af47835f53c660963534e33a090b3073861c95a63d194850503803577"
                    .parse::<Scalar>()
                    .unwrap(),
            Infinity,
        );
        // `Infinity` * `MaybeScalar`
        assert_eq!(
            Infinity
                * "6407352af47835f53c660963534e33a090b3073861c95a63d194850503803577"
                    .parse::<MaybeScalar>()
                    .unwrap(),
            Infinity,
        );

        // `Infinity` * `Zero`
        assert_eq!(Infinity * MaybeScalar::Zero, Infinity);

        // `Scalar` * `Infinity`
        assert_eq!(
            "6407352af47835f53c660963534e33a090b3073861c95a63d194850503803577"
                .parse::<Scalar>()
                .unwrap()
                * Infinity,
            Infinity,
        );
        // `MaybeScalar` * `Infinity`
        assert_eq!(
            "6407352af47835f53c660963534e33a090b3073861c95a63d194850503803577"
                .parse::<MaybeScalar>()
                .unwrap()
                * Infinity,
            Infinity,
        );
        // `Zero` * `Infinity`
        assert_eq!(MaybeScalar::Zero * Infinity, Infinity);
    }

    #[test]
    #[cfg(any(feature = "k256", feature = "secp256k1-invert"))]
    fn point_division_by_scalars() {
        let k = "6407352af47835f53c660963534e33a090b3073861c95a63d194850503803577"
            .parse::<Scalar>()
            .unwrap();

        let point = "0303056e2d7a511a34e0f76ebd1e084bba47cb9cb83ee5950e15b95123654c63fe"
            .parse::<Point>()
            .unwrap();

        assert_eq!(
            point / k,
            "034fca8b1968dfa19107e2638c109b5951d13d59080d236814f591b3c0652e70c3"
                .parse::<Point>()
                .unwrap()
        );

        assert_eq!(k * point / k, point);

        // Run a pseudo-oprf: blind a point with k, multiply it by some other
        // secret scalar r to salt the point.
        let blinded = point * k;

        let r = "90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C"
            .parse::<Scalar>()
            .unwrap();
        let salted = blinded * r;

        // and then unblind the operation result with k.
        let unblinded = salted / k;

        // The result should be the same has having multiplied `point * r` originally.
        assert_eq!(unblinded, point * r);

        // MaybePoint / Scalar
        assert_eq!(MaybePoint::Valid(salted) / k, MaybePoint::Valid(unblinded));
        assert_eq!(
            MaybePoint::Infinity / Scalar::try_from(40).unwrap(),
            MaybePoint::Infinity
        );
    }

    #[test]
    fn point_assignment_operators() {
        let scalar = "b21643ba6bd9b6ca2e1f6da85561092ad44949835519d71dd837be8a8c67fe7f"
            .parse::<Scalar>()
            .unwrap();

        let pub_point = "0303056e2d7a511a34e0f76ebd1e084bba47cb9cb83ee5950e15b95123654c63fe"
            .parse::<Point>()
            .unwrap();

        // `Point` *= `Scalar`
        let mut P1 = Point::generator();
        P1 *= scalar;
        assert_eq!(P1, pub_point);

        // `MaybePoint` *= `Scalar`
        let mut P2 = Valid(Point::generator());
        P2 *= scalar;
        assert_eq!(P2, Valid(pub_point));

        // `MaybePoint` *= `MaybeScalar`
        let mut P2 = Valid(Point::generator());
        P2 *= MaybeScalar::Valid(scalar);
        assert_eq!(P2, Valid(pub_point));
    }

    #[test]
    fn point_iter_sum() {
        {
            let scalars: Vec<Scalar> = (1..1000)
                .map(|i: u128| Scalar::try_from(i).unwrap())
                .collect();
            let points: Vec<Point> = scalars.iter().map(|&k| k.base_point_mul()).collect();

            assert_eq!(
                points.into_iter().sum::<MaybePoint>(),
                scalars.into_iter().sum::<MaybeScalar>().base_point_mul()
            );
        }

        {
            let scalars: Vec<Scalar> = (1..10000)
                .map(|i: u128| Scalar::try_from(i).unwrap())
                .collect();
            let points: Vec<Point> = scalars.iter().map(|&k| k.base_point_mul()).collect();

            assert_eq!(
                points.into_iter().sum::<MaybePoint>(),
                scalars.into_iter().sum::<MaybeScalar>().base_point_mul()
            );
        }
    }
}
