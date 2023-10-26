use super::{MaybePoint, MaybeScalar, Point, Scalar, G};

#[cfg(feature = "secp256k1")]
use super::LIBSECP256K1_CTX;

/// Can't just use `Option<T>` directly here because the blanket
/// `impl Option<T> for T` in the standard library causes conflicts.
trait Optional<T> {
    fn option(self) -> Option<T>;
}

impl Optional<Scalar> for Scalar {
    fn option(self) -> Option<Scalar> {
        Some(self)
    }
}
impl Optional<Scalar> for MaybeScalar {
    fn option(self) -> Option<Scalar> {
        self.into_option()
    }
}
impl Optional<Point> for Point {
    fn option(self) -> Option<Point> {
        Some(self)
    }
}
impl Optional<Point> for MaybePoint {
    fn option(self) -> Option<Point> {
        self.into_option()
    }
}
impl Optional<Point> for G {
    fn option(self) -> Option<Point> {
        Some(Point::generator())
    }
}

mod inner_operator_impl {
    use super::*;

    /// `Scalar` + `Scalar`
    impl std::ops::Add<Scalar> for Scalar {
        type Output = MaybeScalar;

        fn add(self, other: Scalar) -> Self::Output {
            #[cfg(feature = "secp256k1")]
            let inner_result = self.inner.add_tweak(&secp256k1::Scalar::from(other.inner));

            #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
            let inner_result: Option<k256::NonZeroScalar> =
                (k256::NonZeroScalar::new(self.inner.as_ref() + other.inner.as_ref())).into();

            inner_result
                .map(MaybeScalar::from)
                .unwrap_or(MaybeScalar::Zero)
        }
    }

    /// `Point` + `Point`
    impl std::ops::Add<Point> for Point {
        type Output = MaybePoint;
        fn add(self, other: Point) -> Self::Output {
            #[cfg(feature = "secp256k1")]
            let inner_result = self.inner.combine(&other.inner);

            #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
            let inner_result =
                k256::PublicKey::try_from(self.inner.to_projective() + other.inner.as_affine());

            inner_result
                .map(MaybePoint::from)
                .unwrap_or(MaybePoint::Infinity)
        }
    }

    /// Note: `Scalar` * `Scalar` always outputs a non-zero `Scalar`.
    impl std::ops::Mul<Scalar> for Scalar {
        type Output = Scalar;
        fn mul(self, other: Scalar) -> Self::Output {
            #[cfg(feature = "secp256k1")]
            return self
                .inner
                .mul_tweak(&secp256k1::Scalar::from(other.inner))
                .map(Scalar::from)
                .expect("non-zero scalar multiplication never results in zero");

            #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
            return Scalar::from(self.inner * other.inner);
        }
    }

    /// `Point` * `Scalar`
    impl std::ops::Mul<Scalar> for Point {
        type Output = Point;
        fn mul(self, scalar: Scalar) -> Self::Output {
            #[cfg(feature = "secp256k1")]
            return self.mul(&LIBSECP256K1_CTX, scalar);

            #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
            return {
                let nonidentity =
                    k256::elliptic_curve::point::NonIdentity::new(self.inner.to_projective())
                        .unwrap();
                let inner = k256::PublicKey::from(nonidentity * scalar.inner);
                Point::from(inner)
            };
        }
    }
    /// `Scalar` * `Point`
    impl std::ops::Mul<Point> for Scalar {
        type Output = Point;
        fn mul(self, point: Point) -> Self::Output {
            point * self
        }
    }

    /// -`Scalar`
    impl std::ops::Neg for Scalar {
        type Output = Scalar;
        fn neg(self) -> Self::Output {
            #[cfg(feature = "secp256k1")]
            let inner = self.inner.negate();

            #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
            let inner = -self.inner;

            Scalar::from(inner)
        }
    }
    impl std::ops::Neg for MaybeScalar {
        type Output = MaybeScalar;
        fn neg(self) -> Self::Output {
            self.into_option()
                .map(|scalar| MaybeScalar::Valid(-scalar))
                .unwrap_or(MaybeScalar::Zero)
        }
    }

    /// `-Point`
    impl std::ops::Neg for Point {
        type Output = Point;
        fn neg(self) -> Self::Output {
            #[cfg(feature = "secp256k1")]
            return self.negate(&LIBSECP256K1_CTX);

            #[cfg(all(feature = "k256", not(feature = "secp256k1")))]
            return Point::from(
                k256::PublicKey::from_affine(-self.inner.as_affine().clone()).unwrap(),
            );
        }
    }
    impl std::ops::Neg for MaybePoint {
        type Output = MaybePoint;
        fn neg(self) -> Self::Output {
            self.into_option()
                .map(|p| MaybePoint::Valid(-p))
                .unwrap_or(MaybePoint::Infinity)
        }
    }
}

mod generator_ops {
    use super::*;

    /// `Scalar` * `G`
    impl std::ops::Mul<G> for Scalar {
        type Output = Point;
        fn mul(self, _: G) -> Self::Output {
            self.base_point_mul()
        }
    }

    /// `G` * `Scalar`
    impl std::ops::Mul<Scalar> for G {
        type Output = Point;
        fn mul(self, scalar: Scalar) -> Self::Output {
            scalar.base_point_mul()
        }
    }

    /// `-G`
    impl std::ops::Neg for G {
        type Output = Point;
        fn neg(self) -> Self::Output {
            -Point::generator()
        }
    }
}

/// Adds any two types together. These could be `Point`, `Scalar`, or the
/// maybe-versions of each - as long as their shared inner type `I` is additive.
/// The output type T3 is always either `MaybePoint` or `MaybeScalar` because
/// addition operations can always result in zero/infinity.
fn add_any<T1, T2, T3, I>(a: T1, b: T2) -> T3
where
    T1: Optional<I>,
    T2: Optional<I>,
    I: std::ops::Add<Output = T3>,
    T3: From<I> + Default,
{
    match a.option() {
        None => match b.option() {
            None => T3::default(),
            Some(b_inner) => T3::from(b_inner),
        },
        Some(a_inner) => match b.option() {
            None => T3::from(a_inner),
            Some(b_inner) => a_inner + b_inner,
        },
    }
}

/// Simply addition with the right-hand-side negated.
fn subtract_any<T1, T2, N2, T3>(a: T1, b: T2) -> T3
where
    T1: std::ops::Add<N2, Output = T3>,
    T2: std::ops::Neg<Output = N2>,
{
    a + (-b)
}

/// Multiplies any two items which must be commutatively multiplicative,
/// (i.e. a*b = b*a) where the product of their inner types `I1` and `I2`
/// can be converted to the output type `T3`.
///
/// This implementation supports both point multiplication by scalars, or
/// scalar-by-scalar multiplication.
fn multiply_any<T1, T2, I1, I2, I3, T3>(a: T1, b: T2) -> T3
where
    T1: Optional<I1>,
    T2: Optional<I2>,
    I1: std::ops::Mul<I2, Output = I3>,
    I2: std::ops::Mul<I1, Output = I3>,
    T3: Default + From<I3>,
{
    match a.option().zip(b.option()) {
        None => T3::default(),
        Some((a_inner, b_inner)) => T3::from(a_inner * b_inner),
    }
}

/// Implement a binary operator from `std::ops`.
///
/// - `$opname` is the trait name from `std::ops`, such as `Add`, `Sub`, or `Mul`.
/// - `$opfunc` is the function identifier for the trait.
/// - `$op_logic` is a function which generically implements the operation logic.
/// - `$lhs_type` and `$rhs_type` are types to implement the trait on.
/// - `$operator` is the binary operator which is being implemented. This is just for decoration.
macro_rules! implement_binary_ops {
    (
        $opname:ident, $opfunc:ident, // Add, add,
        $op_logic:ident, // implementation function
        $( $lhs_type:ident $operator:tt $rhs_type:ident -> $output_type:ident; )+ // Type1 + Type2 -> OutputType
    ) => {
        $(
            impl std::ops::$opname<$rhs_type> for $lhs_type {
                type Output = $output_type;

                fn $opfunc(self, rhs: $rhs_type) -> Self::Output {
                    $op_logic(self, rhs)
                }
            }
        )+
    };
}

/// Implement a binary assignment operator from `std::ops`.
///
/// - `$opname` is the trait name from `std::ops`, such as `AddAssign`, or `MulAssign`.
/// - `$opfunc` is the function identifier for the trait.
/// - `$lhs_type` and `$rhs_type` are types to implement the trait on.
/// - `$operator` is the binary operator which is being implemented. This is used
///    to invoke the actual binary operator.
macro_rules! implement_assign_ops {
    (
        $opname:ident, $opfunc:ident, // AddAssign, add_assign,
        $( $lhs_type:ident $operator:tt $rhs_type:ident; )+
    ) => {
        $(
            impl std::ops::$opname<$rhs_type> for $lhs_type {
                fn $opfunc(&mut self, rhs: $rhs_type) {
                    *self = *self $operator rhs;
                }
            }
        )+
    };
}

implement_binary_ops!(
    Add, add, add_any,

    Scalar + MaybeScalar -> MaybeScalar;
    MaybeScalar + Scalar -> MaybeScalar;
    MaybeScalar + MaybeScalar -> MaybeScalar;

    Point + MaybePoint -> MaybePoint;
    MaybePoint + Point -> MaybePoint;
    MaybePoint + MaybePoint -> MaybePoint;

    Point + G -> MaybePoint;
    MaybePoint + G -> MaybePoint;
    G + Point -> MaybePoint;
    G + MaybePoint -> MaybePoint;
);

implement_binary_ops!(
    Sub, sub, subtract_any,

    Scalar - Scalar -> MaybeScalar;
    Scalar - MaybeScalar -> MaybeScalar;
    MaybeScalar - Scalar -> MaybeScalar;
    MaybeScalar - MaybeScalar -> MaybeScalar;

    Point - Point -> MaybePoint;
    Point - MaybePoint -> MaybePoint;
    MaybePoint - Point -> MaybePoint;
    MaybePoint - MaybePoint -> MaybePoint;

    Point - G -> MaybePoint;
    MaybePoint - G -> MaybePoint;
    G - Point -> MaybePoint;
    G - MaybePoint -> MaybePoint;
);

implement_binary_ops!(
    Mul, mul, multiply_any,

    Scalar * MaybeScalar -> MaybeScalar;
    MaybeScalar * Scalar -> MaybeScalar;
    MaybeScalar * MaybeScalar -> MaybeScalar;

    Point * MaybeScalar -> MaybePoint;
    MaybePoint * Scalar -> MaybePoint;
    MaybePoint * MaybeScalar -> MaybePoint;

    MaybeScalar * Point -> MaybePoint;
    Scalar * MaybePoint -> MaybePoint;
    MaybeScalar * MaybePoint -> MaybePoint;

    MaybeScalar * G -> MaybePoint;
    G * MaybeScalar -> MaybePoint;
);

implement_assign_ops!(
    AddAssign, add_assign,

    MaybeScalar + Scalar;
    MaybeScalar + MaybeScalar;

    MaybePoint + Point;
    MaybePoint + MaybePoint;
    MaybePoint + G;

    // Cannot `AddAssign` to `Scalar` or `Point`,
    // because addition can always result in a zero result.
);

implement_assign_ops!(
    SubAssign, sub_assign,
    MaybeScalar - Scalar;
    MaybeScalar - MaybeScalar;

    MaybePoint - Point;
    MaybePoint - MaybePoint;
    MaybePoint - G;

    // Cannot `SubAssign` to `Scalar` or `Point`,
    // because addition can always result in a zero result.
);

implement_assign_ops!(
    MulAssign, mul_assign,

    Scalar * Scalar;
    MaybeScalar * Scalar;
    MaybeScalar * MaybeScalar;

    Point * Scalar;
    MaybePoint * Scalar;
    MaybePoint * MaybeScalar;
);

#[cfg(any(feature = "k256", feature = "secp256k1-invert"))]
mod division {
    use super::*;

    /// To divide by `rhs`, we simply multiply by `rhs.inverse()`, because `rhs.inverse()`
    /// is algebraically the same as `1 / rhs`.
    impl std::ops::Div<Scalar> for Scalar {
        type Output = Scalar;
        fn div(self, rhs: Scalar) -> Self::Output {
            self * rhs.invert()
        }
    }

    /// To divide by `rhs`, we simply multiply by `rhs.inverse()`, because `rhs.inverse()`
    /// is algebraically the same as `1 / rhs`.
    impl std::ops::Div<Scalar> for Point {
        type Output = Point;
        fn div(self, rhs: Scalar) -> Self::Output {
            self * rhs.invert()
        }
    }

    /// To divide by `rhs`, we simply multiply by `rhs.inverse()`, because `rhs.inverse()`
    /// is algebraically the same as `1 / rhs`.
    impl std::ops::Div<Scalar> for G {
        type Output = Point;
        fn div(self, rhs: Scalar) -> Self::Output {
            self * rhs.invert()
        }
    }

    /// Divides any two items which can be divided. The left-hand-side type `T1`
    /// can be optional with internal type `I1`, but the right-hand-side must
    /// be non-zero for division to be defined.
    ///
    /// The quotient type of `T1 / I1` must be convertible to the output type `T3`.
    ///
    /// This implementation supports point multiplication by inverted scalars, or
    /// modular division of scalars.
    fn divide_any<T1, T2, I1, I3, T3>(a: T1, b: T2) -> T3
    where
        T1: Optional<I1>,
        I1: std::ops::Div<T2, Output = I3>,
        T3: Default + From<I3>,
    {
        match a.option() {
            None => T3::default(),
            Some(a_inner) => T3::from(a_inner / b),
        }
    }

    implement_binary_ops!(
        Div, div, divide_any,
        MaybeScalar / Scalar -> MaybeScalar;
        MaybePoint / Scalar -> MaybePoint;
    );

    implement_assign_ops!(
        DivAssign, div_assign,

        Scalar / Scalar;
        MaybeScalar / Scalar;

        Point / Scalar;
        MaybePoint / Scalar;
    );
}
