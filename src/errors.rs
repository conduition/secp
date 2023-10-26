macro_rules! simple_error {
    ($name:ident, $error:expr, $doc:literal) => {
        #[doc=$doc]
        #[derive(Debug, PartialEq, Eq)]
        pub struct $name;

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str($error)
            }
        }

        impl std::error::Error for $name {}
    };
}

simple_error!(
    InvalidScalarBytes,
    "received invalid scalar bytes",
    "Returned when parsing a scalar from an incorrectly formatted byte-array."
);

simple_error!(
    InvalidScalarString,
    "received invalid scalar hex string",
    "Returned when parsing a scalar from an incorrectly formatted hex string."
);

simple_error!(
    InvalidPointBytes,
    "received invalid point byte representation",
    "Returned when parsing a point from an incorrectly formatted byte-array."
);

simple_error!(
    InvalidPointString,
    "received invalid point hex string representation",
    "Returned when parsing a point from an incorrectly formatted hex string."
);

simple_error!(
    ZeroScalarError,
    "expected valid non-zero scalar",
    "Returned when asserting a `MaybeScalar` is not zero, \
    or converting from a `MaybeScalar` to a `Scalar`."
);

simple_error!(
    InfinityPointError,
    "expected valid non-infinity point",
    "Returned when asserting a `MaybePoint` is not infinity, \
    or converting from a `MaybePoint` to a `Point`."
);
