#![doc = include_str!("../README.md")]
#![doc = include_str!("../doc/API.md")]

#[cfg(all(not(feature = "secp256k1"), not(feature = "k256")))]
compile_error!("At least one of the `secp256k1` or `k256` features must be enabled.");

mod arithmetic;
pub mod errors;
mod points;
mod scalars;
mod serde;

pub use points::*;
pub use scalars::*;
