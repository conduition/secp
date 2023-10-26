#![doc = include_str!("../README.md")]
#![doc = include_str!("../doc/API.md")]

mod arithmetic;
pub mod errors;
mod points;
mod scalars;
mod serde;

pub use points::*;
pub use scalars::*;
