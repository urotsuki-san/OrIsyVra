#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

//! OrIsyVra-P768/384 core primitives.

mod constants;
mod permutation;
mod prf;

pub use permutation::{
    invert, permute, CAPACITY_BYTES, RATE_BYTES, ROUNDS, STATE_BYTES, STATE_WORDS,
};
#[cfg(feature = "analysis")]
pub use permutation::{invert_rounds, permute_rounds};
pub use prf::{derive_key, mac32, prf_parts, Domain, KEY_SIZE, TAG_SIZE};
