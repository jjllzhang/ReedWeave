//! Reusable BrakeFRI field encodings, hashes, DFT, Merkle commitments and transcript.
pub mod dft;
pub mod fields;
pub mod hash;
pub mod mmcs;
pub mod profile;
pub mod transcript;

/// Number of coefficient blocks.
pub const M: usize = 1 << 6;
/// Fixed terminal coefficient length; the protocol performs at least one fold.
pub const TERMINAL_COEFFICIENTS: usize = 1 << 7;
pub const MIN_LOG_N: usize = 14;
/// Evaluation-domain blowup factor.
pub const B: usize = 2;
/// Number of transcript-sampled queries, including repetitions.
pub const Q: usize = 244;
