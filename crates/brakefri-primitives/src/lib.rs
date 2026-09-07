//! Reusable BrakeFRI field encodings, hashes, DFT, Merkle commitments and transcript.
pub mod dft;
pub mod fields;
pub mod hash;
pub mod mmcs;
pub mod profile;
pub mod transcript;

/// Number of coefficient blocks.
pub const M: usize = 1024;
/// Evaluation-domain blowup factor.
pub const B: usize = 2;
/// Number of transcript-sampled queries, including repetitions.
pub const Q: usize = 244;
