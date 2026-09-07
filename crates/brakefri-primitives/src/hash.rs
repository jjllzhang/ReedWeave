//! Blake3 byte hashing through Plonky3, with distinct leaf, node, and transcript roles.
//!
//! All hashing goes through Plonky3's `p3_blake3::Blake3`. Its `hash_slice`
//! delegates to `hash_iter_slices`, passing the complete preimage to the underlying
//! `blake3` hasher in one update. The separate `hash_iter` API buffers byte iterators
//! in 512-byte chunks. `p3-blake3/neon` enables the aarch64 intrinsics path.

use std::marker::PhantomData;

use p3_blake3::Blake3;
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

use crate::fields::CanonicalField;

pub type Digest = [u8; 32];

/// Protocol hash function identifier, bound into the transcript context.
pub const HASH_ID: &str = "blake3";

/// Hash one complete preimage through Plonky3's Blake3.
fn hash_bytes(bytes: &[u8]) -> Digest {
    Blake3.hash_slice(bytes)
}

/// HashChallenger's byte hash, separated from both Merkle roles.
#[derive(Debug, Clone, Copy)]
pub struct TranscriptHash;

impl CryptographicHasher<u8, Digest> for TranscriptHash {
    fn hash_iter<I: IntoIterator<Item = u8>>(&self, input: I) -> Digest {
        let mut bytes = Vec::new();
        bytes.push(2);
        bytes.extend(input);
        hash_bytes(&bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LeafKind {
    Base = 0,
    Challenge = 1,
}

/// Full Blake3 hash, including its normal padding and finalization.
#[derive(Debug, Clone, Copy)]
pub struct NodeHash;

impl PseudoCompressionFunction<Digest, 2> for NodeHash {
    fn compress(&self, input: [Digest; 2]) -> Digest {
        let mut bytes = [0u8; 65];
        bytes[0] = 1;
        bytes[1..33].copy_from_slice(&input[0]);
        bytes[33..].copy_from_slice(&input[1]);
        hash_bytes(&bytes)
    }
}

/// Width is fixed by the checked single-matrix adapter before hashing.
/// Scalar packing keeps exactly the same preimage on every target architecture.
#[derive(Clone)]
pub(crate) struct CanonicalLeafHash<F> {
    pub(crate) kind: LeafKind,
    pub(crate) coordinate_count: u64,
    pub(crate) marker: PhantomData<F>,
}

impl<F: CanonicalField> CryptographicHasher<F, Digest> for CanonicalLeafHash<F> {
    fn hash_iter<I: IntoIterator<Item = F>>(&self, input: I) -> Digest {
        let mut bytes = Vec::new();
        bytes.push(0);
        bytes.push(F::PROFILE_ID);
        bytes.push(self.kind as u8);
        bytes.extend(self.coordinate_count.to_le_bytes());
        for value in input {
            bytes.extend(value.to_canonical_bytes());
        }
        hash_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Digest {
        assert_eq!(s.len(), 64);
        std::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
    }

    #[test]
    fn hashing_matches_reference_vectors_across_chunk_boundaries() {
        // Official BLAKE3 test vectors, plus one-shot reference digests for
        // 0xAB-filled preimages around 512 bytes and BLAKE3's 1024-byte chunk size.
        assert_eq!(
            hash_bytes(b""),
            hex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
        );
        assert_eq!(
            hash_bytes(b"abc"),
            hex("6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85")
        );
        for (len, expected) in [
            (
                65usize,
                "593d74e07ef1f571aa3ab7e5c5232e3e3343664d1012e402761c86a2c6844083",
            ),
            (
                511,
                "516e5ec8f73bd840de2d602fae053f510575414fb1bd315490c78809d9706525",
            ),
            (
                512,
                "b5459c9e0162967055b19017268129e93f9ff3329b7241b89f62e9e9a01150a6",
            ),
            (
                513,
                "744fa417294ad9ed916e14fd1c93135ba40bd44a4ba4b78a2d01f651d044938a",
            ),
            (
                1024,
                "9c2e6269af15385148a43a5a652ba0048384092aff9e2b03c2a6613a33ec253c",
            ),
            (
                128 * 1024 + 1,
                "391b14ebb97077a7949840758e3652e99d01156c0f4c8252c2ef0ed01dd948db",
            ),
        ] {
            let bytes = vec![0xAB; len];
            assert_eq!(hash_bytes(&bytes), hex(expected));
        }
    }
}
