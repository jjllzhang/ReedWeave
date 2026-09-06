//! Suite-generic byte hashing with distinct leaf, node, and transcript roles.

use std::marker::PhantomData;

use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

use crate::fields::CanonicalField;

pub type Digest = [u8; 32];

pub trait HashSuite: Clone + Send + Sync + 'static {
    type Hasher: CryptographicHasher<u8, Digest> + Clone + Send + Sync + 'static;
    const ID: &'static str;
    fn hasher(&self) -> Self::Hasher;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct KeccakSuite;
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256Suite;
#[derive(Debug, Clone, Copy, Default)]
pub struct Blake3Suite;

impl HashSuite for KeccakSuite {
    type Hasher = p3_keccak::Keccak256Hash;
    const ID: &'static str = "keccak256";
    fn hasher(&self) -> Self::Hasher {
        p3_keccak::Keccak256Hash
    }
}
impl HashSuite for Sha256Suite {
    type Hasher = p3_sha256::Sha256;
    const ID: &'static str = "sha256";
    fn hasher(&self) -> Self::Hasher {
        p3_sha256::Sha256
    }
}
impl HashSuite for Blake3Suite {
    type Hasher = p3_blake3::Blake3;
    const ID: &'static str = "blake3";
    fn hasher(&self) -> Self::Hasher {
        p3_blake3::Blake3
    }
}

/// HashChallenger's byte hash, separated from both Merkle roles.
#[derive(Debug, Clone, Copy)]
pub struct TranscriptHash<H>(pub H);

impl<H: CryptographicHasher<u8, Digest>> CryptographicHasher<u8, Digest> for TranscriptHash<H> {
    fn hash_iter<I: IntoIterator<Item = u8>>(&self, input: I) -> Digest {
        self.0.hash_iter(std::iter::once(2).chain(input))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LeafKind {
    Base = 0,
    Challenge = 1,
}

/// Full byte hash, including the selected hash's normal padding and finalization.
#[derive(Debug, Clone, Copy)]
pub struct NodeHash<H>(pub H);

impl<H: CryptographicHasher<u8, Digest>> PseudoCompressionFunction<Digest, 2> for NodeHash<H> {
    fn compress(&self, input: [Digest; 2]) -> Digest {
        self.0
            .hash_iter(std::iter::once(1).chain(input.into_iter().flatten()))
    }
}

/// Width is fixed by the checked single-matrix adapter before upstream hashing.
/// Scalar packing keeps exactly the same preimage on every target architecture.
#[derive(Clone)]
pub(crate) struct CanonicalLeafHash<F, H> {
    pub(crate) hasher: H,
    pub(crate) kind: LeafKind,
    pub(crate) coordinate_count: u64,
    pub(crate) marker: PhantomData<F>,
}

impl<F: CanonicalField, H: CryptographicHasher<u8, Digest>> CryptographicHasher<F, Digest>
    for CanonicalLeafHash<F, H>
{
    fn hash_iter<I: IntoIterator<Item = F>>(&self, input: I) -> Digest {
        self.hasher.hash_iter(
            [0, F::PROFILE_ID, self.kind as u8]
                .into_iter()
                .chain(self.coordinate_count.to_le_bytes())
                .chain(
                    input
                        .into_iter()
                        .flat_map(|value| value.to_canonical_bytes()),
                ),
        )
    }
}
