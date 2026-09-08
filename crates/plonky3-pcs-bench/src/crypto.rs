//! Scalar canonical Blake3 MMCS and an unbiased byte-backed field challenger.
use std::marker::PhantomData;

use brakefri_primitives::{
    fields::CanonicalField,
    hash::{NodeHash, TranscriptHash},
};
use p3_blake3::Blake3;
use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, CanSampleUniformBits, FieldChallenger,
    GrindingChallenger, HashChallenger, ResamplingError,
};
use p3_commit::ExtensionMmcs;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_stir::StirCommitment;
use p3_symmetric::{CryptographicHasher, MerkleCap};

pub type Cap<F> = MerkleCap<F, [u8; 32]>;
pub type BaseMmcs<F> = MerkleTreeMmcs<F, u8, LeafHash<F>, NodeHash, 2, 32>;
pub type ChallengeMmcs<F, EF> = ExtensionMmcs<F, EF, BaseMmcs<F>>;

#[derive(Clone, Debug)]
pub struct LeafHash<F> {
    role: u8,
    marker: PhantomData<F>,
}
impl<F: CanonicalField> CryptographicHasher<F, [u8; 32]> for LeafHash<F> {
    fn hash_iter<I: IntoIterator<Item = F>>(&self, input: I) -> [u8; 32] {
        let input = input.into_iter();
        let mut bytes = Vec::with_capacity(3 + input.size_hint().0 * F::BYTE_WIDTH);
        bytes.extend([0, F::PROFILE_ID, self.role]);
        for value in input {
            bytes.extend(value.to_canonical_bytes());
        }
        Blake3.hash_slice(&bytes)
    }
}
pub fn mmcs<F: CanonicalField>(role: u8) -> BaseMmcs<F> {
    MerkleTreeMmcs::new(
        LeafHash {
            role,
            marker: PhantomData,
        },
        NodeHash,
        0,
    )
}

#[derive(Clone)]
pub struct Challenger<F> {
    bytes: HashChallenger<u8, TranscriptHash, 32>,
    marker: PhantomData<F>,
}
impl<F: CanonicalField> Challenger<F> {
    pub fn new(context: &[u8]) -> Self {
        let mut result = Self {
            bytes: HashChallenger::new(Vec::new(), TranscriptHash),
            marker: PhantomData,
        };
        result.bytes.observe_slice(context);
        result
    }
}
impl<F: CanonicalField> CanObserve<F> for Challenger<F> {
    fn observe(&mut self, value: F) {
        for byte in value.to_canonical_bytes() {
            self.bytes.observe(byte);
        }
    }
}
impl<F: CanonicalField> CanObserve<Cap<F>> for Challenger<F> {
    fn observe(&mut self, cap: Cap<F>) {
        self.observe(F::from_usize(cap.num_roots()));
        for root in cap.roots() {
            self.bytes.observe_slice(root);
        }
    }
}
impl<F: CanonicalField> CanObserve<StirCommitment<Cap<F>>> for Challenger<F> {
    fn observe(&mut self, commitment: StirCommitment<Cap<F>>) {
        self.observe(F::from_usize(commitment.len()));
        for root in commitment.iter() {
            self.observe(root.clone());
        }
    }
}
impl<F: CanonicalField> CanSample<F> for Challenger<F> {
    fn sample(&mut self) -> F {
        loop {
            let mut bytes = [0u8; 16];
            for byte in &mut bytes[..F::BYTE_WIDTH] {
                *byte = self.bytes.sample();
            }
            if let Ok(value) = F::from_canonical_bytes(&bytes[..F::BYTE_WIDTH]) {
                return value;
            }
        }
    }
}
impl<F: CanonicalField> CanSampleBits<usize> for Challenger<F> {
    fn sample_bits(&mut self, bits: usize) -> usize {
        assert!(bits < usize::BITS as usize);
        let mut value = 0usize;
        for i in 0..bits.div_ceil(8) {
            value |= usize::from(self.bytes.sample()) << (8 * i);
        }
        value & ((1usize << bits) - 1)
    }
}
impl<F: CanonicalField> CanSampleUniformBits<F> for Challenger<F> {
    fn sample_uniform_bits<const RESAMPLE: bool>(
        &mut self,
        bits: usize,
    ) -> Result<usize, ResamplingError> {
        // Fresh bytes already give uniform bits; no field reduction or retry bias.
        Ok(self.sample_bits(bits))
    }
}
impl<F: CanonicalField> FieldChallenger<F> for Challenger<F> {}
impl<F: CanonicalField> GrindingChallenger for Challenger<F> {
    type Witness = F;
    fn grind(&mut self, bits: usize) -> F {
        assert_eq!(bits, 0, "the audited benchmark supports zero PoW only");
        F::ZERO
    }
    fn check_witness(&mut self, bits: usize, witness: F) -> bool {
        bits == 0 && witness == F::ZERO
    }
}
