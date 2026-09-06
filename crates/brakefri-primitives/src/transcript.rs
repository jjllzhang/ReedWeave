//! Sequential byte challenger and locally constructed protocol context.
use crate::fields::{CanonicalField, F128, Goldilocks, GoldilocksQuadratic};
use crate::hash::{Digest, HashSuite, TranscriptHash};
use crate::profile::Profile;
use core::marker::PhantomData;
use p3_challenger::{CanObserve, CanSample, HashChallenger};
use p3_field::{BasedVectorSpace, ExtensionField, TwoAdicField};
use thiserror::Error;

pub const PROTOCOL_LABEL: &[u8] = b"BrakeFRI-Section3-Multiproof-v1";
pub const ENCODING_ID: &[u8] = b"canonical-coordinates-multiproof-v1";

mod sealed {
    pub trait Sealed {}
}
/// A fixed base/challenge pairing. Domains always use the base-field root.
pub trait FieldProfile: sealed::Sealed + Clone + Send + Sync + 'static {
    type Base: CanonicalField + TwoAdicField + Ord;
    type Challenge: CanonicalField + ExtensionField<Self::Base>;
    const PROFILE: Profile;
    fn sample_challenge(source: &mut impl CanSample<u8>) -> Self::Challenge;
}
#[derive(Clone, Copy, Debug)]
pub struct GoldilocksProfile;
#[derive(Clone, Copy, Debug)]
pub struct F128Profile;
impl sealed::Sealed for GoldilocksProfile {}
impl sealed::Sealed for F128Profile {}
impl FieldProfile for GoldilocksProfile {
    type Base = Goldilocks;
    type Challenge = GoldilocksQuadratic;
    const PROFILE: Profile = Profile::GoldilocksQuadratic;
    fn sample_challenge(source: &mut impl CanSample<u8>) -> Self::Challenge {
        GoldilocksQuadratic::from_basis_coefficients_fn(|_| sample_base::<Goldilocks>(source))
    }
}
impl FieldProfile for F128Profile {
    type Base = F128;
    type Challenge = F128;
    const PROFILE: Profile = Profile::F128Base;
    fn sample_challenge(source: &mut impl CanSample<u8>) -> Self::Challenge {
        sample_base::<F128>(source)
    }
}

/// Rejection sampling for a canonical base element; never modular reduction.
fn sample_base<F: CanonicalField>(source: &mut impl CanSample<u8>) -> F {
    assert!(F::BYTE_WIDTH <= 16);
    loop {
        let mut bytes = [0u8; 16];
        for byte in &mut bytes[..F::BYTE_WIDTH] {
            *byte = source.sample();
        }
        if let Ok(value) = F::from_canonical_bytes(&bytes[..F::BYTE_WIDTH]) {
            return value;
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum TranscriptError {
    #[error("log_n must be in 11..=30")]
    UnsupportedSize,
    #[error("transcript payload has the wrong shape")]
    Shape,
    #[error("index sampling requires at most 21 bits")]
    IndexBits,
}

#[derive(Clone)]
pub struct Transcript<P: FieldProfile, S: HashSuite> {
    challenger: HashChallenger<u8, TranscriptHash<S::Hasher>, 32>,
    rounds: usize,
    marker: PhantomData<P>,
}

impl<P: FieldProfile, S: HashSuite> Transcript<P, S> {
    pub fn new(log_n: usize, suite: &S) -> Result<Self, TranscriptError> {
        if !(11..=30).contains(&log_n) {
            return Err(TranscriptError::UnsupportedSize);
        }
        let mut result = Self {
            challenger: HashChallenger::new(Vec::new(), TranscriptHash(suite.hasher())),
            rounds: log_n - 10,
            marker: PhantomData,
        };
        let mut context = Vec::new();
        append_string(&mut context, PROTOCOL_LABEL);
        context.push(P::PROFILE.id());
        for value in [log_n as u64, 1024, 2, 244] {
            context.extend(value.to_le_bytes());
        }
        append_string(&mut context, S::ID.as_bytes());
        append_string(&mut context, ENCODING_ID);
        result.event(1, &context);
        Ok(result)
    }
    fn event(&mut self, tag: u8, payload: &[u8]) {
        self.challenger.observe(tag);
        for byte in (payload.len() as u64)
            .to_le_bytes()
            .into_iter()
            .chain(payload.iter().copied())
        {
            self.challenger.observe(byte);
        }
    }
    pub fn observe_statement(&mut self, root: &Digest, z: P::Base) {
        let mut payload = root.to_vec();
        payload.extend(z.to_canonical_bytes());
        self.event(2, &payload);
    }
    pub fn observe_claim(&mut self, y: P::Base) {
        self.event(3, y.to_canonical_bytes().as_ref());
    }
    pub fn observe_block_values(&mut self, values: &[P::Base]) -> Result<(), TranscriptError> {
        if values.len() != 1024 {
            return Err(TranscriptError::Shape);
        }
        let mut payload = 1024u64.to_le_bytes().to_vec();
        for value in values {
            payload.extend(value.to_canonical_bytes());
        }
        self.event(4, &payload);
        Ok(())
    }
    /// The caller checks the scalar equality before sampling the next challenge.
    pub fn observe_round(
        &mut self,
        j: usize,
        a: P::Challenge,
        b: P::Challenge,
    ) -> Result<(), TranscriptError> {
        if j >= self.rounds {
            return Err(TranscriptError::Shape);
        }
        let mut payload = (j as u64).to_le_bytes().to_vec();
        payload.extend(a.to_canonical_bytes());
        payload.extend(b.to_canonical_bytes());
        self.event(5, &payload);
        Ok(())
    }
    pub fn observe_round_root(&mut self, j: usize, root: &Digest) -> Result<(), TranscriptError> {
        if j >= self.rounds {
            return Err(TranscriptError::Shape);
        }
        let mut payload = (j as u64).to_le_bytes().to_vec();
        payload.extend(root);
        self.event(6, &payload);
        Ok(())
    }
    pub fn observe_terminal(&mut self, constant: P::Challenge, values: [P::Challenge; 2]) {
        let mut payload = Vec::with_capacity(48);
        for value in [constant, values[0], values[1]] {
            payload.extend(value.to_canonical_bytes());
        }
        self.event(7, &payload);
    }
    pub fn sample_base(&mut self) -> P::Base {
        sample_base::<P::Base>(&mut self.challenger)
    }
    pub fn sample_challenge(&mut self) -> P::Challenge {
        P::sample_challenge(&mut self.challenger)
    }
    /// Fresh bytes per index, retaining repetitions and discarding unused high bits.
    pub fn sample_index(&mut self, bits: usize) -> Result<usize, TranscriptError> {
        sample_index(&mut self.challenger, bits)
    }
    pub fn sample_queries(&mut self) -> Vec<usize> {
        (0..244)
            .map(|_| {
                self.sample_index(self.rounds + 1)
                    .expect("validated domain")
            })
            .collect()
    }
}
fn append_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend((value.len() as u64).to_le_bytes());
    out.extend(value);
}
fn sample_index(source: &mut impl CanSample<u8>, bits: usize) -> Result<usize, TranscriptError> {
    if bits > 21 {
        return Err(TranscriptError::IndexBits);
    }
    let mut value = 0usize;
    for i in 0..bits.div_ceil(8) {
        value |= (source.sample() as usize) << (8 * i);
    }
    Ok(value & ((1usize << bits) - 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{KeccakSuite, Sha256Suite};
    use crate::profile::{F128_MODULUS, GOLDILOCKS_MODULUS};
    use p3_field::PrimeCharacteristicRing;
    use p3_symmetric::CryptographicHasher;
    use std::collections::VecDeque;
    struct Bytes(VecDeque<u8>);
    impl CanSample<u8> for Bytes {
        fn sample(&mut self) -> u8 {
            self.0.pop_front().unwrap()
        }
    }
    #[test]
    fn rejection_and_independent_coordinates() {
        let mut bytes = Vec::new();
        bytes.extend((GOLDILOCKS_MODULUS as u64).to_le_bytes());
        bytes.extend(9u64.to_le_bytes());
        bytes.extend(u64::MAX.to_le_bytes());
        bytes.extend(11u64.to_le_bytes());
        let mut source = Bytes(bytes.into());
        let value = GoldilocksProfile::sample_challenge(&mut source);
        let coordinates: &[Goldilocks] = value.as_basis_coefficients_slice();
        assert_eq!(
            coordinates,
            &[Goldilocks::from_u8(9), Goldilocks::from_u8(11)]
        );
        assert!(source.0.is_empty());
        let mut source = Bytes(
            F128_MODULUS
                .to_le_bytes()
                .into_iter()
                .chain(u128::MAX.to_le_bytes())
                .chain(17u128.to_le_bytes())
                .collect(),
        );
        assert_eq!(
            F128Profile::sample_challenge(&mut source),
            F128::from_u8(17)
        );
        assert!(source.0.is_empty());
    }
    #[test]
    fn fresh_index_bytes_and_repetitions() {
        let mut bytes = Bytes([0xff, 0xfe, 0x01, 0x01].into());
        assert_eq!(sample_index(&mut bytes, 9), Ok(255));
        assert_eq!(sample_index(&mut bytes, 1), Ok(1));
        assert_eq!(sample_index(&mut bytes, 1), Ok(1));
        assert!(bytes.0.is_empty());
        assert!(sample_index(&mut bytes, 22).is_err());
    }
    #[test]
    fn context_and_upstream_byte_order() {
        let mut t = Transcript::<GoldilocksProfile, KeccakSuite>::new(11, &KeccakSuite).unwrap();
        let mut context = Vec::new();
        append_string(&mut context, PROTOCOL_LABEL);
        context.push(1);
        for x in [11u64, 1024, 2, 244] {
            context.extend(x.to_le_bytes());
        }
        append_string(&mut context, b"keccak256");
        append_string(&mut context, ENCODING_ID);
        let framed = [2u8, 1]
            .into_iter()
            .chain((context.len() as u64).to_le_bytes())
            .chain(context);
        let digest = KeccakSuite.hasher().hash_iter(framed);
        for expected in digest.into_iter().rev() {
            assert_eq!(t.challenger.sample(), expected);
        }
        // After exhaustion the digest is chained in natural array order.
        let next = KeccakSuite
            .hasher()
            .hash_iter([2].into_iter().chain(digest));
        assert_eq!(t.challenger.sample(), next[31]);
        let mut a = Transcript::<GoldilocksProfile, KeccakSuite>::new(11, &KeccakSuite).unwrap();
        let mut b = Transcript::<GoldilocksProfile, Sha256Suite>::new(11, &Sha256Suite).unwrap();
        assert_ne!(a.sample_challenge(), b.sample_challenge());
    }
    fn replay_all_events<P: FieldProfile, S: HashSuite>(suite: S) {
        let mut transcript = Transcript::<P, S>::new(12, &suite).unwrap();
        let mut reference = HashChallenger::new(Vec::new(), TranscriptHash(suite.hasher()));
        fn observe<H: CryptographicHasher<u8, Digest>>(
            reference: &mut HashChallenger<u8, H, 32>,
            tag: u8,
            payload: Vec<u8>,
        ) {
            for byte in [tag]
                .into_iter()
                .chain((payload.len() as u64).to_le_bytes())
                .chain(payload)
            {
                reference.observe(byte);
            }
        }
        let mut context = Vec::new();
        append_string(&mut context, PROTOCOL_LABEL);
        context.push(P::PROFILE.id());
        for value in [12u64, 1024, 2, 244] {
            context.extend(value.to_le_bytes());
        }
        append_string(&mut context, S::ID.as_bytes());
        append_string(&mut context, ENCODING_ID);
        observe(&mut reference, 1, context);
        let root = [9; 32];
        transcript.observe_statement(&root, P::Base::TWO);
        observe(
            &mut reference,
            2,
            root.into_iter()
                .chain(P::Base::TWO.to_canonical_bytes())
                .collect(),
        );
        transcript.observe_claim(P::Base::ONE);
        observe(
            &mut reference,
            3,
            P::Base::ONE.to_canonical_bytes().into_iter().collect(),
        );
        let blocks: Vec<_> = (0..1024).map(P::Base::from_usize).collect();
        transcript.observe_block_values(&blocks).unwrap();
        observe(
            &mut reference,
            4,
            1024u64
                .to_le_bytes()
                .into_iter()
                .chain(blocks.iter().flat_map(CanonicalField::to_canonical_bytes))
                .collect(),
        );
        for _ in 0..1024 {
            assert_eq!(
                transcript.sample_challenge(),
                P::sample_challenge(&mut reference)
            );
        }
        for j in 0..2 {
            transcript
                .observe_round(j, P::Challenge::ONE, P::Challenge::TWO)
                .unwrap();
            observe(
                &mut reference,
                5,
                (j as u64)
                    .to_le_bytes()
                    .into_iter()
                    .chain(P::Challenge::ONE.to_canonical_bytes())
                    .chain(P::Challenge::TWO.to_canonical_bytes())
                    .collect(),
            );
            assert_eq!(
                transcript.sample_challenge(),
                P::sample_challenge(&mut reference)
            );
            transcript.observe_round_root(j, &root).unwrap();
            observe(
                &mut reference,
                6,
                (j as u64).to_le_bytes().into_iter().chain(root).collect(),
            );
        }
        transcript.observe_terminal(P::Challenge::ONE, [P::Challenge::TWO, P::Challenge::ZERO]);
        observe(
            &mut reference,
            7,
            [P::Challenge::ONE, P::Challenge::TWO, P::Challenge::ZERO]
                .iter()
                .flat_map(CanonicalField::to_canonical_bytes)
                .collect(),
        );
        let expected: Vec<_> = (0..244)
            .map(|_| sample_index(&mut reference, 3).unwrap())
            .collect();
        assert_eq!(transcript.sample_queries(), expected);
    }
    #[test]
    fn complete_event_framing_replays_with_current_upstream() {
        replay_all_events::<GoldilocksProfile, _>(KeccakSuite);
        replay_all_events::<F128Profile, _>(KeccakSuite);
        replay_all_events::<GoldilocksProfile, _>(Sha256Suite);
        replay_all_events::<F128Profile, _>(Sha256Suite);
        replay_all_events::<GoldilocksProfile, _>(crate::hash::Blake3Suite);
        replay_all_events::<F128Profile, _>(crate::hash::Blake3Suite);
    }
    #[test]
    fn events_bind_statement_both_scalars_roots_and_terminal() {
        let t = Transcript::<GoldilocksProfile, KeccakSuite>::new(11, &KeccakSuite).unwrap();
        let root = [3; 32];
        let sample = |mut x: Transcript<GoldilocksProfile, KeccakSuite>| x.sample_challenge();
        let mut a = t.clone();
        a.observe_statement(&root, Goldilocks::ONE);
        let mut b = t.clone();
        b.observe_statement(&root, Goldilocks::TWO);
        assert_ne!(sample(a), sample(b));
        let mut a = t.clone();
        a.observe_claim(Goldilocks::ONE);
        let mut b = t.clone();
        b.observe_claim(Goldilocks::TWO);
        assert_ne!(sample(a), sample(b));
        let mut a = t.clone();
        a.observe_block_values(&vec![Goldilocks::ONE; 1024])
            .unwrap();
        let mut b = t.clone();
        b.observe_block_values(&vec![Goldilocks::TWO; 1024])
            .unwrap();
        assert_ne!(sample(a), sample(b));
        for (aa, bb) in [
            (GoldilocksQuadratic::TWO, GoldilocksQuadratic::ONE),
            (GoldilocksQuadratic::ONE, GoldilocksQuadratic::TWO),
        ] {
            let mut a = t.clone();
            a.observe_round(0, GoldilocksQuadratic::ONE, GoldilocksQuadratic::ONE)
                .unwrap();
            let mut b = t.clone();
            b.observe_round(0, aa, bb).unwrap();
            assert_ne!(sample(a), sample(b));
        }
        let mut a = t.clone();
        a.observe_round_root(0, &root).unwrap();
        let mut b = t.clone();
        b.observe_round_root(0, &[4; 32]).unwrap();
        assert_ne!(sample(a), sample(b));
        let mut a = t.clone();
        a.observe_terminal(GoldilocksQuadratic::ONE, [GoldilocksQuadratic::ONE; 2]);
        let mut b = t.clone();
        b.observe_terminal(GoldilocksQuadratic::TWO, [GoldilocksQuadratic::ONE; 2]);
        assert_ne!(a.sample_queries(), b.sample_queries());
        assert_eq!(a.sample_queries().len(), 244);
        assert!(a.observe_block_values(&[]).is_err());
        assert!(
            a.observe_round(1, GoldilocksQuadratic::ZERO, GoldilocksQuadratic::ZERO)
                .is_err()
        );
    }
}
