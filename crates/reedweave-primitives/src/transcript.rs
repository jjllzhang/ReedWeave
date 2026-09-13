//! Sequential byte challenger and locally constructed protocol context.
use crate::fields::{
    CanonicalField, Goldilocks, GoldilocksCubic, GoldilocksQuadratic, GoldilocksQuintic,
};
use crate::hash::{Digest, HASH_ID, TranscriptHash};
use crate::profile::{BaseField, Profile};
use core::marker::PhantomData;
use p3_challenger::{CanObserve, CanSample, HashChallenger};
use p3_field::{BasedVectorSpace, ExtensionField, TwoAdicField};
use p3_symmetric::CryptographicHasher;
use thiserror::Error;

pub const PROTOCOL_LABEL: &[u8] = b"ReedWeave-Section3-Multiproof";
pub const ENCODING_ID: &[u8] = b"canonical-coordinates-multiproof";

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
macro_rules! profile {
    ($name:ident, $challenge:ty, $variant:ident) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;
        impl sealed::Sealed for $name {}
        impl FieldProfile for $name {
            type Base = Goldilocks;
            type Challenge = $challenge;
            const PROFILE: Profile = Profile::$variant;
            fn sample_challenge(source: &mut impl CanSample<u8>) -> Self::Challenge {
                Self::Challenge::from_basis_coefficients_fn(|_| sample_base(source))
            }
        }
    };
}
profile!(GoldilocksBaseProfile, Goldilocks, GoldilocksBase);
profile!(
    GoldilocksQuadraticProfile,
    GoldilocksQuadratic,
    GoldilocksQuadratic
);
profile!(GoldilocksCubicProfile, GoldilocksCubic, GoldilocksCubic);
profile!(
    GoldilocksQuinticProfile,
    GoldilocksQuintic,
    GoldilocksQuintic
);
pub type GoldilocksProfile = GoldilocksQuadraticProfile;

/// Independent primitive context; core supplies this from validated public parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranscriptContext {
    pub base_field: BaseField,
    pub extension_degree: usize,
    pub log_d: usize,
    pub m: usize,
    pub blowup: usize,
    pub terminal_coefficients: usize,
    pub num_queries: usize,
}
impl TranscriptContext {
    fn geometry(&self) -> Result<(usize, usize), TranscriptError> {
        let bad = TranscriptError::UnsupportedSize;
        let d = 1usize
            .checked_shl(u32::try_from(self.log_d).map_err(|_| bad)?)
            .ok_or(bad)?;
        if self.m == 0 || !d.is_multiple_of(self.m) || self.num_queries == 0 {
            return Err(bad);
        }
        let k = d / self.m;
        if k < 2
            || !k.is_power_of_two()
            || self.blowup < 2
            || !self.blowup.is_power_of_two()
            || !self.terminal_coefficients.is_power_of_two()
            || self.terminal_coefficients > k / 2
        {
            return Err(bad);
        }
        let n = k.checked_mul(self.blowup).ok_or(bad)?;
        if n.ilog2() > 32 || Profile::from_degree(self.extension_degree).is_none() {
            return Err(bad);
        }
        self.num_queries.checked_mul(2).ok_or(bad)?;
        Ok((
            (k / self.terminal_coefficients).ilog2() as usize,
            n.ilog2() as usize,
        ))
    }
    fn canonical_bytes(&self) -> Result<Vec<u8>, TranscriptError> {
        self.geometry()?;
        let mut context = Vec::new();
        append_string(&mut context, PROTOCOL_LABEL);
        append_string(&mut context, self.base_field.to_string().as_bytes());
        append_string(
            &mut context,
            Profile::from_degree(self.extension_degree)
                .ok_or(TranscriptError::UnsupportedSize)?
                .representation(),
        );
        for value in [
            self.extension_degree,
            self.log_d,
            self.m,
            self.blowup,
            self.terminal_coefficients,
            self.num_queries,
        ] {
            context.extend(
                u64::try_from(value)
                    .map_err(|_| TranscriptError::UnsupportedSize)?
                    .to_le_bytes(),
            );
        }
        append_string(&mut context, HASH_ID.as_bytes());
        append_string(&mut context, ENCODING_ID);
        Ok(context)
    }
    /// Trusted-context fingerprint carried in proofs for strict cross-instance rejection,
    /// including degenerate polynomials whose authenticated query sets coincide.
    pub fn identifier(&self) -> Result<Digest, TranscriptError> {
        Ok(TranscriptHash.hash_slice(&self.canonical_bytes()?))
    }
}

/// Rejection sampling for a canonical base element; never modular reduction.
fn sample_base(source: &mut impl CanSample<u8>) -> Goldilocks {
    loop {
        let mut bytes = [0u8; 8];
        for byte in &mut bytes {
            *byte = source.sample();
        }
        if let Ok(value) = Goldilocks::from_canonical_bytes(&bytes) {
            return value;
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum TranscriptError {
    #[error("invalid transcript geometry or profile")]
    UnsupportedSize,
    #[error("transcript payload has the wrong shape")]
    Shape,
    #[error("index sampling requires at most 32 addressable bits")]
    IndexBits,
}

#[derive(Clone)]
pub struct Transcript<P: FieldProfile> {
    challenger: HashChallenger<u8, TranscriptHash, 32>,
    rounds: usize,
    context: TranscriptContext,
    log_domain_size: usize,
    marker: PhantomData<P>,
}

impl<P: FieldProfile> Transcript<P> {
    pub fn new(context: TranscriptContext) -> Result<Self, TranscriptError> {
        let (rounds, log_domain_size) = context.geometry()?;
        if context.extension_degree != P::PROFILE.extension_degree() {
            return Err(TranscriptError::UnsupportedSize);
        }
        let bytes = context.canonical_bytes()?;
        let mut result = Self {
            challenger: HashChallenger::new(Vec::new(), TranscriptHash),
            rounds,
            log_domain_size,
            context,
            marker: PhantomData,
        };
        result.event(1, &bytes);
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
        if values.len() != self.context.m {
            return Err(TranscriptError::Shape);
        }
        let mut payload = (self.context.m as u64).to_le_bytes().to_vec();
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
    pub fn observe_terminal(
        &mut self,
        coefficients: &[P::Challenge],
    ) -> Result<(), TranscriptError> {
        if coefficients.len() != self.context.terminal_coefficients {
            return Err(TranscriptError::Shape);
        }
        let mut payload = (coefficients.len() as u64).to_le_bytes().to_vec();
        for value in coefficients {
            payload.extend(value.to_canonical_bytes());
        }
        self.event(7, &payload);
        Ok(())
    }
    pub fn sample_challenge(&mut self) -> P::Challenge {
        P::sample_challenge(&mut self.challenger)
    }
    /// Fresh bytes per index, retaining repetitions and discarding unused high bits.
    pub fn sample_index(&mut self, bits: usize) -> Result<usize, TranscriptError> {
        sample_index(&mut self.challenger, bits)
    }
    pub fn sample_queries(&mut self) -> Vec<usize> {
        (0..self.context.num_queries)
            .map(|_| {
                self.sample_index(self.log_domain_size)
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
    if bits > 32 || bits >= usize::BITS as usize {
        return Err(TranscriptError::IndexBits);
    }
    let mut value = 0usize;
    for i in 0..bits.div_ceil(8) {
        value |= (source.sample() as usize) << (8 * i);
    }
    Ok(value & ((1usize << bits) - 1))
}

#[cfg(test)]
#[path = "transcript_tests.rs"]
mod tests;
