//! Independent ReedWeave_JB commit/eval transcript domains and event schedule.
//! Commit binds pp and root before sampling uniformly in K \\ L0. Eval binds the
//! complete commitment and claim before alpha, all four round values before
//! gamma, and intermediate roots and terminal coefficients before queries.
use crate::{JbCommitment, JbParams, PublicParams};
use core::marker::PhantomData;
use p3_challenger::{CanObserve, CanSample, HashChallenger};
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::CryptographicHasher;
pub use reedweave_primitives::transcript::TranscriptError;
use reedweave_primitives::{
    fields::CanonicalField,
    hash::{Digest, HASH_ID, TranscriptHash},
    profile::{BaseField, Profile},
    transcript::FieldProfile,
};

pub const COMMIT_LABEL: &[u8] = b"ReedWeave_JB-Commit-Multiproof-v1";
pub const EVAL_LABEL: &[u8] = b"ReedWeave_JB-Eval-Multiproof-v1";
pub const ENCODING_ID: &[u8] = b"canonical-coordinates-jb-multiproof-v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranscriptContext {
    pub base_field: BaseField,
    pub extension_degree: usize,
    pub log_d: usize,
    pub m: usize,
    pub blowup: usize,
    pub terminal_coefficients: usize,
    pub num_queries: usize,
    pub agreement_numerator: u32,
    pub agreement_denominator: u32,
}
impl TranscriptContext {
    fn params(&self) -> Result<JbParams, TranscriptError> {
        let params = JbParams::new(PublicParams {
            base_field: self.base_field,
            extension_degree: self.extension_degree,
            log_d: self.log_d,
            m: self.m,
            blowup: self.blowup,
            terminal_coefficients: self.terminal_coefficients,
            num_queries: self.num_queries,
            agreement_numerator: self.agreement_numerator,
            agreement_denominator: self.agreement_denominator,
        })
        .map_err(|_| TranscriptError::UnsupportedSize)?;
        // Directly constructed contexts must also use the unique canonical radius.
        if params.agreement_numerator() != self.agreement_numerator
            || params.agreement_denominator() != self.agreement_denominator
        {
            return Err(TranscriptError::UnsupportedSize);
        }
        Ok(params)
    }
    fn canonical_bytes(&self) -> Result<Vec<u8>, TranscriptError> {
        self.params()?;
        let mut out = Vec::new();
        append_string(&mut out, COMMIT_LABEL);
        append_string(&mut out, EVAL_LABEL);
        append_string(&mut out, self.base_field.to_string().as_bytes());
        append_string(
            &mut out,
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
            out.extend(
                u64::try_from(value)
                    .map_err(|_| TranscriptError::UnsupportedSize)?
                    .to_le_bytes(),
            );
        }
        out.extend(self.agreement_numerator.to_le_bytes());
        out.extend(self.agreement_denominator.to_le_bytes());
        append_string(&mut out, HASH_ID.as_bytes());
        append_string(&mut out, ENCODING_ID);
        Ok(out)
    }
    pub fn identifier(&self) -> Result<Digest, TranscriptError> {
        Ok(TranscriptHash.hash_slice(&self.canonical_bytes()?))
    }
}

type Challenger = HashChallenger<u8, TranscriptHash, 32>;
fn event(challenger: &mut Challenger, tag: u8, payload: &[u8]) {
    challenger.observe(tag);
    for byte in (payload.len() as u64)
        .to_le_bytes()
        .into_iter()
        .chain(payload.iter().copied())
    {
        challenger.observe(byte);
    }
}
fn start<P: FieldProfile>(
    context: &TranscriptContext,
    label: &[u8],
) -> Result<Challenger, TranscriptError> {
    if context.extension_degree != P::PROFILE.extension_degree() {
        return Err(TranscriptError::UnsupportedSize);
    }
    let mut challenger = Challenger::new(Vec::new(), TranscriptHash);
    event(&mut challenger, 0, label);
    event(&mut challenger, 1, &context.canonical_bytes()?);
    Ok(challenger)
}

/// No prover-selected retry count and no truncation: each rejection consumes fresh
/// canonical-coordinate samples. Zero and base-field OOD elements remain legal.
fn sample_ood<P: FieldProfile>(
    source: &mut impl CanSample<u8>,
    domain_size: usize,
) -> P::Challenge {
    loop {
        let zeta = P::sample_challenge(source);
        if zeta.exp_u64(domain_size as u64) != P::Challenge::ONE {
            return zeta;
        }
    }
}
pub(crate) fn commit_challenge<P: FieldProfile>(
    context: TranscriptContext,
    root: &Digest,
) -> Result<P::Challenge, TranscriptError> {
    let domain_size = context.params()?.domain_size();
    let mut challenger = start::<P>(&context, COMMIT_LABEL)?;
    event(&mut challenger, 2, root);
    Ok(sample_ood::<P>(&mut challenger, domain_size))
}

#[derive(Clone)]
pub(crate) struct Transcript<P: FieldProfile> {
    challenger: Challenger,
    rounds: usize,
    context: TranscriptContext,
    log_domain_size: usize,
    marker: PhantomData<P>,
}
impl<P: FieldProfile> Transcript<P> {
    pub fn new(context: TranscriptContext) -> Result<Self, TranscriptError> {
        let params = context.params()?;
        Ok(Self {
            challenger: start::<P>(&context, EVAL_LABEL)?,
            rounds: params.rounds(),
            log_domain_size: params.log_domain_size(),
            context,
            marker: PhantomData,
        })
    }
    pub fn observe_statement(
        &mut self,
        commitment: &JbCommitment<P>,
        z: P::Base,
        y: P::Base,
    ) -> Result<(), TranscriptError> {
        if commitment.deep_values.len() != self.context.m {
            return Err(TranscriptError::Shape);
        }
        let mut payload = commitment.context_id.to_vec();
        payload.extend(commitment.root);
        payload.extend(commitment.zeta.to_canonical_bytes());
        payload.extend((commitment.deep_values.len() as u64).to_le_bytes());
        for c in &commitment.deep_values {
            payload.extend(c.to_canonical_bytes());
        }
        payload.extend(z.to_canonical_bytes());
        payload.extend(y.to_canonical_bytes());
        event(&mut self.challenger, 2, &payload);
        Ok(())
    }
    pub fn observe_block_values(&mut self, values: &[P::Base]) -> Result<(), TranscriptError> {
        if values.len() != self.context.m {
            return Err(TranscriptError::Shape);
        }
        let mut payload = (values.len() as u64).to_le_bytes().to_vec();
        for value in values {
            payload.extend(value.to_canonical_bytes());
        }
        event(&mut self.challenger, 4, &payload);
        Ok(())
    }
    pub fn observe_round(
        &mut self,
        j: usize,
        a: P::Challenge,
        b: P::Challenge,
        deep_a: P::Challenge,
        deep_b: P::Challenge,
    ) -> Result<(), TranscriptError> {
        if j >= self.rounds {
            return Err(TranscriptError::Shape);
        }
        let mut payload = (j as u64).to_le_bytes().to_vec();
        for value in [a, b, deep_a, deep_b] {
            payload.extend(value.to_canonical_bytes());
        }
        event(&mut self.challenger, 5, &payload);
        Ok(())
    }
    pub fn observe_round_root(&mut self, j: usize, root: &Digest) -> Result<(), TranscriptError> {
        if j >= self.rounds - 1 {
            return Err(TranscriptError::Shape);
        }
        let mut payload = (j as u64).to_le_bytes().to_vec();
        payload.extend(root);
        event(&mut self.challenger, 6, &payload);
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
        event(&mut self.challenger, 7, &payload);
        Ok(())
    }
    pub fn sample_challenge(&mut self) -> P::Challenge {
        P::sample_challenge(&mut self.challenger)
    }
    pub fn sample_queries(&mut self) -> Vec<usize> {
        (0..self.context.num_queries)
            .map(|_| {
                sample_index(&mut self.challenger, self.log_domain_size).expect("validated domain")
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
