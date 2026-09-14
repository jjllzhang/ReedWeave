//! ReedWeave_UB: standalone coefficient-input unique-decoding PCS. Typed proofs contain protocol messages
//! and a 32-byte trusted-context digest identifying the protocol and parameters.
use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};
use p3_matrix::{Dimensions, dense::RowMajorMatrix};
use reedweave_primitives::{
    dft::{DftError, NaturalOrderDft, padded_coefficient_blocks},
    hash::Digest,
    mmcs::{CanonicalMmcs, LeafKind, MatrixOpening, MatrixProverData, MmcsError, MultiProof},
    polynomial::{combine_rows, evaluate_interleaved},
    transcript::{FieldProfile, Transcript, TranscriptError},
};
use reedweave_runtime::ExecutionContext;
use thiserror::Error;

use crate::UbParams;

#[cfg(test)]
#[path = "pcs_tests.rs"]
mod tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment {
    pub root: Digest,
}

#[derive(Clone, Debug)]
pub struct Round<K> {
    pub even_value: K,
    pub odd_value: K,
}

#[derive(Clone, Debug)]
pub struct ScalarOpening<K> {
    pub values: Vec<K>,
    pub proof: MultiProof,
}

#[derive(Clone, Debug)]
pub struct UbProof<P: FieldProfile> {
    /// Fingerprint of the complete trusted public context.
    pub context_id: Digest,
    pub block_values: Vec<P::Base>,
    pub rounds: Vec<Round<P::Challenge>>,
    /// Roots of pi_1 through pi_(t-1); pi_0 and pi_t are virtual.
    pub oracle_roots: Vec<Digest>,
    /// Ascending coefficients, padded to the public terminal degree bound.
    pub terminal_coefficients: Vec<P::Challenge>,
    pub initial_opening: MatrixOpening<P::Base>,
    pub scalar_openings: Vec<ScalarOpening<P::Challenge>>,
}

#[derive(Clone, Debug)]
pub struct Opening<P: FieldProfile> {
    /// Public claim, supplied separately to verification; not part of `UbProof`.
    pub y: P::Base,
    pub proof: UbProof<P>,
}

/// Immutable commitment state, reusable for arbitrary subsequent evaluation points.
/// The MMCS owns the only retained encoding; coefficients are moved here by commit.
pub struct ProverData<P: FieldProfile> {
    params: UbParams,
    coefficients: Vec<P::Base>,
    initial: MatrixProverData<P::Base>,
    commitment: Commitment,
}

impl<P: FieldProfile> ProverData<P> {
    pub fn commitment(&self) -> Commitment {
        self.commitment
    }

    pub fn coefficients(&self) -> &[P::Base] {
        &self.coefficients
    }

    /// Natural-order N-by-m table: each matrix row is one oracle column.
    pub fn encoded_word(&self) -> &RowMajorMatrix<P::Base> {
        self.initial.matrix()
    }
}

#[derive(Debug, Error)]
pub enum PcsError {
    #[error("parameter profile does not match the selected field types")]
    ProfileMismatch,
    #[error("prover state belongs to different parameters or suite")]
    StateMismatch,
    #[error("expected {expected} coefficients, received {actual}")]
    CoefficientCount { expected: usize, actual: usize },
    #[error("invalid proof shape: {0}")]
    Shape(&'static str),
    #[error("block claims do not reconstruct the public claim")]
    Claim,
    #[error("round {0} scalar identity failed")]
    Scalar(usize),
    #[error("terminal polynomial and evaluation disagree")]
    Terminal,
    #[error("full opening word does not match the commitment root")]
    OpeningRoot,
    #[error("full opening exceeds the strict unique-decoding column radius")]
    OpeningDistance,
    #[error("local fold failed at query {query}, round {round}")]
    Fold { query: usize, round: usize },
    #[error(transparent)]
    Dft(#[from] DftError),
    #[error(transparent)]
    Mmcs(#[from] MmcsError),
    #[error(transparent)]
    Transcript(#[from] TranscriptError),
}

/// Trusted configuration. Hashing is fixed to Blake3 and never proof-controlled.
pub struct ReedWeaveUb<P: FieldProfile> {
    params: UbParams,
    dft: NaturalOrderDft<P::Base>,
    initial_mmcs: CanonicalMmcs<P::Base>,
    scalar_mmcs: CanonicalMmcs<P::Challenge>,
}

impl<P: FieldProfile> ReedWeaveUb<P> {
    pub fn new(params: UbParams) -> Result<Self, PcsError> {
        if params.profile() != P::PROFILE {
            return Err(PcsError::ProfileMismatch);
        }
        Ok(Self {
            initial_mmcs: CanonicalMmcs::new(LeafKind::Base, params.m())?,
            scalar_mmcs: CanonicalMmcs::new(LeafKind::Challenge, 1)?,
            params,
            dft: NaturalOrderDft::default(),
        })
    }

    pub fn params(&self) -> &UbParams {
        &self.params
    }

    pub fn commit(
        &self,
        mut coefficients: Vec<P::Base>,
        execution: &ExecutionContext,
    ) -> Result<(Commitment, ProverData<P>), PcsError> {
        if coefficients.len() > self.params.d() {
            return Err(PcsError::CoefficientCount {
                expected: self.params.d(),
                actual: coefficients.len(),
            });
        }
        coefficients.resize(self.params.d(), P::Base::ZERO);
        let padded = padded_coefficient_blocks(
            &coefficients,
            self.params.m(),
            self.params.k(),
            self.params.domain_size(),
        )?;
        let matrix = self.dft.dft_batch(padded, execution)?;
        let (root, initial) = self.initial_mmcs.commit(matrix, execution)?;
        let commitment = Commitment { root };
        Ok((
            commitment,
            ProverData {
                params: self.params.clone(),
                coefficients,
                initial,
                commitment,
            },
        ))
    }

    /// Check the complete decoded opening, not an evaluation proof.
    /// The supplied word may differ from the encoding in at most floor((N-k)/2)
    /// columns. Rows of this N-by-m matrix represent whole oracle columns.
    pub fn open_base(
        &self,
        commitment: &Commitment,
        coefficients: &[P::Base],
        word: &RowMajorMatrix<P::Base>,
        execution: &ExecutionContext,
    ) -> Result<(), PcsError> {
        if coefficients.len() > self.params.d() {
            return Err(PcsError::CoefficientCount {
                expected: self.params.d(),
                actual: coefficients.len(),
            });
        }
        if word.width != self.params.m()
            || word.values.len() != self.params.domain_size() * self.params.m()
        {
            return Err(PcsError::Shape("full opening word"));
        }
        let (root, _) = self.initial_mmcs.commit(word.clone(), execution)?;
        if root != commitment.root {
            return Err(PcsError::OpeningRoot);
        }
        let padded = padded_coefficient_blocks(
            coefficients,
            self.params.m(),
            self.params.k(),
            self.params.domain_size(),
        )?;
        let expected = self.dft.dft_batch(padded, execution)?;
        let errors = word
            .values
            .chunks_exact(self.params.m())
            .zip(expected.values.chunks_exact(self.params.m()))
            .filter(|(actual, expected)| actual != expected)
            .count();
        // Equivalent to 2*errors < N-k+1, without multiplication overflow.
        if errors > (self.params.domain_size() - self.params.k()) / 2 {
            return Err(PcsError::OpeningDistance);
        }
        Ok(())
    }

    pub fn prove(
        &self,
        state: &ProverData<P>,
        z: P::Base,
        execution: &ExecutionContext,
    ) -> Result<Opening<P>, PcsError> {
        if state.params != self.params {
            return Err(PcsError::StateMismatch);
        }
        let z0 = z.exp_u64(self.params.m() as u64);
        let blocks = evaluate_interleaved(&state.coefficients, self.params.m(), z0, execution);
        let y = reconstruct(&blocks, z);
        let mut transcript = self.start(&state.commitment, z, y, &blocks)?;
        let weights = power_weights(transcript.sample_challenge(), self.params.m());
        let mut coefficients = combine_rows(&state.coefficients, &weights, execution);
        let mut initial_word = (self.params.rounds() > 1)
            .then(|| combine_rows(&state.initial.matrix().values, &weights, execution));
        let mut layers: Vec<MatrixProverData<P::Challenge>> =
            Vec::with_capacity(self.params.rounds() - 1);
        let mut rounds = Vec::with_capacity(self.params.rounds());
        let mut oracle_roots = Vec::with_capacity(self.params.rounds() - 1);
        let mut point = z.exp_u64(self.params.m() as u64);
        let mut claim = combine::<P>(&blocks, &weights);
        let mut omega = P::Base::two_adic_generator(self.params.log_domain_size());
        for j in 0..self.params.rounds() {
            let square = point.square();
            let even_value = horner(
                coefficients.iter().step_by(2).copied(),
                P::Challenge::from(square),
            );
            let odd_value = horner(
                coefficients.iter().skip(1).step_by(2).copied(),
                P::Challenge::from(square),
            );
            transcript.observe_round(j, even_value, odd_value)?;
            if claim != even_value + odd_value * point {
                return Err(PcsError::Scalar(j));
            }
            let gamma = transcript.sample_challenge();
            coefficients = fold_coefficients(&coefficients, gamma);
            if j + 1 < self.params.rounds() {
                let word = if j == 0 {
                    initial_word
                        .as_deref()
                        .ok_or(PcsError::Shape("initial word"))?
                } else {
                    &layers[j - 1].matrix().values
                };
                let folded = fold_word::<P>(word, gamma, omega);
                let (root, layer) = self
                    .scalar_mmcs
                    .commit(RowMajorMatrix::new_col(folded), execution)?;
                transcript.observe_round_root(j, &root)?;
                oracle_roots.push(root);
                layers.push(layer);
            }
            initial_word = None;
            rounds.push(Round {
                even_value,
                odd_value,
            });
            claim = even_value + gamma * odd_value;
            point = square;
            omega = omega.square();
        }
        let terminal_coefficients = coefficients;
        if horner(
            terminal_coefficients.iter().copied(),
            P::Challenge::from(point),
        ) != claim
        {
            return Err(PcsError::Terminal);
        }
        transcript.observe_terminal(&terminal_coefficients)?;
        let starts = transcript.sample_queries();
        let sets = query_sets(&self.params, &starts);
        let initial_opening = self
            .initial_mmcs
            .open_multi_batch(&sets[0], &state.initial)?;
        let mut scalar_openings = Vec::with_capacity(self.params.rounds() - 1);
        for j in 1..self.params.rounds() {
            let opening = self
                .scalar_mmcs
                .open_multi_batch(&sets[j], &layers[j - 1])?;
            let values = opening
                .rows
                .into_iter()
                .map(|row| {
                    if row.len() != 1 {
                        return Err(PcsError::Shape("scalar MMCS row"));
                    }
                    Ok(row[0])
                })
                .collect::<Result<_, _>>()?;
            scalar_openings.push(ScalarOpening {
                values,
                proof: opening.proof,
            });
        }
        Ok(Opening {
            y,
            proof: UbProof {
                context_id: self.params.transcript_context().identifier()?,
                block_values: blocks,
                rounds,
                oracle_roots,
                terminal_coefficients,
                initial_opening,
                scalar_openings,
            },
        })
    }

    /// Verify an intended public statement using only authenticated queried rows.
    /// This does not require an exact codeword: it checks the decoded-opening relation.
    pub fn verify(
        &self,
        commitment: &Commitment,
        z: P::Base,
        y: P::Base,
        proof: &UbProof<P>,
        execution: &ExecutionContext,
    ) -> Result<(), PcsError> {
        self.validate_shape(proof)?;
        let mut transcript = self.start(commitment, z, y, &proof.block_values)?;
        let weights = power_weights(transcript.sample_challenge(), self.params.m());
        let mut claim = combine::<P>(&proof.block_values, &weights);
        let mut point = z.exp_u64(self.params.m() as u64);
        let mut gammas = Vec::with_capacity(self.params.rounds());
        for (j, round) in proof.rounds.iter().enumerate() {
            transcript.observe_round(j, round.even_value, round.odd_value)?;
            if claim != round.even_value + round.odd_value * point {
                return Err(PcsError::Scalar(j));
            }
            let gamma = transcript.sample_challenge();
            gammas.push(gamma);
            if j + 1 < self.params.rounds() {
                transcript.observe_round_root(j, &proof.oracle_roots[j])?;
            }
            claim = round.even_value + gamma * round.odd_value;
            point = point.square();
        }
        if horner(
            proof.terminal_coefficients.iter().copied(),
            P::Challenge::from(point),
        ) != claim
        {
            return Err(PcsError::Terminal);
        }
        transcript.observe_terminal(&proof.terminal_coefficients)?;
        let starts = transcript.sample_queries();
        let sets = query_sets(&self.params, &starts);
        // Validate all exact counts before any large authentication work.
        if proof.initial_opening.rows.len() != sets[0].len()
            || proof
                .scalar_openings
                .iter()
                .zip(&sets[1..])
                .any(|(opening, set)| opening.values.len() != set.len())
        {
            return Err(PcsError::Shape("derived opening count"));
        }
        // The wide initial tree is one indivisible upstream authentication job.
        // Require at least 256 scalar leaves across the other trees before paying
        // for coarse scheduling alongside it. This is a conservative work heuristic,
        // not a measured crossover; small proofs use the same pool sequentially.
        let scalar_leaves: usize = sets[1..].iter().map(Vec::len).sum();
        execution.try_for_each_tree(self.params.rounds(), scalar_leaves >= 256, |tree| {
            if tree == 0 {
                return self.initial_mmcs.verify_multi_batch(
                    &commitment.root,
                    Dimensions {
                        width: self.params.m(),
                        height: self.params.domain_size(),
                    },
                    &sets[0],
                    &proof.initial_opening.rows,
                    &proof.initial_opening.proof,
                );
            }
            let opening = &proof.scalar_openings[tree - 1];
            // Width-one array views borrow the flat proof buffer without copying fields
            // or allocating a singleton field vector per authenticated value.
            let (rows, _) = opening.values.as_chunks::<1>();
            self.scalar_mmcs.verify_multi_batch(
                &proof.oracle_roots[tree - 1],
                Dimensions {
                    width: 1,
                    height: self.params.domain_size() >> tree,
                },
                &sets[tree],
                rows,
                &opening.proof,
            )
        })?;
        let initial: Vec<_> = proof
            .initial_opening
            .rows
            .iter()
            .map(|row| combine::<P>(row, &weights))
            .collect();
        let words: Vec<&[P::Challenge]> = std::iter::once(initial.as_slice())
            .chain(
                proof
                    .scalar_openings
                    .iter()
                    .map(|opening| opening.values.as_slice()),
            )
            .collect();
        let inverse_two = P::Base::TWO.inverse();
        let omega = P::Base::two_adic_generator(self.params.log_domain_size());
        let inverse_omega = omega.inverse();
        let terminal_omega = omega.exp_power_of_2(self.params.rounds());
        for (query, &start) in starts.iter().enumerate() {
            // This is the inverse of the actual signed point, even in the upper half.
            let mut inverse_point = inverse_omega.exp_u64(start as u64);
            for j in 0..self.params.rounds() {
                let height = self.params.domain_size() >> j;
                let t = start % height;
                let at = |index| -> Result<P::Challenge, PcsError> {
                    let position = sets[j]
                        .binary_search(&index)
                        .map_err(|_| PcsError::Shape("query lookup"))?;
                    Ok(words[j][position])
                };
                let positive = at(t)?;
                let negative = at(t ^ (height / 2))?;
                let folded = (positive + negative) * inverse_two
                    + gammas[j] * (positive - negative) * (inverse_two * inverse_point);
                let child = t % (height / 2);
                let expected = if j + 1 == self.params.rounds() {
                    horner(
                        proof.terminal_coefficients.iter().copied(),
                        P::Challenge::from(terminal_omega.exp_u64(child as u64)),
                    )
                } else {
                    let position = sets[j + 1]
                        .binary_search(&child)
                        .map_err(|_| PcsError::Shape("child lookup"))?;
                    words[j + 1][position]
                };
                if folded != expected {
                    return Err(PcsError::Fold { query, round: j });
                }
                inverse_point = inverse_point.square();
            }
        }
        Ok(())
    }

    fn start(
        &self,
        commitment: &Commitment,
        z: P::Base,
        y: P::Base,
        blocks: &[P::Base],
    ) -> Result<Transcript<P>, PcsError> {
        let mut transcript = Transcript::new(self.params.transcript_context())?;
        transcript.observe_statement(&commitment.root, z);
        transcript.observe_claim(y);
        transcript.observe_block_values(blocks)?;
        if reconstruct(blocks, z) != y {
            return Err(PcsError::Claim);
        }
        Ok(transcript)
    }

    /// Public-geometry bounds for typed callers, independently of future byte decoding.
    pub fn validate_shape(&self, proof: &UbProof<P>) -> Result<(), PcsError> {
        validate_proof_shape(&self.params, proof)
    }
}

/// Bounds shared by typed verification and the parameter-aware byte parser.
pub(crate) fn opening_bounds(params: &UbParams, j: usize) -> Result<(usize, usize), PcsError> {
    let height = params.layer_size(j).ok_or(PcsError::Shape("layer"))?;
    let depth = params
        .log_domain_size()
        .checked_sub(j)
        .ok_or(PcsError::Shape("depth"))?;
    let count = params
        .num_queries()
        .checked_mul(2)
        .ok_or(PcsError::Shape("query bound"))?
        .min(height);
    Ok((count, depth))
}

pub(crate) fn boundary_bound(count: usize, depth: usize) -> Result<usize, PcsError> {
    count
        .checked_mul(depth)
        .ok_or(PcsError::Shape("boundary bound"))
}

pub(crate) fn validate_proof_shape<P: FieldProfile>(
    params: &UbParams,
    proof: &UbProof<P>,
) -> Result<(), PcsError> {
    if params.profile() != P::PROFILE {
        return Err(PcsError::ProfileMismatch);
    }
    if proof.context_id != params.transcript_context().identifier()? {
        return Err(PcsError::StateMismatch);
    }
    if proof.block_values.len() != params.m()
        || proof.terminal_coefficients.len() != params.terminal_coefficient_count()
        || proof.rounds.len() != params.rounds()
        || proof.oracle_roots.len() != params.rounds() - 1
        || proof.scalar_openings.len() != params.rounds() - 1
    {
        return Err(PcsError::Shape("prefix or layer count"));
    }
    let bounded = |j, count, nodes| -> Result<bool, PcsError> {
        let (maximum, depth) = opening_bounds(params, j)?;
        Ok(count > 0 && count <= maximum && nodes <= boundary_bound(count, depth)?)
    };
    if !bounded(
        0,
        proof.initial_opening.rows.len(),
        proof.initial_opening.proof.sibling_hashes.len(),
    )? || proof
        .initial_opening
        .rows
        .iter()
        .any(|row| row.len() != params.m())
    {
        return Err(PcsError::Shape("initial opening"));
    }
    for (j, opening) in proof.scalar_openings.iter().enumerate() {
        if !bounded(
            j + 1,
            opening.values.len(),
            opening.proof.sibling_hashes.len(),
        )? {
            return Err(PcsError::Shape("scalar opening"));
        }
    }
    Ok(())
}

fn horner<F: Field>(coefficients: impl DoubleEndedIterator<Item = F>, point: F) -> F {
    coefficients
        .rev()
        .fold(F::ZERO, |value, coefficient| value * point + coefficient)
}
fn reconstruct<F: Field>(blocks: &[F], z: F) -> F {
    let mut weight = F::ONE;
    let mut y = F::ZERO;
    for &value in blocks {
        y += weight * value;
        weight *= z;
    }
    y
}
fn combine<P: FieldProfile>(values: &[P::Base], weights: &[P::Challenge]) -> P::Challenge {
    values
        .iter()
        .zip(weights)
        .map(|(&value, &weight)| weight * value)
        .sum()
}
fn fold_coefficients<K: Field>(coefficients: &[K], gamma: K) -> Vec<K> {
    coefficients
        .chunks_exact(2)
        .map(|pair| pair[0] + gamma * pair[1])
        .collect()
}
fn fold_word<P: FieldProfile>(
    word: &[P::Challenge],
    gamma: P::Challenge,
    omega: P::Base,
) -> Vec<P::Challenge> {
    let half = word.len() / 2;
    let inverse_omega = omega.inverse();
    let inverse_two = P::Base::TWO.inverse();
    let mut inverse_power = P::Base::ONE;
    let mut result = Vec::with_capacity(half);
    for t in 0..half {
        result.push(
            (word[t] + word[t + half]) * inverse_two
                + gamma * (word[t] - word[t + half]) * (inverse_two * inverse_power),
        );
        inverse_power *= inverse_omega;
    }
    result
}

/// The ordered experiment is preserved in `starts`; only per-tree leaf indices are deduplicated.
/// These sets are derived locally and are never transmitted. Binary search in each sorted
/// set is the index-to-opening lookup, bounded by at most 2 * Q entries.
fn query_sets(params: &UbParams, starts: &[usize]) -> Vec<Vec<usize>> {
    (0..params.rounds())
        .map(|j| {
            let height = params.domain_size() >> j;
            let mut set: Vec<_> = starts
                .iter()
                .flat_map(|start| {
                    let t = start % height;
                    [t, t ^ (height / 2)]
                })
                .collect();
            set.sort_unstable();
            set.dedup();
            set
        })
        .collect()
}

fn power_weights<K: Field>(alpha: K, count: usize) -> Vec<K> {
    let mut power = K::ONE;
    (0..count)
        .map(|_| {
            let result = power;
            power *= alpha;
            result
        })
        .collect()
}
