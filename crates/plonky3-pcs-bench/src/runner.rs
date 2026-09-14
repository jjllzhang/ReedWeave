use crate::{
    Result,
    config::{Case, Field, Protocol, Settings},
    crypto::Challenger,
    output::{self, Trial},
    params::{self, Audit},
    resources,
};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::Pcs;
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{
    ExtensionField, TwoAdicField, coset::TwoAdicMultiplicativeCoset,
    extension::CubicTrinomialExtensionField,
};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use reedweave_primitives::fields::{CanonicalField, Goldilocks};
use reedweave_runtime::ExecutionContext;
use serde::de::DeserializeOwned;
use std::time::Instant;

pub(crate) type GoldilocksCubic = CubicTrinomialExtensionField<Goldilocks>;

#[cfg(test)]
#[path = "runner_tests.rs"]
mod tests;

/// SplitMix64-v1 fixture stream, matching ReedWeave_UB's coefficient fixtures.
/// Never used for internal Fiat-Shamir challenges.
#[derive(Clone)]
pub(crate) struct Fixture(pub(crate) u64);
impl Fixture {
    fn word(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    pub(crate) fn field<F: CanonicalField>(&mut self) -> F {
        loop {
            let mut bytes = [0; 16];
            for chunk in bytes[..F::BYTE_WIDTH].chunks_exact_mut(8) {
                chunk.copy_from_slice(&self.word().to_le_bytes());
            }
            if let Ok(value) = F::from_canonical_bytes(&bytes[..F::BYTE_WIDTH]) {
                return value;
            }
        }
    }
}
pub fn audit(case: &Case) -> Result<Audit> {
    match case.field {
        Field::Goldilocks => params::audit::<Goldilocks, GoldilocksCubic>(case),
    }
}
pub fn run(case: &Case, settings: &Settings) -> Result<()> {
    audit(case)?;
    resources::admit(case, settings)?;
    match (case.field, case.protocol) {
        (Field::Goldilocks, Protocol::Fri) => {
            run_generic::<Goldilocks, GoldilocksCubic, _>(case, settings, params::fri)
        }
        (Field::Goldilocks, Protocol::Stir) => {
            run_generic::<Goldilocks, GoldilocksCubic, _>(case, settings, params::stir)
        }
        (Field::Goldilocks, Protocol::Whir) => run_trials(case, settings, |points| {
            crate::whir::trial(case, settings, points)
        }),
    }
}
fn run_generic<F, EF, PCS>(case: &Case, settings: &Settings, make_pcs: fn() -> PCS) -> Result<()>
where
    F: CanonicalField + TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField,
    PCS: Pcs<EF, Challenger<F>, Domain = TwoAdicMultiplicativeCoset<F>>,
    PCS::Commitment: PartialEq,
    Challenger<F>: CanObserve<PCS::Commitment>,
{
    run_trials(case, settings, |points| {
        trial::<F, EF, PCS>(case, settings, points, make_pcs)
    })
}
fn run_trials(
    case: &Case,
    settings: &Settings,
    measure: impl Fn(&mut Fixture) -> Result<Trial> + Sync,
) -> Result<()> {
    let execution = ExecutionContext::new(case.threads)?;
    let mut csv = output::open(&case.csv_path(settings))?;
    let seed = settings.seed ^ 0x706f696e74730000 ^ case.log_n as u64;
    let mut points = Fixture(seed);
    eprintln!(
        "START {} timing_model={} seed={} upstream_revision={} warmups=1 repetitions={}",
        case.label(),
        case.protocol.timing_model(),
        settings.seed,
        output::REVISION,
        settings.repetitions
    );
    for repetition in 0..=settings.repetitions {
        resources::admit(case, settings)?;
        // PCS, DFT caches, retained trees and proof data are scoped to one trial.
        // All phases, including upstream parallel operations, use the same local pool.
        let trial = execution.install(|| measure(&mut points))?;
        if repetition == 0 {
            points = Fixture(seed);
            eprintln!("WARMUP VERIFIED {}", case.label());
        } else {
            output::append(&mut csv, case, &trial)?;
            eprintln!(
                "VERIFIED {} repetition={} proof_size={}",
                case.label(),
                repetition,
                trial.commitment_size + trial.opening_proof_size
            );
        }
    }
    Ok(())
}
pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let (value, trailing) = postcard::take_from_bytes(bytes)?;
    if !trailing.is_empty() {
        return Err("trailing bytes in benchmark encoding".into());
    }
    Ok(value)
}
fn decode_transport<C: DeserializeOwned + PartialEq, P: DeserializeOwned>(
    expected: &C,
    commitment_bytes: &[u8],
    proof_bytes: &[u8],
) -> Result<(C, P)> {
    let commitment = decode(commitment_bytes)?;
    if &commitment != expected {
        return Err("decoded commitment mismatch".into());
    }
    Ok((commitment, decode(proof_bytes)?))
}
fn trial<F, EF, PCS>(
    case: &Case,
    settings: &Settings,
    points: &mut Fixture,
    make_pcs: fn() -> PCS,
) -> Result<Trial>
where
    F: CanonicalField + TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField,
    PCS: Pcs<EF, Challenger<F>, Domain = TwoAdicMultiplicativeCoset<F>>,
    PCS::Commitment: PartialEq,
    Challenger<F>: CanObserve<PCS::Commitment>,
{
    let n = 1usize << case.log_n;
    let mut fixture = Fixture(settings.seed ^ case.log_n as u64);
    let mut coefficients = Vec::new();
    coefficients.try_reserve_exact(n)?;
    coefficients.extend((0..n).map(|_| fixture.field::<F>()));
    let pcs = make_pcs();
    let input_dft = Radix2DitParallel::<F>::default();
    let domain = pcs.natural_domain_for_degree(n);

    let start = Instant::now();
    // P3's PCS API takes evaluations. Charge this initial transform to commit,
    // including its fresh DFT cache. Coefficients enter in ascending monomial order.
    let evaluations = input_dft
        .coset_dft_batch(RowMajorMatrix::new_col(coefficients), domain.shift())
        .to_row_major_matrix();
    let (commitment, state) = pcs.commit([(domain, evaluations)]);
    let commit_time = start.elapsed().as_secs_f64();
    let commitment_bytes = postcard::to_allocvec(&commitment)?;
    drop(input_dft);

    // External opening point, supplied after commitment. Exclude the committed
    // LDE coset so the upstream quotient never has a zero denominator.
    let shift_power = EF::from(F::GENERATOR.exp_power_of_2(case.log_n + params::LOG_INV_RATE));
    let z = loop {
        let point = EF::from_basis_coefficients_fn(|_| points.field::<F>());
        if point.exp_power_of_2(case.log_n + params::LOG_INV_RATE) != shift_power {
            break point;
        }
    };
    let context = format!(
        "plonky3-pcs-bench-v1:{}:{}:extension={}:log_n={}:rate=1/4:fri=2,128,151:stir=4,JohnsonBound,100:pow=0:{}",
        case.protocol.name(),
        case.field.name(),
        case.field.extension_degree(),
        case.log_n,
        output::REVISION
    );
    let fresh_challenger = || Challenger::<F>::new(context.as_bytes());
    let start = Instant::now();
    let mut prover = fresh_challenger();
    prover.observe(commitment.clone());
    FieldChallenger::<F>::observe_algebra_element(&mut prover, z);
    let (opened, proof) = pcs.open(vec![(&state, vec![vec![z]])], &mut prover);
    let prove_time = start.elapsed().as_secs_f64();
    let proof_bytes = postcard::to_allocvec(&proof)?;
    drop(proof);
    let values = opened
        .first()
        .and_then(|r| r.first())
        .and_then(|p| p.first())
        .ok_or("missing opening value")?
        .clone();
    if values.len() != 1 {
        return Err("expected one polynomial opening".into());
    }

    // Strict transport decoding/binding is excluded, not protocol verification.
    let (decoded_commitment, decoded_proof): (PCS::Commitment, PCS::Proof) =
        decode_transport(&commitment, &commitment_bytes, &proof_bytes)?;
    let start = Instant::now();
    let mut verifier = fresh_challenger();
    verifier.observe(decoded_commitment.clone());
    FieldChallenger::<F>::observe_algebra_element(&mut verifier, z);
    pcs.verify(
        vec![(decoded_commitment, vec![(domain, vec![(z, values)])])],
        &decoded_proof,
        &mut verifier,
    )
    .map_err(|e| format!("PCS verification failed: {e:?}"))?;
    let verify_time = start.elapsed().as_secs_f64();
    Ok(Trial {
        commit_time,
        prove_time,
        verify_time,
        commitment_size: commitment_bytes.len(),
        opening_proof_size: proof_bytes.len(),
    })
}
