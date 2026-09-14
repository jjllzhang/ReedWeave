//! Native multilinear WHIR: one Goldilocks hypercube table, one prescribed point.
use std::time::Instant;

use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::MultilinearPcs;
use p3_dft::Radix2DitParallel;
use p3_field::BasedVectorSpace;
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::point::Point;
use p3_sumcheck::{
    OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec,
    layout::{Layout as _, SuffixProver, Table},
};
use p3_whir::{
    fiat_shamir::domain_separator::DomainSeparator,
    pcs::{proof::PcsProof, prover::WhirProver},
};
use reedweave_primitives::fields::Goldilocks;

use crate::{
    Result,
    config::{Case, Settings},
    crypto::{BaseMmcs, Cap, Challenger, mmcs},
    output::{self, Trial},
    runner::{Fixture, GoldilocksCubic as EF, decode},
    whir_params,
};

type Layout = SuffixProver<Goldilocks, EF>;
type Pcs = WhirProver<
    EF,
    Goldilocks,
    Radix2DitParallel<Goldilocks>,
    BaseMmcs<Goldilocks>,
    Challenger<Goldilocks>,
    Layout,
>;
type Proof = PcsProof<Goldilocks, EF, BaseMmcs<Goldilocks>>;

struct Setup {
    pcs: Pcs,
    protocol: OpeningProtocol,
    separator: DomainSeparator<EF, Goldilocks>,
    context: String,
}
impl Setup {
    fn new(log_n: usize) -> Result<Self> {
        let config = whir_params::config(log_n)?;
        // Fresh lazy caches: no FFT twiddles are precomputed outside commit.
        // WHIR's verifier constructs its extension MMCS from this SAME backend;
        // do not change only the prover's extension leaf role. Extension values
        // are flattened into canonical base coordinates by upstream on both sides.
        let pcs = Pcs::new(config, Radix2DitParallel::default(), mmcs(0));
        let protocol = OpeningProtocol::new(vec![TableSpec::new(
            TableShape::new(log_n, 1),
            vec![OpeningBatch::new(vec![0], Vec::new())],
        )]);
        let mut separator = DomainSeparator::new(Vec::new());
        pcs.add_domain_separator::<32>(&mut separator);
        let context = format!(
            "plonky3-pcs-bench-whir-native-v1:goldilocks:extension=3:log_n={log_n}:layout=suffix:tables=1:columns=1:prescribed_points=1:rate=1/4:fold_variables=2:JohnsonBound:target=100:query_union=half:pow=0:{}",
            output::REVISION
        );
        Ok(Self {
            pcs,
            protocol,
            separator,
            context,
        })
    }

    fn challenger(&self) -> Challenger<Goldilocks> {
        let mut challenger = Challenger::new(self.context.as_bytes());
        self.separator.observe_domain_separator(&mut challenger);
        challenger
    }
}

pub(crate) fn trial(case: &Case, settings: &Settings, points: &mut Fixture) -> Result<Trial> {
    let n = 1usize << case.log_n;
    let mut fixture = Fixture(settings.seed ^ case.log_n as u64);
    let mut values = Vec::new();
    values.try_reserve_exact(n)?;
    values.extend((0..n).map(|_| fixture.field::<Goldilocks>()));
    let setup = Setup::new(case.log_n)?;

    let start = Instant::now();
    let mut prover = setup.challenger();
    // Identical raw fixtures to FRI/STIR, but interpreted as Boolean-hypercube
    // EVALUATIONS, not univariate coefficients. Include stacking/preprocessing.
    let table = Table::new(RowMajorMatrix::new(values, n));
    let witness = Layout::new_witness(vec![table], whir_params::FOLD_VARIABLES);
    // commit observes the root once; its transcript must continue into open_at.
    let (commitment, state) = setup.pcs.commit(witness, &mut prover);
    let commit_time = start.elapsed().as_secs_f64();
    let commitment_bytes = postcard::to_allocvec(&commitment)?;

    // External point selected after commit. All m extension coordinates are
    // independent fixture draws; internal WHIR/OOD challenges use Fiat-Shamir.
    let point = Point::new(
        (0..case.log_n)
            .map(|_| EF::from_basis_coefficients_fn(|_| points.field::<Goldilocks>()))
            .collect(),
    );
    let start = Instant::now();
    prover.observe_algebra_slice(point.as_slice());
    let proof = setup.pcs.open_at(
        state,
        &setup.protocol,
        std::slice::from_ref(&point),
        &mut prover,
    );
    let prove_time = start.elapsed().as_secs_f64();
    let proof_bytes = postcard::to_allocvec(&proof)?;
    let public_eval = single_eval(&proof)?;
    drop(proof);

    // Strict transport decoding/binding is excluded, not protocol verification.
    let (decoded_commitment, decoded_proof) =
        decode_transport(&commitment, &commitment_bytes, &proof_bytes, public_eval)?;
    let start = Instant::now();
    verify_decoded(&setup, &decoded_commitment, &decoded_proof, &point)?;
    let verify_time = start.elapsed().as_secs_f64();
    drop(decoded_proof);
    Ok(Trial {
        commit_time,
        prove_time,
        verify_time,
        commitment_size: commitment_bytes.len(),
        opening_proof_size: proof_bytes.len(),
    })
}

fn single_eval(proof: &Proof) -> Result<EF> {
    if proof.evals.len() != 1
        || proof.evals[0].current().len() != 1
        || !proof.evals[0].next().is_empty()
    {
        return Err("WHIR expected one polynomial opening at one point".into());
    }
    Ok(proof.evals[0].current()[0])
}

fn decode_transport(
    expected: &Cap<Goldilocks>,
    commitment_bytes: &[u8],
    proof_bytes: &[u8],
    public_eval: EF,
) -> Result<(Cap<Goldilocks>, Proof)> {
    let commitment: Cap<Goldilocks> = decode(commitment_bytes)?;
    if &commitment != expected {
        return Err("decoded WHIR commitment mismatch".into());
    }
    let proof: Proof = decode(proof_bytes)?;
    if single_eval(&proof)? != public_eval {
        return Err("decoded WHIR evaluation mismatch".into());
    }
    Ok((commitment, proof))
}

fn verify_decoded(
    setup: &Setup,
    commitment: &Cap<Goldilocks>,
    proof: &Proof,
    point: &Point<EF>,
) -> Result<()> {
    let mut verifier = setup.challenger();
    // Unlike MultilinearPcs::verify, verify_at does NOT observe the root.
    // Replay commit's observation, then bind the external point before OOD.
    verifier.observe(commitment.clone());
    verifier.observe_algebra_slice(point.as_slice());
    setup
        .pcs
        .verify_at(
            commitment,
            proof,
            &setup.protocol,
            std::slice::from_ref(point),
            &mut verifier,
        )
        .map_err(|e| format!("WHIR PCS verification failed: {e:?}"))?;
    Ok(())
}

#[cfg(test)]
#[path = "whir_tests.rs"]
mod tests;
