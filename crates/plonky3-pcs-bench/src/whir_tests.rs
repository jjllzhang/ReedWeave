use super::*;
use crate::config::{Field, Protocol};
use p3_field::PrimeCharacteristicRing;
use reedweave_runtime::ExecutionContext;

#[test]
fn serialized_native_trials_verify_in_both_local_pool_sizes() {
    for (threads, log_n) in [(1, 10), (32, 10), (1, 11), (32, 11)] {
        let execution = ExecutionContext::new(threads).unwrap();
        let case = Case {
            protocol: Protocol::Whir,
            field: Field::Goldilocks,
            log_n,
            threads,
        };
        let settings = Settings {
            out: Default::default(),
            seed: 20260906,
            repetitions: 1,
            max_memory_mib: None,
            time_limit_seconds: None,
        };
        let measured = execution
            .install(|| trial(&case, &settings, &mut Fixture(123)))
            .unwrap();
        assert_eq!(measured.commitment_size, 33);
        assert!(measured.opening_proof_size > 0);
    }
}

struct FixtureProof {
    setup: Setup,
    root: Cap<Goldilocks>,
    root_bytes: Vec<u8>,
    proof: Proof,
    point: Point<EF>,
    value: EF,
}
fn fixture_proof() -> FixtureProof {
    let log_n = 10;
    let setup = Setup::new(log_n).unwrap();
    let mut fixture = Fixture(123);
    let values: Vec<_> = (0..1 << log_n)
        .map(|_| fixture.field::<Goldilocks>())
        .collect();
    let mut prover = setup.challenger();
    let witness = Layout::new_witness(
        vec![Table::new(RowMajorMatrix::new(values.clone(), 1 << log_n))],
        whir_params::FOLD_VARIABLES,
    );
    let (root, state) = setup.pcs.commit(witness, &mut prover);
    let point = Point::new(
        (0..log_n)
            .map(|_| EF::from_basis_coefficients_fn(|_| fixture.field::<Goldilocks>()))
            .collect(),
    );
    // Independent multilinear evaluation in big-endian hypercube order.
    // This oracle deliberately does not use p3-multilinear-util's evaluator.
    let value = values
        .iter()
        .enumerate()
        .map(|(index, &v)| {
            point
                .iter()
                .enumerate()
                .fold(EF::from(v), |product, (j, &r)| {
                    product
                        * if (index >> (log_n - 1 - j)) & 1 == 1 {
                            r
                        } else {
                            EF::ONE - r
                        }
                })
        })
        .sum::<EF>();
    prover.observe_algebra_slice(point.as_slice());
    let proof = setup.pcs.open_at(
        state,
        &setup.protocol,
        std::slice::from_ref(&point),
        &mut prover,
    );
    assert_eq!(single_eval(&proof).unwrap(), value);
    let root_bytes = postcard::to_allocvec(&root).unwrap();
    FixtureProof {
        setup,
        root,
        root_bytes,
        proof,
        point,
        value,
    }
}

// Exercise the same decode/binding and typed verification phases as the runner.
fn verify_encoded(
    setup: &Setup,
    expected: &Cap<Goldilocks>,
    commitment_bytes: &[u8],
    proof_bytes: &[u8],
    point: &Point<EF>,
    public_eval: EF,
) -> Result<()> {
    let (commitment, proof) =
        decode_transport(expected, commitment_bytes, proof_bytes, public_eval)?;
    verify_decoded(setup, &commitment, &proof, point)
}

#[test]
fn proof_matches_independent_multilinear_oracle_and_rejects_tampering() {
    ExecutionContext::new(1).unwrap().install(|| {
        let mut f = fixture_proof();
        let bytes = postcard::to_allocvec(&f.proof).unwrap();
        assert!(
            verify_encoded(&f.setup, &f.root, &f.root_bytes, &bytes, &f.point, f.value).is_ok()
        );
        // Public claim mismatch is rejected before upstream verification.
        assert!(
            verify_encoded(
                &f.setup,
                &f.root,
                &f.root_bytes,
                &bytes,
                &f.point,
                f.value + EF::ONE
            )
            .is_err()
        );
        let mut coords = f.point.as_slice().to_vec();
        coords[0] += EF::ONE;
        assert!(
            verify_encoded(
                &f.setup,
                &f.root,
                &f.root_bytes,
                &bytes,
                &Point::new(coords),
                f.value
            )
            .is_err()
        );
        let mut wrong_root = f.root_bytes.clone();
        wrong_root[1] ^= 1;
        assert!(verify_encoded(&f.setup, &f.root, &wrong_root, &bytes, &f.point, f.value).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(
            verify_encoded(
                &f.setup,
                &f.root,
                &f.root_bytes,
                &trailing,
                &f.point,
                f.value
            )
            .is_err()
        );
        assert!(
            verify_encoded(
                &f.setup,
                &f.root,
                &f.root_bytes,
                &bytes[..bytes.len() / 2],
                &f.point,
                f.value
            )
            .is_err()
        );
        // Change both the claimed public value and proof-carried value: the
        // actual WHIR verifier (not only the wrapper's equality check) rejects.
        f.proof.evals = vec![OpeningBatch::new(vec![f.value + EF::ONE], Vec::new())];
        let forged = postcard::to_allocvec(&f.proof).unwrap();
        assert!(
            verify_encoded(
                &f.setup,
                &f.root,
                &f.root_bytes,
                &forged,
                &f.point,
                f.value + EF::ONE
            )
            .is_err()
        );
        f.proof.evals = vec![OpeningBatch::new(vec![f.value], Vec::new())];
        f.proof.whir.initial_ood_answers[0] += EF::ONE;
        let forged = postcard::to_allocvec(&f.proof).unwrap();
        assert!(
            verify_encoded(&f.setup, &f.root, &f.root_bytes, &forged, &f.point, f.value).is_err()
        );
    });
}

#[test]
fn identical_inputs_produce_identical_proofs_across_thread_counts() {
    let encode = || {
        let f = fixture_proof();
        (f.root_bytes, postcard::to_allocvec(&f.proof).unwrap())
    };
    let single = ExecutionContext::new(1).unwrap().install(encode);
    let parallel = ExecutionContext::new(32).unwrap().install(encode);
    assert_eq!(single, parallel);
}
