//! Coordinator-owned integration tests: wire domains must separate UB and JB
//! even when the underlying base Merkle root and public evaluation are equal.
use p3_field::PrimeCharacteristicRing;
use reedweave_jb_core::{JbParams, PublicParams as JbPublicParams, ReedWeaveJb, codec as jb_codec};
use reedweave_primitives::{
    fields::Goldilocks as F,
    transcript::{
        FieldProfile, GoldilocksBaseProfile, GoldilocksCubicProfile, GoldilocksQuadraticProfile,
        GoldilocksQuinticProfile,
    },
};
use reedweave_runtime::ExecutionContext;
use reedweave_ub_core::{
    BaseField, PublicParams as UbPublicParams, ReedWeaveUb, UbParams, codec as ub_codec,
};

fn check<P: FieldProfile<Base = F>>() {
    let execution = ExecutionContext::new(1).unwrap();
    let ub = UbParams::new(UbPublicParams {
        base_field: BaseField::Goldilocks,
        extension_degree: P::PROFILE.extension_degree(),
        log_d: 4,
        m: 2,
        blowup: 2,
        terminal_coefficients: 2,
        num_queries: 40, // Q>N, so proof sets can saturate despite different transcripts.
    })
    .unwrap();
    let jb = JbParams::new(JbPublicParams {
        base_field: BaseField::Goldilocks,
        extension_degree: ub.extension_degree(),
        log_d: ub.log_d(),
        m: ub.m(),
        blowup: ub.blowup(),
        terminal_coefficients: ub.terminal_coefficient_count(),
        num_queries: ub.num_queries(),
        agreement_numerator: 18,
        agreement_denominator: 25,
    })
    .unwrap();
    let ub_pcs = ReedWeaveUb::<P>::new(ub.clone()).unwrap();
    let jb_pcs = ReedWeaveJb::<P>::new(jb.clone()).unwrap();
    for coefficients in [vec![F::ZERO], vec![F::ONE], vec![F::ONE; ub.d()]] {
        let (ub_commitment, ub_state) = ub_pcs.commit(coefficients.clone(), &execution).unwrap();
        let (jb_commitment, jb_state) = jb_pcs.commit(coefficients, &execution).unwrap();
        assert_eq!(ub_commitment.root, jb_commitment.root);
        let ub_opening = ub_pcs.prove(&ub_state, F::ZERO, &execution).unwrap();
        let jb_opening = jb_pcs.prove(&jb_state, F::ZERO, &execution).unwrap();
        assert_eq!(ub_opening.y, jb_opening.y);
        let ub_bytes = ub_codec::encode_eval_proof(&ub, &ub_opening.proof).unwrap();
        let jb_bytes = jb_codec::encode_eval_proof(&jb, &jb_opening.proof).unwrap();
        assert_ne!(&ub_bytes[..32], &jb_bytes[..32]);
        assert!(jb_codec::decode_eval_proof::<P>(&jb, &ub_bytes).is_err());
        assert!(ub_codec::decode_eval_proof::<P>(&ub, &jb_bytes).is_err());
        let ub_commit_bytes = ub_codec::encode_commitment(&ub_commitment);
        let jb_commit_bytes = jb_codec::encode_commitment(&jb, &jb_commitment).unwrap();
        assert!(jb_codec::decode_commitment::<P>(&jb, &ub_commit_bytes).is_err());
        assert!(ub_codec::decode_commitment(&jb_commit_bytes).is_err());
        assert_eq!(
            jb_pcs
                .verify_encoded(
                    &jb_commitment,
                    (F::ZERO, jb_opening.y),
                    &jb_commit_bytes,
                    &jb_bytes,
                    &execution,
                )
                .unwrap(),
            jb_commit_bytes.len() + jb_bytes.len()
        );
        assert!(
            jb_pcs
                .verify_encoded(
                    &jb_commitment,
                    (F::ZERO, jb_opening.y),
                    &jb_commit_bytes,
                    &ub_bytes,
                    &execution,
                )
                .is_err()
        );
    }
}

#[test]
fn ub_and_jb_are_separate_even_for_degenerate_saturated_proofs() {
    check::<GoldilocksBaseProfile>();
    check::<GoldilocksQuadraticProfile>();
    check::<GoldilocksCubicProfile>();
    check::<GoldilocksQuinticProfile>();
}
