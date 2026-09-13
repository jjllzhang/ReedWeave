use p3_field::{PrimeCharacteristicRing, TwoAdicField};
use reedweave_jb_core::{BaseField, JbParams, PcsError, PublicParams, ReedWeaveJb};
use reedweave_primitives::transcript::{
    FieldProfile, GoldilocksBaseProfile, GoldilocksCubicProfile, GoldilocksProfile,
    GoldilocksQuinticProfile,
};
use reedweave_runtime::ExecutionContext;
fn roundtrip<P: FieldProfile>() {
    let execution = ExecutionContext::new(2).unwrap();
    for (log_d, m, blowup, kt, queries) in [(2, 1, 2, 2, 19), (5, 4, 2, 2, 40), (6, 2, 4, 4, 3)] {
        let params = JbParams::new(PublicParams {
            base_field: BaseField::Goldilocks,
            extension_degree: P::PROFILE.extension_degree(),
            log_d,
            m,
            blowup,
            terminal_coefficients: kt,
            num_queries: queries,
            agreement_numerator: 3,
            agreement_denominator: 4,
        })
        .unwrap();
        let pcs = ReedWeaveJb::<P>::new(params.clone()).unwrap();
        let mut highest = vec![P::Base::ZERO; params.d()];
        highest[params.d() - 1] = P::Base::ONE;
        for coefficients in [
            vec![],
            vec![P::Base::from_u8(7)],
            highest,
            (0..params.d() - 1)
                .map(|i| P::Base::from_usize(i * i + 1))
                .collect(),
        ] {
            let (commitment, state) = pcs.commit(coefficients.clone(), &execution).unwrap();
            assert_eq!(&commitment, state.commitment());
            assert_eq!(state.coefficients().len(), params.d());
            pcs.validate_commitment(&commitment).unwrap();
            pcs.open_deep(&commitment, &coefficients, state.encoded_word(), &execution)
                .unwrap();
            for z in [
                P::Base::ZERO,
                P::Base::TWO,
                P::Base::two_adic_generator(params.log_domain_size()),
            ] {
                let opening = pcs.prove(&state, z, &execution).unwrap();
                assert_eq!(
                    opening.y,
                    coefficients
                        .iter()
                        .rev()
                        .fold(P::Base::ZERO, |v, &c| v * z + c)
                );
                pcs.verify(&commitment, z, opening.y, &opening.proof, &execution)
                    .unwrap();
                assert_eq!(&commitment, state.commitment());
                assert_eq!(opening.proof.oracle_roots.len(), params.rounds() - 1);
                assert_eq!(opening.proof.scalar_openings.len(), params.rounds() - 1);
                if params.rounds() == 1 {
                    assert!(opening.proof.oracle_roots.is_empty());
                    assert!(opening.proof.scalar_openings.is_empty());
                }
                let repeated = pcs.prove(&state, z, &execution).unwrap();
                assert_eq!(
                    reedweave_jb_core::codec::encode_eval_proof(&params, &opening.proof).unwrap(),
                    reedweave_jb_core::codec::encode_eval_proof(&params, &repeated.proof).unwrap()
                );
            }
        }
        assert!(matches!(
            pcs.commit(vec![P::Base::ZERO; params.d() + 1], &execution),
            Err(PcsError::CoefficientCount { .. })
        ));
    }
}
#[test]
fn reusable_state_all_profiles_geometries_and_polynomial_shapes() {
    roundtrip::<GoldilocksBaseProfile>();
    roundtrip::<GoldilocksProfile>();
    roundtrip::<GoldilocksCubicProfile>();
    roundtrip::<GoldilocksQuinticProfile>();
}
fn negative<P: FieldProfile>() {
    let execution = ExecutionContext::new(1).unwrap();
    let params = JbParams::new(PublicParams {
        base_field: BaseField::Goldilocks,
        extension_degree: P::PROFILE.extension_degree(),
        log_d: 6,
        m: 4,
        blowup: 2,
        terminal_coefficients: 2,
        num_queries: 3,
        agreement_numerator: 3,
        agreement_denominator: 4,
    })
    .unwrap();
    let pcs = ReedWeaveJb::<P>::new(params.clone()).unwrap();
    let (commitment, state) = pcs
        .commit(
            (0..params.d())
                .map(|i| P::Base::from_usize(i + 1))
                .collect(),
            &execution,
        )
        .unwrap();
    let z = P::Base::TWO;
    let opening = pcs.prove(&state, z, &execution).unwrap();
    for j in 0..params.rounds() {
        for which in 0..4 {
            let mut bad = opening.proof.clone();
            match which {
                0 => bad.rounds[j].even_value += P::Challenge::ONE,
                1 => bad.rounds[j].odd_value += P::Challenge::ONE,
                2 => bad.rounds[j].deep_even_value += P::Challenge::ONE,
                _ => bad.rounds[j].deep_odd_value += P::Challenge::ONE,
            }
            assert!(
                pcs.verify(&commitment, z, opening.y, &bad, &execution)
                    .is_err()
            );
        }
    }
    let mut bad_c = commitment.clone();
    bad_c.deep_values[0] += P::Challenge::ONE;
    // Shape and FS replay alone cannot certify DEEP answers.
    pcs.validate_commitment(&bad_c).unwrap();
    assert!(
        pcs.verify(&bad_c, z, opening.y, &opening.proof, &execution)
            .is_err()
    );
    for mutation in 0..12 {
        let mut bad = opening.proof.clone();
        match mutation {
            0 => bad.block_values[0] += P::Base::ONE,
            1 => bad.terminal_coefficients[0] += P::Challenge::ONE,
            2 => bad.oracle_roots[0][0] ^= 1,
            3 => bad.initial_opening.rows[0][0] += P::Base::ONE,
            4 => bad.scalar_openings[0].values[0] += P::Challenge::ONE,
            5 => {
                bad.initial_opening.rows.pop();
            }
            6 => bad
                .initial_opening
                .rows
                .push(vec![P::Base::ZERO; params.m()]),
            7 => bad.initial_opening.proof.sibling_hashes.push([0; 32]),
            8 => {
                bad.scalar_openings[0].values.pop();
            }
            9 => bad.scalar_openings[0].proof.sibling_hashes.push([0; 32]),
            10 => bad.oracle_roots.push([0; 32]), // terminal authentication prohibited
            _ => {
                bad.rounds.pop();
            }
        }
        assert!(
            pcs.verify(&commitment, z, opening.y, &bad, &execution)
                .is_err(),
            "mutation {mutation}"
        );
    }
    assert!(
        pcs.verify(
            &commitment,
            z,
            opening.y + P::Base::ONE,
            &opening.proof,
            &execution
        )
        .is_err()
    );
}
#[test]
fn all_transmitted_message_classes_and_deep_fields_are_binding() {
    negative::<GoldilocksBaseProfile>();
    negative::<GoldilocksProfile>();
    negative::<GoldilocksCubicProfile>();
    negative::<GoldilocksQuinticProfile>();
}
