use p3_field::{PrimeCharacteristicRing, TwoAdicField};
use reedweave_ub_core::{BaseField, UbParams, PcsError, PublicParams, ReedWeaveUb};
use reedweave_primitives::transcript::{
    FieldProfile, GoldilocksBaseProfile, GoldilocksCubicProfile, GoldilocksProfile,
    GoldilocksQuinticProfile,
};
use reedweave_runtime::ExecutionContext;

fn cases<P: FieldProfile>() {
    let execution = ExecutionContext::new(2).unwrap();
    for (log_d, m, blowup, kt, q) in [
        (2, 1, 2, 2, 1),
        (4, 1, 4, 2, 70),
        (5, 4, 2, 2, 19),
        (6, 8, 8, 4, 3),
    ] {
        let params = params::<P>(log_d, m, blowup, kt, q);
        let pcs = ReedWeaveUb::<P>::new(params.clone()).unwrap();
        for kind in 0..4 {
            let mut coefficients = vec![P::Base::ZERO; params.d()];
            match kind {
                0 => {}
                1 => coefficients[0] = P::Base::from_u8(17),
                2 => {
                    for i in [
                        0,
                        params.k() - 1,
                        params.k().min(params.d() - 1),
                        params.d() - 1,
                    ] {
                        coefficients[i] = P::Base::from_usize(i + 1);
                    }
                }
                _ => {
                    for (i, value) in coefficients.iter_mut().enumerate() {
                        *value = P::Base::from_usize(i * i + 7);
                    }
                }
            }
            let evaluate = |z| {
                coefficients
                    .iter()
                    .rev()
                    .fold(P::Base::ZERO, |a, &c| a * z + c)
            };
            let points = [
                P::Base::ZERO,
                P::Base::from_u8(3),
                P::Base::two_adic_generator(params.log_domain_size()),
            ];
            let expected = points.map(evaluate);
            let (commitment, state) = pcs.commit(coefficients, &execution).unwrap();
            assert_eq!(state.commitment(), commitment);
            for (z, expected_y) in points.into_iter().zip(expected) {
                let opening = pcs.prove(&state, z, &execution).unwrap();
                assert_eq!(opening.y, expected_y);
                pcs.verify(&commitment, z, expected_y, &opening.proof, &execution)
                    .unwrap();
                let bytes =
                    reedweave_ub_core::codec::encode_eval_proof(&params, &opening.proof).unwrap();
                assert_eq!(
                    pcs.verify_encoded(
                        &commitment,
                        (z, expected_y),
                        &commitment.root,
                        &bytes,
                        &execution
                    )
                    .unwrap(),
                    32 + bytes.len()
                );
                assert!(
                    pcs.verify(
                        &commitment,
                        z,
                        expected_y + P::Base::ONE,
                        &opening.proof,
                        &execution
                    )
                    .is_err()
                );
                if kind == 3 {
                    assert!(
                        pcs.verify(
                            &commitment,
                            z + P::Base::ONE,
                            expected_y,
                            &opening.proof,
                            &execution
                        )
                        .is_err()
                    );
                }
                assert_eq!(opening.proof.terminal_coefficients.len(), kt);
                assert_eq!(opening.proof.rounds.len(), params.rounds());
                assert_eq!(opening.proof.oracle_roots.len(), params.rounds() - 1);
                if params.rounds() == 1 {
                    assert!(opening.proof.oracle_roots.is_empty());
                    assert!(opening.proof.scalar_openings.is_empty());
                }
            }
            // Opening at two points does not change retained commitment state.
            let different =
                ReedWeaveUb::<P>::new(self::params::<P>(log_d + 1, m, blowup, kt, q)).unwrap();
            assert!(matches!(
                different.prove(&state, P::Base::ZERO, &execution),
                Err(PcsError::StateMismatch)
            ));
        }
        let short = vec![P::Base::TWO];
        let (short_root, short_state) = pcs.commit(short, &execution).unwrap();
        let mut padded = vec![P::Base::ZERO; params.d()];
        padded[0] = P::Base::TWO;
        assert_eq!(short_root, pcs.commit(padded, &execution).unwrap().0);
        let opened = pcs.prove(&short_state, P::Base::TWO, &execution).unwrap();
        assert_eq!(opened.y, P::Base::TWO);
        pcs.verify(
            &short_root,
            P::Base::TWO,
            opened.y,
            &opened.proof,
            &execution,
        )
        .unwrap();
        assert!(pcs.commit(vec![], &execution).is_ok());
        assert!(
            pcs.commit(vec![P::Base::ZERO; params.d() + 1], &execution)
                .is_err()
        );
    }
}

#[test]
fn honest_polynomials_all_supported_extensions() {
    cases::<GoldilocksProfile>();
    cases::<GoldilocksBaseProfile>();
    cases::<GoldilocksCubicProfile>();
    cases::<GoldilocksQuinticProfile>();
}

fn malformed<P: FieldProfile>() {
    let execution = ExecutionContext::new(1).unwrap();
    let params = params::<P>(6, 4, 2, 2, 19);
    let pcs = ReedWeaveUb::<P>::new(params.clone()).unwrap();
    let coefficients = (0..params.d())
        .map(|i| P::Base::from_usize(i + 1))
        .collect();
    let (commitment, state) = pcs.commit(coefficients, &execution).unwrap();
    let z = P::Base::TWO;
    let opening = pcs.prove(&state, z, &execution).unwrap();
    let reject = |proof: &_| {
        assert!(
            pcs.verify(&commitment, z, opening.y, proof, &execution)
                .is_err()
        )
    };
    for mutation in 0..29 {
        let mut proof = opening.proof.clone();
        match mutation {
            0 => {
                proof.block_values.pop();
            }
            1 => proof.block_values.push(P::Base::ZERO),
            2 => proof.block_values[0] += P::Base::ONE,
            3 => {
                proof.rounds.pop();
            }
            4 => proof.rounds.push(proof.rounds[0].clone()),
            5 => proof.rounds[0].even_value += P::Challenge::ONE,
            6 => proof.rounds[0].odd_value += P::Challenge::ONE,
            7 => proof.oracle_roots[0][0] ^= 1,
            8 => proof.terminal_coefficients[0] += P::Challenge::ONE,
            9 => proof.terminal_coefficients[1] += P::Challenge::ONE,
            10 => proof.oracle_roots.last_mut().unwrap()[0] ^= 1,
            11 => {
                proof.initial_opening.rows[0].pop();
            }
            12 => {
                proof.initial_opening.rows.pop();
            }
            13 => proof.initial_opening.rows[0][0] += P::Base::ONE,
            14 => proof.initial_opening.rows.swap(0, 1),
            15 => {
                proof.scalar_openings.pop();
            }
            16 => proof.scalar_openings[0].values[0] += P::Challenge::ONE,
            17 => proof.scalar_openings[0].proof.sibling_hashes.push([0; 32]),
            18 => proof.scalar_openings[0].values.swap(0, 1),
            19 => {
                proof.scalar_openings[0].values.pop();
            }
            20 => proof.scalar_openings[0].values.push(P::Challenge::ZERO),
            21 => proof.initial_opening.rows[0].push(P::Base::ZERO),
            22 => proof
                .initial_opening
                .rows
                .push(proof.initial_opening.rows[0].clone()),
            // No redundant terminal multiproof (or extra committed virtual word).
            23 => proof
                .scalar_openings
                .push(proof.scalar_openings.last().unwrap().clone()),
            24 => proof.initial_opening.proof.sibling_hashes.push([0; 32]),
            25 => {
                proof.terminal_coefficients.pop();
            }
            26 => proof.terminal_coefficients.push(P::Challenge::ZERO),
            27 => { proof.oracle_roots.pop(); }
            28 => proof.oracle_roots.push([0; 32]),
            _ => unreachable!(),
        }
        reject(&proof);
    }
    // Preserve reconstruction: the complete block vector still binds the row challenges.
    let mut proof = opening.proof.clone();
    proof.block_values[0] -= z;
    proof.block_values[1] += P::Base::ONE;
    reject(&proof);
    // Preserve the first scalar identity: both scalars still affect gamma.
    let mut proof = opening.proof.clone();
    proof.rounds[0].even_value -= P::Challenge::from(z.exp_u64(params.m() as u64));
    proof.rounds[0].odd_value += P::Challenge::ONE;
    reject(&proof);
    let mut wrong_commitment = commitment;
    wrong_commitment.root[0] ^= 1;
    assert!(
        pcs.verify(&wrong_commitment, z, opening.y, &opening.proof, &execution)
            .is_err()
    );
    let other_size = ReedWeaveUb::<P>::new(self::params::<P>(4, 4, 2, 2, 19)).unwrap();
    assert!(
        other_size
            .verify(&commitment, z, opening.y, &opening.proof, &execution)
            .is_err()
    );
}

#[test]
fn malformed_shapes_algebra_and_statement_binding() {
    malformed::<GoldilocksProfile>();
    malformed::<GoldilocksBaseProfile>();
    malformed::<GoldilocksCubicProfile>();
    malformed::<GoldilocksQuinticProfile>();
}

#[test]
fn trusted_profile_and_parameter_binding() {
    use reedweave_primitives::fields::Goldilocks as F;
    let execution = ExecutionContext::new(1).unwrap();
    let params = params::<GoldilocksProfile>(5, 4, 2, 2, 19);
    assert!(matches!(
        ReedWeaveUb::<GoldilocksBaseProfile>::new(params.clone()),
        Err(PcsError::ProfileMismatch)
    ));
    let pcs = ReedWeaveUb::<GoldilocksProfile>::new(params.clone()).unwrap();
    let (commitment, state) = pcs
        .commit((0..params.d()).map(F::from_usize).collect(), &execution)
        .unwrap();
    let opening = pcs.prove(&state, F::TWO, &execution).unwrap();
    pcs.verify(&commitment, F::TWO, opening.y, &opening.proof, &execution)
        .unwrap();
    let other_size =
        ReedWeaveUb::<GoldilocksProfile>::new(self::params::<GoldilocksProfile>(4, 4, 2, 2, 19))
            .unwrap();
    assert!(
        other_size
            .verify(&commitment, F::TWO, opening.y, &opening.proof, &execution)
            .is_err()
    );
}

fn params<P: FieldProfile>(
    log_d: usize,
    m: usize,
    blowup: usize,
    kt: usize,
    q: usize,
) -> UbParams {
    UbParams::new(PublicParams {
        base_field: BaseField::Goldilocks,
        extension_degree: P::PROFILE.extension_degree(),
        log_d,
        m,
        blowup,
        terminal_coefficients: kt,
        num_queries: q,
    })
    .unwrap()
}
