use brakefri_core::{BrakeFri, BrakeParams, PcsError};
use brakefri_primitives::transcript::{F128Profile, FieldProfile, GoldilocksProfile};
use brakefri_runtime::ExecutionContext;
use p3_field::PrimeCharacteristicRing;

fn cases<P: FieldProfile>() {
    let execution = ExecutionContext::new(2).unwrap();
    for log_n in [14, 15, 16] {
        let params = BrakeParams::new(P::PROFILE, log_n).unwrap();
        let pcs = BrakeFri::<P>::new(params.clone()).unwrap();
        for kind in 0..4 {
            let mut coefficients = vec![P::Base::ZERO; params.n()];
            match kind {
                0 => {}
                1 => coefficients[0] = P::Base::from_u8(17),
                2 => {
                    for i in [0, params.k() - 1, params.k(), params.n() - 1] {
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
            let expected = [evaluate(P::Base::ZERO), evaluate(P::Base::from_u8(3))];
            let (commitment, state) = pcs.commit(coefficients, &execution).unwrap();
            assert_eq!(state.commitment(), commitment);
            for (z, expected_y) in [P::Base::ZERO, P::Base::from_u8(3)]
                .into_iter()
                .zip(expected)
            {
                let opening = pcs.prove(&state, z, &execution).unwrap();
                assert_eq!(opening.y, expected_y);
                pcs.verify(&commitment, z, expected_y, &opening.proof, &execution)
                    .unwrap();
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
                assert_eq!(opening.proof.terminal_coefficients.len(), 128);
                assert_eq!(opening.proof.rounds.len(), log_n - 13);
                if log_n == 14 {
                    assert!(opening.proof.scalar_openings.is_empty());
                }
            }
            // Opening at two points does not change retained commitment state.
            let different =
                BrakeFri::<P>::new(BrakeParams::new(P::PROFILE, log_n + 1).unwrap()).unwrap();
            assert!(matches!(
                different.prove(&state, P::Base::ZERO, &execution),
                Err(PcsError::StateMismatch)
            ));
        }
        assert!(matches!(
            pcs.commit(vec![], &execution),
            Err(PcsError::CoefficientCount { .. })
        ));
        assert!(
            pcs.commit(vec![P::Base::ZERO; params.n() - 1], &execution)
                .is_err()
        );
        assert!(
            pcs.commit(vec![P::Base::ZERO; params.n() + 1], &execution)
                .is_err()
        );
    }
}

#[test]
fn honest_polynomials_both_profiles() {
    cases::<GoldilocksProfile>();
    cases::<F128Profile>();
}

fn malformed<P: FieldProfile>() {
    let execution = ExecutionContext::new(1).unwrap();
    let params = BrakeParams::new(P::PROFILE, 16).unwrap();
    let pcs = BrakeFri::<P>::new(params.clone()).unwrap();
    let coefficients = (0..params.n())
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
    for mutation in 0..27 {
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
            7 => proof.rounds[0].next_oracle_root[0] ^= 1,
            8 => proof.terminal_coefficients[0] += P::Challenge::ONE,
            9 => proof.terminal_coefficients[127] += P::Challenge::ONE,
            10 => proof.rounds.last_mut().unwrap().next_oracle_root[0] ^= 1,
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
            _ => unreachable!(),
        }
        reject(&proof);
    }
    // Preserve reconstruction: the complete block vector still binds the row challenges.
    let mut proof = opening.proof.clone();
    proof.block_values[0] -= z.exp_u64(params.k() as u64);
    proof.block_values[1] += P::Base::ONE;
    reject(&proof);
    // Preserve the first scalar identity: both scalars still affect gamma.
    let mut proof = opening.proof.clone();
    proof.rounds[0].even_value -= P::Challenge::from(z);
    proof.rounds[0].odd_value += P::Challenge::ONE;
    reject(&proof);
    let mut wrong_commitment = commitment;
    wrong_commitment.root[0] ^= 1;
    assert!(
        pcs.verify(&wrong_commitment, z, opening.y, &opening.proof, &execution)
            .is_err()
    );
    let other_size = BrakeFri::<P>::new(BrakeParams::new(P::PROFILE, 14).unwrap()).unwrap();
    assert!(
        other_size
            .verify(&commitment, z, opening.y, &opening.proof, &execution)
            .is_err()
    );
}

#[test]
fn malformed_shapes_algebra_and_statement_binding() {
    malformed::<GoldilocksProfile>();
    malformed::<F128Profile>();
}

#[test]
fn trusted_profile_and_parameter_binding() {
    use brakefri_primitives::fields::Goldilocks as F;
    let execution = ExecutionContext::new(1).unwrap();
    let params = BrakeParams::new(GoldilocksProfile::PROFILE, 15).unwrap();
    assert!(matches!(
        BrakeFri::<F128Profile>::new(params.clone()),
        Err(PcsError::ProfileMismatch)
    ));
    let pcs = BrakeFri::<GoldilocksProfile>::new(params.clone()).unwrap();
    let (commitment, state) = pcs
        .commit((0..params.n()).map(F::from_usize).collect(), &execution)
        .unwrap();
    let opening = pcs.prove(&state, F::TWO, &execution).unwrap();
    pcs.verify(&commitment, F::TWO, opening.y, &opening.proof, &execution)
        .unwrap();
    let other_size = BrakeFri::<GoldilocksProfile>::new(
        BrakeParams::new(GoldilocksProfile::PROFILE, 14).unwrap(),
    )
    .unwrap();
    assert!(
        other_size
            .verify(&commitment, F::TWO, opening.y, &opening.proof, &execution)
            .is_err()
    );
}
