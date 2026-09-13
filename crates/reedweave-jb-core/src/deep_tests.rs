//! Algebraic gates under controlled challenges, and the complete noisy relation.
use super::*;
use crate::{BaseField, PublicParams};
use reedweave_primitives::transcript::{
    GoldilocksBaseProfile, GoldilocksCubicProfile, GoldilocksProfile, GoldilocksQuinticProfile,
};
fn params<P: FieldProfile>() -> JbParams {
    JbParams::new(PublicParams {
        base_field: BaseField::Goldilocks,
        extension_degree: P::PROFILE.extension_degree(),
        log_d: 5,
        m: 4,
        blowup: 4,
        terminal_coefficients: 2,
        num_queries: 40,
        agreement_numerator: 3,
        agreement_denominator: 4,
    })
    .unwrap()
}
fn controlled<P: FieldProfile>() {
    let params = params::<P>();
    let coefficients: Vec<_> = (0..params.d())
        .map(|i| P::Base::from_usize(i + 3))
        .collect();
    // Includes coincident points, base OOD points and zero challenges. These are
    // legal interactive executions even when rare under the production hash.
    for zeta in [P::Challenge::ZERO, P::Challenge::TWO] {
        assert_ne!(zeta.exp_u64(params.domain_size() as u64), P::Challenge::ONE);
        for target in [P::Challenge::ZERO, zeta, P::Challenge::from_u8(3)] {
            let c = deep_values::<P>(&coefficients, params.m(), zeta);
            let v = deep_values::<P>(&coefficients, params.m(), target);
            for alpha in [P::Challenge::ZERO, P::Challenge::ONE, P::Challenge::TWO] {
                let weights = power_weights(alpha, params.m());
                let folded: Vec<_> = coefficients
                    .chunks_exact(params.m())
                    .map(|row| combine::<P>(row, &weights))
                    .collect();
                let claim0 = combine_extension(&v, &weights);
                let deep_claim0 = combine_extension(&c, &weights);
                // Wrong c_0 always changes the combined claim, even at alpha=0.
                let mut bad_c = c.clone();
                bad_c[0] += P::Challenge::ONE;
                assert_ne!(deep_claim0, combine_extension(&bad_c, &weights));
                for gamma in [P::Challenge::ZERO, P::Challenge::ONE, P::Challenge::TWO] {
                    let mut coefficients = folded.clone();
                    let mut point = target;
                    let mut deep_point = zeta;
                    let mut claim = claim0;
                    let mut deep_claim = deep_claim0;
                    for j in 0..params.rounds() {
                        let round = JbRound {
                            even_value: horner(
                                coefficients.iter().step_by(2).copied(),
                                point.square(),
                            ),
                            odd_value: horner(
                                coefficients.iter().skip(1).step_by(2).copied(),
                                point.square(),
                            ),
                            deep_even_value: horner(
                                coefficients.iter().step_by(2).copied(),
                                deep_point.square(),
                            ),
                            deep_odd_value: horner(
                                coefficients.iter().skip(1).step_by(2).copied(),
                                deep_point.square(),
                            ),
                        };
                        check_round(j, point, claim, deep_point, deep_claim, &round).unwrap();
                        assert!(
                            matches!(check_round(j, point, claim, deep_point, deep_claim + P::Challenge::ONE, &round), Err(PcsError::DeepScalar(r)) if r == j)
                        );
                        let mut bad = round.clone();
                        bad.deep_even_value += P::Challenge::ONE;
                        assert!(
                            matches!(check_round(j, point, claim, deep_point, deep_claim, &bad), Err(PcsError::DeepScalar(r)) if r == j)
                        );
                        let mut bad = round.clone();
                        bad.deep_odd_value += P::Challenge::ONE;
                        if deep_point != P::Challenge::ZERO {
                            assert!(
                                matches!(check_round(j, point, claim, deep_point, deep_claim, &bad), Err(PcsError::DeepScalar(r)) if r == j)
                            );
                        } else {
                            // At zero, b does not enter this round's identity but
                            // a nonzero gamma binds it through the next claim.
                            check_round(j, point, claim, deep_point, deep_claim, &bad).unwrap();
                            if gamma != P::Challenge::ZERO {
                                assert_ne!(
                                    round.deep_even_value + gamma * round.deep_odd_value,
                                    bad.deep_even_value + gamma * bad.deep_odd_value
                                );
                            }
                        }
                        claim = round.even_value + gamma * round.odd_value;
                        deep_claim = round.deep_even_value + gamma * round.deep_odd_value;
                        point = point.square();
                        deep_point = deep_point.square();
                        coefficients = fold_coefficients(&coefficients, gamma);
                        assert_ne!(
                            deep_point.exp_u64((params.domain_size() >> (j + 1)) as u64),
                            P::Challenge::ONE
                        );
                    }
                    check_terminal(&coefficients, point, claim, deep_point, deep_claim).unwrap();
                    assert!(matches!(
                        check_terminal(
                            &coefficients,
                            point,
                            claim,
                            deep_point,
                            deep_claim + P::Challenge::ONE
                        ),
                        Err(PcsError::DeepTerminal)
                    ));
                    if point != deep_point {
                        // Add X-point: first terminal equation is unchanged, the
                        // second must reject. No FS/query mutation is involved.
                        let mut bad = coefficients.clone();
                        bad[0] -= point;
                        bad[1] += P::Challenge::ONE;
                        assert!(matches!(
                            check_terminal(&bad, point, claim, deep_point, deep_claim),
                            Err(PcsError::DeepTerminal)
                        ));
                    }
                }
            }
        }
    }
}
#[test]
fn controlled_dual_chain_checks_zero_challenges_coincident_points_and_each_deep_gate() {
    controlled::<GoldilocksBaseProfile>();
    controlled::<GoldilocksProfile>();
    controlled::<GoldilocksCubicProfile>();
    controlled::<GoldilocksQuinticProfile>();
}
fn noisy<P: FieldProfile>() {
    let execution = ExecutionContext::new(1).unwrap();
    let params = params::<P>();
    let pcs = ReedWeaveJb::<P>::new(params.clone()).unwrap();
    let coefficients: Vec<_> = (0..params.d() - 1)
        .map(|i| P::Base::from_usize(i + 1))
        .collect();
    let (honest, state) = pcs.commit(coefficients.clone(), &execution).unwrap();
    pcs.open_deep(&honest, &coefficients, state.encoded_word(), &execution)
        .unwrap();
    // N=32, a=3/4: E<8. Recommit each noisy word BEFORE deriving zeta/c.
    let commit_word = |word: &RowMajorMatrix<P::Base>| {
        let (root, _) = pcs.initial_mmcs.commit(word.clone(), &execution).unwrap();
        let zeta = commit_challenge::<P>(params.transcript_context(), &root).unwrap();
        JbCommitment::<P> {
            context_id: params.transcript_context().identifier().unwrap(),
            root,
            zeta,
            deep_values: deep_values::<P>(&coefficients, params.m(), zeta),
        }
    };
    for errors in [0, 1, 7, 8, 9] {
        let mut word = state.encoded_word().clone();
        for row in 0..errors {
            // All components differ in the same columns: still just E errors.
            for column in 0..params.m() {
                word.values[row * params.m() + column] += P::Base::ONE;
            }
        }
        let commitment = commit_word(&word);
        let result = pcs.open_deep(&commitment, &coefficients, &word, &execution);
        if errors < 8 {
            result.unwrap();
        } else {
            assert!(matches!(result, Err(PcsError::OpeningDistance)));
        }
        let mut bad = commitment.clone();
        bad.deep_values[0] += P::Challenge::ONE;
        if errors < 8 {
            assert!(matches!(
                pcs.open_deep(&bad, &coefficients, &word, &execution),
                Err(PcsError::DeepOpening)
            ));
        }
    }
    // Four errors in each component separately can still have union size eight.
    let mut word = state.encoded_word().clone();
    for row in 0..4 {
        word.values[row * params.m()] += P::Base::ONE;
    }
    for row in 4..8 {
        word.values[row * params.m() + 1] += P::Base::ONE;
    }
    let commitment = commit_word(&word);
    assert!(matches!(
        pcs.open_deep(&commitment, &coefficients, &word, &execution),
        Err(PcsError::OpeningDistance)
    ));
    assert!(matches!(
        pcs.open_deep(&honest, &coefficients, &word, &execution),
        Err(PcsError::OpeningRoot)
    ));
    let mut bad = honest.clone();
    bad.context_id[0] ^= 1;
    assert!(matches!(
        pcs.open_deep(&bad, &coefficients, state.encoded_word(), &execution),
        Err(PcsError::StateMismatch)
    ));
    let mut bad = honest.clone();
    bad.zeta = P::Challenge::ONE;
    assert!(matches!(
        pcs.validate_commitment(&bad),
        Err(PcsError::CommitmentChallenge)
    ));
    let mut bad = honest.clone();
    bad.zeta = if honest.zeta == P::Challenge::ZERO {
        P::Challenge::TWO
    } else {
        P::Challenge::ZERO
    };
    assert!(matches!(
        pcs.validate_commitment(&bad),
        Err(PcsError::CommitmentChallenge)
    ));
    let mut bad = honest.clone();
    bad.deep_values.pop();
    assert!(matches!(
        pcs.validate_commitment(&bad),
        Err(PcsError::Shape(_))
    ));
    let mut malformed = state.encoded_word().clone();
    malformed.width += 1;
    assert!(matches!(
        pcs.open_deep(&honest, &coefficients, &malformed, &execution),
        Err(PcsError::Shape(_))
    ));
    let mut malformed = state.encoded_word().clone();
    malformed.values.pop();
    assert!(matches!(
        pcs.open_deep(&honest, &coefficients, &malformed, &execution),
        Err(PcsError::Shape(_))
    ));
    assert!(matches!(
        pcs.open_deep(
            &honest,
            &vec![P::Base::ZERO; params.d() + 1],
            state.encoded_word(),
            &execution
        ),
        Err(PcsError::CoefficientCount { .. })
    ));
}
fn beyond_unique_radius<P: FieldProfile>() {
    let execution = ExecutionContext::new(1).unwrap();
    let params = JbParams::new(PublicParams {
        base_field: BaseField::Goldilocks,
        extension_degree: P::PROFILE.extension_degree(),
        log_d: 8,
        m: 4,
        blowup: 2,
        terminal_coefficients: 2,
        num_queries: 3,
        agreement_numerator: 23,
        agreement_denominator: 32,
    })
    .unwrap();
    let pcs = ReedWeaveJb::<P>::new(params.clone()).unwrap();
    let coefficients: Vec<_> = (0..params.d())
        .map(|i| P::Base::from_usize(i + 1))
        .collect();
    let (_, state) = pcs.commit(coefficients.clone(), &execution).unwrap();
    assert_eq!((params.k(), params.domain_size()), (64, 128));
    for errors in [32, 33, 34, 35, 36, 37] {
        let mut word = state.encoded_word().clone();
        for row in 0..errors {
            word.values[row * params.m()] += P::Base::ONE;
        }
        let (root, _) = pcs.initial_mmcs.commit(word.clone(), &execution).unwrap();
        let zeta = commit_challenge::<P>(params.transcript_context(), &root).unwrap();
        let commitment = JbCommitment::<P> {
            context_id: params.transcript_context().identifier().unwrap(),
            root,
            zeta,
            deep_values: deep_values::<P>(&coefficients, params.m(), zeta),
        };
        let result = pcs.open_deep(&commitment, &coefficients, &word, &execution);
        // UB accepts only E<=32; JB accepts E<36, not its exact boundary.
        if errors < 36 {
            result.unwrap();
        } else {
            assert!(matches!(result, Err(PcsError::OpeningDistance)));
        }
    }
}
#[test]
fn johnson_opening_accepts_noise_genuinely_beyond_unique_decoding() {
    beyond_unique_radius::<GoldilocksBaseProfile>();
    beyond_unique_radius::<GoldilocksProfile>();
    beyond_unique_radius::<GoldilocksCubicProfile>();
    beyond_unique_radius::<GoldilocksQuinticProfile>();
}

#[test]
fn noisy_full_opening_uses_strict_joint_column_distance_and_deep_values() {
    noisy::<GoldilocksBaseProfile>();
    noisy::<GoldilocksProfile>();
    noisy::<GoldilocksCubicProfile>();
    noisy::<GoldilocksQuinticProfile>();
}
