use super::*;
use brakefri_primitives::{
    hash::{Blake3Suite, KeccakSuite, Sha256Suite},
    transcript::{F128Profile, GoldilocksProfile},
};

fn algebra<P: FieldProfile>() {
    let execution = ExecutionContext::new(1).unwrap();
    let dft = NaturalOrderDft::<P::Base>::default();
    let mut transcript = Transcript::<P, Blake3Suite>::new(14, &Blake3Suite).unwrap();
    for log_k in 1..=5 {
        let k = 1 << log_k;
        let coefficients: Vec<_> = (0..k).map(|_| transcript.sample_challenge()).collect();
        let mut padded = coefficients.clone();
        padded.resize(2 * k, P::Challenge::ZERO);
        let word = dft
            .dft_extension_batch(RowMajorMatrix::new_col(padded), &execution)
            .unwrap()
            .values;
        let omega = P::Base::two_adic_generator(log_k + 1);
        for gamma in [
            P::Challenge::ZERO,
            P::Challenge::ONE,
            transcript.sample_challenge(),
        ] {
            let folded_coefficients = fold_coefficients(&coefficients, gamma);
            let folded_word = fold_word::<P>(&word, gamma, omega);
            for z in [P::Challenge::ZERO, transcript.sample_challenge()] {
                let even = horner(coefficients.iter().step_by(2).copied(), z.square());
                let odd = horner(coefficients.iter().skip(1).step_by(2).copied(), z.square());
                assert_eq!(horner(coefficients.iter().copied(), z), even + z * odd);
                assert_eq!(
                    horner(folded_coefficients.iter().copied(), z.square()),
                    even + gamma * odd
                );
            }
            // Independent direct evaluation checks every child, not only sampled points.
            let next_root = omega.square();
            for (t, &value) in folded_word.iter().enumerate() {
                assert_eq!(
                    value,
                    horner(
                        folded_coefficients.iter().copied(),
                        P::Challenge::from(next_root.exp_u64(t as u64))
                    )
                );
            }
            // Use both signed representatives of every pair.
            for t in 0..2 * k {
                let x = omega.exp_u64(t as u64);
                let plus = word[t];
                let minus = word[t ^ k];
                assert_eq!(
                    (plus + minus) * P::Base::TWO.inverse()
                        + gamma * (plus - minus) * (P::Base::TWO * x).inverse(),
                    folded_word[t % k]
                );
            }
        }
    }
}

#[test]
fn coefficient_word_folds_match_direct_polynomials_and_both_signs() {
    algebra::<GoldilocksProfile>();
    algebra::<F128Profile>();
}

/// Small reference prover: re-evaluate each folded polynomial directly. The production
/// prover instead folds the retained words. Optionally corrupt one selected scalar
/// oracle while keeping all scalar identities, roots, and authentications valid.
fn reference<P: FieldProfile, S: HashSuite>(
    pcs: &BrakeFri<P, S>,
    state: &ProverData<P, S>,
    z: P::Base,
    execution: &ExecutionContext,
    corrupt_layer: Option<usize>,
) -> (Opening<P>, Vec<usize>) {
    let k = pcs.params.k();
    let blocks: Vec<_> = state
        .coefficients
        .chunks_exact(k)
        .map(|block| {
            block
                .iter()
                .enumerate()
                .map(|(a, &c)| c * z.exp_u64(a as u64))
                .sum()
        })
        .collect();
    let y: P::Base = blocks
        .iter()
        .enumerate()
        .map(|(i, &v)| v * z.exp_u64((i * k) as u64))
        .sum();
    let mut transcript = Transcript::<P, S>::new(pcs.params.log_n(), &pcs.suite).unwrap();
    transcript.observe_statement(&state.commitment.root, z);
    transcript.observe_claim(y);
    transcript.observe_block_values(&blocks).unwrap();
    let r: Vec<_> = (0..M).map(|_| transcript.sample_challenge()).collect();
    // Catch a controller using a fixed r_0 or powers of one seed.
    assert_ne!(r[0], P::Challenge::ONE);
    assert_ne!(r[2], r[1].square());
    let mut coefficients: Vec<P::Challenge> = (0..k)
        .map(|a| (0..M).map(|i| r[i] * state.coefficients[i * k + a]).sum())
        .collect();
    let mut point = z;
    let mut rounds = Vec::new();
    let mut layers = Vec::new();
    for j in 0..pcs.params.rounds() {
        let square = point.square();
        let even: P::Challenge = coefficients
            .iter()
            .step_by(2)
            .enumerate()
            .map(|(a, &c)| c * square.exp_u64(a as u64))
            .sum();
        let odd: P::Challenge = coefficients
            .iter()
            .skip(1)
            .step_by(2)
            .enumerate()
            .map(|(a, &c)| c * square.exp_u64(a as u64))
            .sum();
        transcript.observe_round(j, even, odd).unwrap();
        let gamma = transcript.sample_challenge();
        coefficients = coefficients
            .chunks_exact(2)
            .map(|pair| pair[0] + gamma * pair[1])
            .collect();
        let height = pcs.params.domain_size() >> (j + 1);
        let root = P::Base::two_adic_generator(pcs.params.log_domain_size() - j - 1);
        let word: Vec<_> = (0..height)
            .map(|t| {
                let x = root.exp_u64(t as u64);
                let value: P::Challenge = coefficients
                    .iter()
                    .enumerate()
                    .map(|(a, &c)| c * x.exp_u64(a as u64))
                    .sum();
                value
                    + if corrupt_layer == Some(j) {
                        P::Challenge::ONE
                    } else {
                        P::Challenge::ZERO
                    }
            })
            .collect();
        let (root, layer) = pcs
            .scalar_mmcs
            .commit(RowMajorMatrix::new_col(word), execution)
            .unwrap();
        transcript.observe_round_root(j, &root).unwrap();
        rounds.push(Round {
            even_value: even,
            odd_value: odd,
            next_oracle_root: root,
        });
        layers.push(layer);
        point = square;
    }
    let terminal_constant = coefficients[0];
    let terminal_values = [terminal_constant; 2];
    transcript.observe_terminal(terminal_constant, terminal_values);
    let starts = transcript.sample_queries();
    // Independent oracle-query reference: enumerate the natural domain and test
    // membership using the signed points, rather than call production query_sets.
    let sets: Vec<Vec<usize>> = (0..pcs.params.rounds())
        .map(|j| {
            let height = pcs.params.domain_size() >> j;
            (0..height)
                .filter(|&t| {
                    starts.iter().any(|&start| {
                        let index = start % height;
                        t == index || t == (index + height / 2) % height
                    })
                })
                .collect()
        })
        .collect();
    assert_eq!(query_sets(&pcs.params, &starts), sets);
    let initial_opening = pcs
        .initial_mmcs
        .open_multi_batch(&sets[0], &state.initial)
        .unwrap();
    let scalar_openings = (1..pcs.params.rounds())
        .map(|j| {
            let opening = pcs
                .scalar_mmcs
                .open_multi_batch(&sets[j], &layers[j - 1])
                .unwrap();
            ScalarOpening {
                values: opening.rows.into_iter().map(|row| row[0]).collect(),
                proof: opening.proof,
            }
        })
        .collect();
    (
        Opening {
            y,
            proof: BrakeProof {
                block_values: blocks,
                rounds,
                terminal_constant,
                terminal_values,
                initial_opening,
                scalar_openings,
            },
        },
        starts,
    )
}

fn interoperability<P: FieldProfile, S: HashSuite>(suite: S) {
    let execution = ExecutionContext::new(1).unwrap();
    let params = BrakeParams::new(P::PROFILE, 14).unwrap();
    let pcs = BrakeFri::<P, S>::new(params.clone(), suite).unwrap();
    let coefficients: Vec<_> = (0..params.n())
        .map(|i| P::Base::from_usize(i + 3))
        .collect();
    let original_allocation = coefficients.as_ptr();
    let (commitment, state) = pcs.commit(coefficients, &execution).unwrap();
    assert_eq!(state.coefficients.as_ptr(), original_allocation);
    let z = P::Base::ZERO;
    let production = pcs.prove(&state, z, &execution).unwrap();
    let (reference, starts) = reference(&pcs, &state, z, &execution, None);
    assert_eq!(starts.len(), Q);
    assert!(starts.iter().any(|&t| t >= params.domain_size() / 2));
    let mut unique = starts.clone();
    unique.sort_unstable();
    unique.dedup();
    assert!(unique.len() < starts.len());
    assert_eq!(production.y, reference.y);
    assert_eq!(production.proof.block_values, reference.proof.block_values);
    for (a, b) in production.proof.rounds.iter().zip(&reference.proof.rounds) {
        assert_eq!(a.even_value, b.even_value);
        assert_eq!(a.odd_value, b.odd_value);
        assert_eq!(a.next_oracle_root, b.next_oracle_root);
    }
    assert_eq!(
        production.proof.terminal_constant,
        reference.proof.terminal_constant
    );
    assert_eq!(
        production.proof.terminal_values,
        reference.proof.terminal_values
    );
    assert_eq!(
        production.proof.initial_opening.rows,
        reference.proof.initial_opening.rows
    );
    assert_eq!(
        production.proof.initial_opening.proof.sibling_hashes,
        reference.proof.initial_opening.proof.sibling_hashes
    );
    for (a, b) in production
        .proof
        .scalar_openings
        .iter()
        .zip(&reference.proof.scalar_openings)
    {
        assert_eq!(a.values, b.values);
        assert_eq!(a.proof.sibling_hashes, b.proof.sibling_hashes);
    }
    pcs.verify(&commitment, z, reference.y, &reference.proof, &execution)
        .unwrap();
    for layer in 0..params.rounds() - 1 {
        let (forged, _) = self::reference(&pcs, &state, z, &execution, Some(layer));
        // The first inconsistent edge ends in pi_(layer+1). All earlier folds,
        // scalar checks, terminal checks, and shared authentications are valid.
        assert!(matches!(
            pcs.verify(&commitment, z, forged.y, &forged.proof, &execution),
            Err(PcsError::Fold { query: 0, round }) if round == layer
        ));
    }
}

#[test]
fn reference_prover_transcript_interoperability_and_authenticated_bad_folds() {
    interoperability::<GoldilocksProfile, _>(Blake3Suite);
    interoperability::<F128Profile, _>(Blake3Suite);
    interoperability::<GoldilocksProfile, _>(Sha256Suite);
    interoperability::<F128Profile, _>(Sha256Suite);
    interoperability::<GoldilocksProfile, _>(KeccakSuite);
    interoperability::<F128Profile, _>(KeccakSuite);
}

/// A degree-k monomial in one initial column folds consistently through every
/// queried scalar tree, but cannot fold to the claimed zero terminal word.
/// This tests the final local equality after all other verification gates pass.
fn bad_final_fold<P: FieldProfile>() {
    let execution = ExecutionContext::new(1).unwrap();
    let params = BrakeParams::new(P::PROFILE, 14).unwrap();
    let pcs = BrakeFri::<P, _>::new(params.clone(), Blake3Suite).unwrap();
    let omega = P::Base::two_adic_generator(params.log_domain_size());
    let mut matrix = vec![P::Base::ZERO; params.domain_size() * M];
    for t in 0..params.domain_size() {
        matrix[t * M] = omega.exp_u64((t * params.k()) as u64);
    }
    let (root, initial) = pcs
        .initial_mmcs
        .commit(RowMajorMatrix::new(matrix, M), &execution)
        .unwrap();
    let commitment = Commitment { root };
    let blocks = vec![P::Base::ZERO; M];
    let mut transcript = pcs
        .start(&commitment, P::Base::ZERO, P::Base::ZERO, &blocks)
        .unwrap();
    let weights: Vec<_> = (0..M).map(|_| transcript.sample_challenge()).collect();
    assert_ne!(weights[0], P::Challenge::ZERO);
    let mut rounds = Vec::new();
    let mut layers = Vec::new();
    for j in 0..params.rounds() {
        transcript
            .observe_round(j, P::Challenge::ZERO, P::Challenge::ZERO)
            .unwrap();
        let _gamma = transcript.sample_challenge();
        let height = params.domain_size() >> (j + 1);
        let degree = params.k() >> (j + 1);
        // Direct polynomial evaluation, independent of the production fold code.
        // All exponents before the last fold are even, so gamma has no effect.
        let word = (0..height)
            .map(|t| {
                if j + 1 == params.rounds() {
                    P::Challenge::ZERO
                } else {
                    weights[0] * omega.exp_u64(((t << (j + 1)) * degree) as u64)
                }
            })
            .collect();
        let (root, layer) = pcs
            .scalar_mmcs
            .commit(RowMajorMatrix::new_col(word), &execution)
            .unwrap();
        transcript.observe_round_root(j, &root).unwrap();
        rounds.push(Round {
            even_value: P::Challenge::ZERO,
            odd_value: P::Challenge::ZERO,
            next_oracle_root: root,
        });
        layers.push(layer);
    }
    transcript.observe_terminal(P::Challenge::ZERO, [P::Challenge::ZERO; 2]);
    let starts = transcript.sample_queries();
    assert_eq!(starts.len(), Q);
    assert!(starts.iter().any(|&t| t < params.domain_size() / 2));
    assert!(starts.iter().any(|&t| t >= params.domain_size() / 2));
    let sets = query_sets(&params, &starts);
    let proof = BrakeProof {
        block_values: blocks,
        rounds,
        terminal_constant: P::Challenge::ZERO,
        terminal_values: [P::Challenge::ZERO; 2],
        initial_opening: pcs
            .initial_mmcs
            .open_multi_batch(&sets[0], &initial)
            .unwrap(),
        scalar_openings: (1..params.rounds())
            .map(|j| {
                let opening = pcs
                    .scalar_mmcs
                    .open_multi_batch(&sets[j], &layers[j - 1])
                    .unwrap();
                ScalarOpening {
                    values: opening.rows.into_iter().map(|row| row[0]).collect(),
                    proof: opening.proof,
                }
            })
            .collect(),
    };
    assert!(matches!(
        pcs.verify(&commitment, P::Base::ZERO, P::Base::ZERO, &proof, &execution),
        Err(PcsError::Fold { query: 0, round }) if round == params.rounds() - 1
    ));
}

#[test]
fn authenticated_oracles_must_satisfy_the_final_fold() {
    bad_final_fold::<GoldilocksProfile>();
    bad_final_fold::<F128Profile>();
}

#[test]
fn nonempty_boundaries_and_exact_upstream_authentication() {
    let execution = ExecutionContext::new(2).unwrap();
    let params = BrakeParams::new(GoldilocksProfile::PROFILE, 18).unwrap();
    let pcs = BrakeFri::<GoldilocksProfile, _>::new(params.clone(), Blake3Suite).unwrap();
    type F = <GoldilocksProfile as FieldProfile>::Base;
    let (commitment, state) = pcs
        .commit(
            (0..params.n()).map(|i| F::from_usize(i + 1)).collect(),
            &execution,
        )
        .unwrap();
    let opening = pcs.prove(&state, F::TWO, &execution).unwrap();
    pcs.verify(&commitment, F::TWO, opening.y, &opening.proof, &execution)
        .unwrap();
    assert!(
        !opening
            .proof
            .initial_opening
            .proof
            .sibling_hashes
            .is_empty()
    );
    for mutation in 0..3 {
        let mut proof = opening.proof.clone();
        match mutation {
            0 => {
                proof.initial_opening.proof.sibling_hashes.pop();
            }
            1 => proof.initial_opening.proof.sibling_hashes.push([0; 32]),
            _ => proof.initial_opening.proof.sibling_hashes[0][0] ^= 1,
        }
        assert!(
            pcs.verify(&commitment, F::TWO, opening.y, &proof, &execution)
                .is_err()
        );
    }
    // Interoperate with the M1 ordinary-path test adapter at each queried index.
    let mut transcript = pcs
        .start(&commitment, F::TWO, opening.y, &opening.proof.block_values)
        .unwrap();
    for _ in 0..M {
        let _ = transcript.sample_challenge();
    }
    for (j, round) in opening.proof.rounds.iter().enumerate() {
        transcript
            .observe_round(j, round.even_value, round.odd_value)
            .unwrap();
        let _ = transcript.sample_challenge();
        transcript
            .observe_round_root(j, &round.next_oracle_root)
            .unwrap();
    }
    transcript.observe_terminal(
        opening.proof.terminal_constant,
        opening.proof.terminal_values,
    );
    let sets = query_sets(&params, &transcript.sample_queries());
    // A valid multiproof for another canonical set at the same root must not
    // substitute for the verifier's transcript-derived positions.
    let mut substituted = sets[0].clone();
    let other = (0..params.domain_size())
        .find(|index| substituted.binary_search(index).is_err())
        .unwrap();
    substituted[0] = other;
    substituted.sort_unstable();
    let mut forged = opening.proof.clone();
    forged.initial_opening = pcs
        .initial_mmcs
        .open_multi_batch(&substituted, &state.initial)
        .unwrap();
    assert!(matches!(
        pcs.verify(&commitment, F::TWO, opening.y, &forged, &execution),
        Err(PcsError::Mmcs(_))
    ));
    for (&index, expected) in sets[0].iter().zip(&opening.proof.initial_opening.rows) {
        let (row, path) = pcs.initial_mmcs.open_batch(index, &state.initial).unwrap();
        assert_eq!(&row, expected);
        pcs.initial_mmcs
            .verify_batch(
                &commitment.root,
                Dimensions {
                    width: M,
                    height: params.domain_size(),
                },
                index,
                &row,
                &path,
            )
            .unwrap();
    }
}
