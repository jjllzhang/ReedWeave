use super::*;

#[test]
fn measured_repetitions_and_failures_use_original_paths() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("core-timing-{}-{unique}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let settings = Settings {
        out: root.clone(),
        seed: 123,
        repetitions: 2,
        max_memory_mib: None,
        time_limit_seconds: None,
        allow_memory_overcommit: false,
    };
    for protocol in [Protocol::Fri, Protocol::Stir] {
        let case = Case {
            protocol,
            field: Field::Goldilocks,
            log_n: 10,
            threads: 1,
        };
        assert_eq!(
            case.csv_path(&settings),
            root.join(protocol.name().to_uppercase())
                .join("goldilocks.csv")
        );
        let calls = AtomicUsize::new(0);
        run_trials(&case, &settings, |_| {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(Trial {
                commit_time: 0.1,
                prove_time: 0.2,
                verify_time: 0.3,
                commitment_size: 33,
                opening_proof_size: 100,
            })
        })
        .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 3);
        let path = case.csv_path(&settings);
        let before = std::fs::read_to_string(&path).unwrap();
        assert_eq!(before.lines().count(), 3);
        assert!(
            before
                .lines()
                .skip(1)
                .all(|r| r.ends_with("100.000,200.000,300.000,0.130"))
        );
        // Warmup succeeds, then a transport failure must not append a success row.
        let calls = AtomicUsize::new(0);
        assert!(
            run_trials(&case, &settings, |_| {
                if calls.fetch_add(1, Ordering::Relaxed) == 0 {
                    Ok(Trial {
                        commit_time: 0.0,
                        prove_time: 0.0,
                        verify_time: 0.0,
                        commitment_size: 33,
                        opening_proof_size: 100,
                    })
                } else {
                    decode_transport::<u8, u8>(&1, &[2], &[3])?;
                    unreachable!()
                }
            })
            .is_err()
        );
        assert_eq!(std::fs::read_to_string(path).unwrap(), before);
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn all_audited_sizes_reach_the_target_with_actual_extension_types() {
    for field in [Field::Goldilocks] {
        for protocol in [Protocol::Fri, Protocol::Stir] {
            for log_n in 20..=30 {
                let case = Case {
                    protocol,
                    field,
                    log_n,
                    threads: 1,
                };
                let report = audit(&case).unwrap();
                assert!(report.bits >= 100.0);
                assert_eq!(
                    report.queries.len(),
                    match protocol {
                        Protocol::Fri => 1,
                        Protocol::Stir => log_n / 2,
                        Protocol::Whir => unreachable!(),
                    }
                );
                assert_eq!(
                    report.terminal,
                    match protocol {
                        Protocol::Fri => params::FRI_TERMINAL_COEFFICIENTS,
                        Protocol::Stir => 1 << (log_n % 2),
                        Protocol::Whir => unreachable!(),
                    }
                );
            }
        }
    }
}

fn transport_rejections<PCS>(pcs: PCS)
where
    PCS: Pcs<
            GoldilocksCubic,
            Challenger<Goldilocks>,
            Domain = TwoAdicMultiplicativeCoset<Goldilocks>,
        >,
    PCS::Commitment: PartialEq,
    Challenger<Goldilocks>: CanObserve<PCS::Commitment>,
{
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
    let domain = pcs.natural_domain_for_degree(1 << 10);
    let (commitment, state) = pcs.commit([(
        domain,
        RowMajorMatrix::new_col(vec![Goldilocks::ONE; 1 << 10]),
    )]);
    let z = GoldilocksCubic::from_basis_coefficients_fn(|i| Goldilocks::from_usize(i + 7));
    let challenger = || {
        let mut c = Challenger::<Goldilocks>::new(b"transport-test");
        c.observe(commitment.clone());
        FieldChallenger::<Goldilocks>::observe_algebra_element(&mut c, z);
        c
    };
    let (opened, proof) = pcs.open(vec![(&state, vec![vec![z]])], &mut challenger());
    let roots = postcard::to_allocvec(&commitment).unwrap();
    let bytes = postcard::to_allocvec(&proof).unwrap();
    let receive = |root_bytes: &[u8], proof_bytes: &[u8]| {
        decode_transport::<PCS::Commitment, PCS::Proof>(&commitment, root_bytes, proof_bytes)
    };
    let (received, decoded) = receive(&roots, &bytes).unwrap();
    assert_eq!(postcard::to_allocvec(&received).unwrap(), roots);
    assert_eq!(postcard::to_allocvec(&decoded).unwrap(), bytes);
    pcs.verify(
        vec![(
            received.clone(),
            vec![(domain, vec![(z, opened[0][0][0].clone())])],
        )],
        &decoded,
        &mut challenger(),
    )
    .unwrap();
    let mut wrong_values = opened[0][0][0].clone();
    wrong_values[0] += GoldilocksCubic::ONE;
    assert!(
        pcs.verify(
            vec![(received, vec![(domain, vec![(z, wrong_values)])])],
            &decoded,
            &mut challenger(),
        )
        .is_err()
    );
    let mut wrong = roots.clone();
    *wrong.last_mut().unwrap() ^= 1;
    assert!(receive(&wrong, &bytes).is_err());
    let mut trailing_root = roots.clone();
    trailing_root.push(0);
    assert!(receive(&trailing_root, &bytes).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(receive(&roots, &trailing).is_err());
    assert!(receive(&roots, &bytes[..bytes.len() / 2]).is_err());
}

#[test]
fn fri_and_stir_keep_transport_and_protocol_checks() {
    ExecutionContext::new(1).unwrap().install(|| {
        transport_rejections(params::fri::<Goldilocks, GoldilocksCubic>());
        transport_rejections(params::stir::<Goldilocks, GoldilocksCubic>());
    });
}

#[test]
fn goldilocks_pcs_profiles_accept_serialized_single_polynomial_openings() {
    // Small API integration cases, outside the production benchmark range.
    // Call the trial directly: no CSV, process scheduling or repetitions.
    let settings = Settings {
        out: Default::default(),
        seed: 20260906,
        repetitions: 1,
        max_memory_mib: None,
        time_limit_seconds: None,
        allow_memory_overcommit: false,
    };
    let execution = ExecutionContext::new(1).unwrap();
    for field in [Field::Goldilocks] {
        for protocol in [Protocol::Fri, Protocol::Stir] {
            let case = Case {
                protocol,
                field,
                log_n: 10,
                threads: 1,
            };
            let measured = execution
                .install(|| {
                    let mut points = Fixture(123);
                    match (field, protocol) {
                        (_, Protocol::Whir) => unreachable!(),
                        (Field::Goldilocks, Protocol::Fri) => {
                            trial::<Goldilocks, GoldilocksCubic, _>(
                                &case,
                                &settings,
                                &mut points,
                                params::fri,
                            )
                        }
                        (Field::Goldilocks, Protocol::Stir) => {
                            trial::<Goldilocks, GoldilocksCubic, _>(
                                &case,
                                &settings,
                                &mut points,
                                params::stir,
                            )
                        }
                    }
                })
                .unwrap();
            assert_eq!(
                measured.commitment_size,
                if protocol == Protocol::Fri { 33 } else { 34 }
            );
            assert!(measured.opening_proof_size > 0);
        }
    }
}
