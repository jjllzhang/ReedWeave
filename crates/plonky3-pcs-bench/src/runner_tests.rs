use super::*;

#[test]
fn all_audited_sizes_reach_the_target_with_actual_extension_types() {
    for field in [Field::Goldilocks, Field::F128] {
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
                    }
                );
                assert_eq!(
                    report.terminal,
                    match protocol {
                        Protocol::Fri => brakefri_primitives::TERMINAL_COEFFICIENTS,
                        Protocol::Stir => 1 << (log_n % 2),
                    }
                );
            }
        }
    }
}

#[test]
fn four_pcs_profiles_accept_serialized_single_polynomial_openings() {
    // Small API integration cases, outside the production benchmark range.
    // Call the trial directly: no CSV, process scheduling or repetitions.
    let settings = Settings {
        out: Default::default(),
        seed: 20260906,
        repetitions: 1,
        max_memory_mib: None,
        time_limit_seconds: None,
    };
    let execution = ExecutionContext::new(1).unwrap();
    for field in [Field::Goldilocks, Field::F128] {
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
                        (Field::F128, Protocol::Fri) => trial::<F128, F128Quadratic, _>(
                            &case,
                            &settings,
                            &mut points,
                            params::fri,
                        ),
                        (Field::F128, Protocol::Stir) => trial::<F128, F128Quadratic, _>(
                            &case,
                            &settings,
                            &mut points,
                            params::stir,
                        ),
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
