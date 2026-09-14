use std::process::Command;

fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_plonky3-pcs-bench"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn build_profile_is_reported_by_help_and_audited_preflight() {
    let (rate, queries) = if cfg!(feature = "rate-half") {
        ("1/2", "244")
    } else {
        ("1/4", "151")
    };
    let help = cli(&["--help"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains(&format!("initial rate {rate}")));
    let output = cli(&[
        "preflight", "--protocols", "fri", "--log-n", "20", "--threads", "1",
        "--allow-memory-overcommit",
    ]);
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains(&format!("rate={rate}")));
    assert!(text.contains(&format!("queries={queries} ")));
}

#[test]
fn whir_preflight_defaults_to_goldilocks_20_through_28() {
    let output = cli(&["preflight", "--protocols", "whir"]);
    // Available memory may reject the largest sizes; all cases must still be
    // audited without allocating proof data, producing CSVs or panicking.
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        stderr.matches("algebraic_bound_bits=").count(),
        18,
        "{stderr}"
    );
    assert!(stderr.contains("log_n=20"));
    assert!(stderr.contains("log_n=28"));
    assert!(!stderr.contains("log_n=29") && !stderr.contains("f128"));
    assert!(!stderr.contains("panicked"));
}

#[test]
fn whir_rejects_unsupported_fields_sizes_and_threads_before_output() {
    for (field, size, threads, error) in [
        ("f128", "20", "1", "invalid value"),
        ("goldilocks", "19", "1", "20..=28"),
        ("goldilocks", "29", "1", "20..=28"),
        ("goldilocks", "20", "2", "1 or 32"),
    ] {
        let output = cli(&[
            "run",
            "--protocol",
            "whir",
            "--field",
            field,
            "--log-n",
            size,
            "--threads",
            threads,
        ]);
        assert!(!output.status.success());
        assert!(String::from_utf8(output.stderr).unwrap().contains(error));
    }
    let output = cli(&["preflight", "--protocols", "whir", "--log-n", "20..29"]);
    assert!(!output.status.success());
}

#[test]
fn all_protocol_entrypoints_reject_removed_field() {
    for protocol in ["fri", "stir", "whir"] {
        for command in ["preflight", "sweep"] {
            let output = cli(&[command, "--protocols", protocol, "--fields", "f128"]);
            assert!(!output.status.success());
            assert!(
                String::from_utf8(output.stderr)
                    .unwrap()
                    .contains("invalid value")
            );
        }
        let output = cli(&[
            "run",
            "--protocol",
            protocol,
            "--field",
            "f128",
            "--log-n",
            "20",
            "--threads",
            "1",
        ]);
        assert!(!output.status.success());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("invalid value")
        );
    }
}

#[test]
fn default_matrix_is_goldilocks_fri_and_stir() {
    let output = cli(&["preflight"]);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        stderr.matches("algebraic_bound_bits=").count(),
        44,
        "{stderr}"
    );
    assert!(!stderr.contains("whir "));
}

#[test]
fn mixed_protocol_defaults_only_include_supported_cases() {
    let output = cli(&["preflight", "--protocols", "fri,stir,whir"]);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        stderr.matches("algebraic_bound_bits=").count(),
        62,
        "{stderr}"
    );
    assert!(!stderr.contains("whir f128"));
}

#[test]
fn overcommit_preflight_keeps_security_audits_and_explicit_caps() {
    let args = [
        "preflight", "--protocols", "fri,stir,whir", "--log-n", "28",
        "--threads", "32", "--allow-memory-overcommit",
    ];
    let output = cli(&args);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(String::from_utf8_lossy(&output.stderr).matches("algebraic_bound_bits=").count(), 3);
    let mut capped = args.to_vec();
    capped.extend(["--max-memory-mib", "1"]);
    let output = cli(&capped);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("explicit memory cap"));
}

#[test]
fn whir_resource_rejection_does_not_write_measurements() {
    let path = std::env::temp_dir().join(format!("whir-rejected-{}", std::process::id()));
    assert!(!path.exists());
    let output = cli(&[
        "run",
        "--protocol",
        "whir",
        "--field",
        "goldilocks",
        "--log-n",
        "20",
        "--threads",
        "1",
        "--max-memory-mib",
        "1",
        "--out",
        path.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("unmeasured")
    );
    assert!(!path.exists());
}
