use std::{
    path::Path,
    process::{Command, Output},
};

const PP: &[&str] = &[
    "--base-field",
    "goldilocks",
    "--extension-degree",
    "1,2,3,5",
    "--log-d",
    "2",
    "--m",
    "1",
    "--blowup",
    "2",
    "--terminal-coefficients",
    "2",
    "--num-queries",
    "1",
    "--agreement-numerator",
    "6",
    "--agreement-denominator",
    "8",
];
const HEADER: &str = "base_field,extension_degree,log_d,m,blowup,terminal_coefficients,num_queries,agreement_numerator,agreement_denominator,threads,commit_time_ms,open_time_ms,verify_time_ms,proof_size_KiB";
fn bench(out: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_reedweave-jb-bench"))
        .args(args)
        .arg("--out")
        .arg(out)
        .output()
        .unwrap()
}
fn success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn tiny_all_profiles_verified_and_isolated() {
    let directory = tempfile::tempdir().unwrap();
    let mut args = vec!["preflight"];
    args.extend_from_slice(PP);
    let preflight = bench(directory.path(), &args);
    success(&preflight);
    let stdout = String::from_utf8_lossy(&preflight.stdout);
    assert_eq!(stdout.lines().count(), 4);
    assert!(
        stdout
            .lines()
            .all(|s| s.contains("geometry valid; security not evaluated")
                && s.contains("agreement=3/4")
                && s.contains("commitment="))
    );
    assert_eq!(directory.path().read_dir().unwrap().count(), 0);
    // Candidate grids are legal preflight, not ambiguous measurement campaigns.
    args[0] = "sweep";
    assert!(!bench(directory.path(), &args).status.success());
    assert_eq!(directory.path().read_dir().unwrap().count(), 0);
    std::fs::create_dir(directory.path().join("ReedWeave_UB")).unwrap();
    let historical = directory.path().join("ReedWeave_UB/goldilocks.csv");
    std::fs::write(&historical, "historical\n").unwrap();
    for degree in ["1", "2", "3", "5"] {
        let root = directory.path().join(degree);
        let mut args = vec!["sweep"];
        args.extend_from_slice(PP);
        let position = args
            .iter()
            .position(|&a| a == "--extension-degree")
            .unwrap();
        args[position + 1] = degree;
        args.extend_from_slice(&["--threads", "1,32", "--repetitions", "2"]);
        let sweep = bench(&root, &args);
        success(&sweep);
        let stderr = String::from_utf8_lossy(&sweep.stderr);
        assert_eq!(stderr.matches("timing_model=core-v1").count(), 2);
        let progress: Vec<_> = stderr
            .lines()
            .filter(|s| s.starts_with("WARMUP VERIFIED ") || s.starts_with("VERIFIED "))
            .collect();
        assert_eq!(progress.len(), 6);
        for case in progress.chunks_exact(3) {
            assert!(case[0].starts_with("WARMUP VERIFIED "));
            assert!(case[1].contains(" repetition=1 "));
            assert!(case[2].contains(" repetition=2 "));
            assert_eq!(
                case[0].split("proof_size=").nth(1),
                case[1].split("proof_size=").nth(1)
            );
        }
        let path = root.join("ReedWeave_JB/goldilocks.csv");
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().next().unwrap(), HEADER);
        assert_eq!(text.lines().count(), 5);
        for (index, row) in text.lines().skip(1).enumerate() {
            let columns: Vec<_> = row.split(',').collect();
            let threads = if index < 2 { "1" } else { "32" };
            assert_eq!(
                &columns[..10],
                [
                    "goldilocks",
                    degree,
                    "2",
                    "1",
                    "2",
                    "2",
                    "1",
                    "3",
                    "4",
                    threads
                ]
            );
            assert_eq!(columns.len(), 14);
            assert!(
                columns[10..13]
                    .iter()
                    .all(|v| v.parse::<f64>().unwrap() >= 0.0)
            );
            assert!(columns[13].parse::<f64>().unwrap() > 32.0 / 1024.0);
        }
        // A different fraction at the same size cannot append, even on another thread.
        let numerator = args
            .iter()
            .position(|&a| a == "--agreement-numerator")
            .unwrap();
        args[numerator + 1] = "7";
        let failed = bench(&root, &args);
        assert!(!failed.status.success());
        assert!(String::from_utf8_lossy(&failed.stderr).contains("mixed public parameters"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        std::fs::write(&path, "incompatible\n").unwrap();
        assert!(!bench(&root, &args).status.success());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "incompatible\n");
    }
    assert_eq!(std::fs::read_to_string(historical).unwrap(), "historical\n");
}

#[test]
fn config_overlay_propagates_every_parameter_to_worker() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, "[pp]\nbase_field='invalid'\nextension_degree=4\nlog_d=0\nm=0\nblowup=0\nterminal_coefficients=0\nnum_queries=0\nagreement_numerator=0\nagreement_denominator=0\n[benchmark]\nthreads=[32]\nrepetitions=0\n").unwrap();
    let output = bench(
        directory.path(),
        &[
            "run",
            "--config",
            path.to_str().unwrap(),
            "--base-field",
            "goldilocks",
            "--extension-degree",
            "5",
            "--log-d",
            "5",
            "--m",
            "4",
            "--blowup",
            "4",
            "--terminal-coefficients",
            "2",
            "--num-queries",
            "35",
            "--agreement-numerator",
            "18",
            "--agreement-denominator",
            "25",
            "--threads",
            "1",
            "--repetitions",
            "1",
        ],
    );
    success(&output);
    let text =
        std::fs::read_to_string(directory.path().join("ReedWeave_JB/goldilocks.csv")).unwrap();
    assert_eq!(text.lines().count(), 2);
    assert!(
        text.lines()
            .nth(1)
            .unwrap()
            .starts_with("goldilocks,5,5,4,4,2,35,18,25,1,")
    );
}

#[test]
fn missing_pp_old_switches_and_resources_fail_without_output() {
    let directory = tempfile::tempdir().unwrap();
    for args in [
        vec!["run"],
        vec!["preflight"],
        vec!["run", "--log-n", "14"],
        vec!["run", "--d", "2"],
        vec!["run", "--field", "f128-base"],
    ] {
        assert!(!bench(directory.path(), &args).status.success());
    }
    for omitted in ["--agreement-numerator", "--agreement-denominator"] {
        let mut args = vec!["preflight"];
        args.extend_from_slice(PP);
        let position = args.iter().position(|&arg| arg == omitted).unwrap();
        args.drain(position..position + 2);
        let output = bench(directory.path(), &args);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(omitted));
    }
    let mut args = vec!["preflight"];
    args.extend_from_slice(PP);
    let terminal = args
        .iter()
        .position(|&arg| arg == "--terminal-coefficients")
        .unwrap();
    args[terminal + 1] = "1";
    let output = bench(directory.path(), &args);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid protocol geometry"));
    let mut args = vec!["run"];
    args.extend_from_slice(PP);
    let degree = args
        .iter()
        .position(|&arg| arg == "--extension-degree")
        .unwrap();
    args[degree + 1] = "1";
    args.extend_from_slice(&["--max-memory-mib", "1"]);
    let output = bench(directory.path(), &args);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unmeasured"));
    assert_eq!(directory.path().read_dir().unwrap().count(), 0);
}
