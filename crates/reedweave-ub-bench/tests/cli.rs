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
];
const HEADER: &str = "base_field,extension_degree,log_d,m,blowup,terminal_coefficients,num_queries,threads,commit_time_ms,open_time_ms,verify_time_ms,proof_size_KiB";
fn bench(out: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_reedweave-ub-bench"))
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
            .all(|s| s.contains("geometry valid; security not evaluated"))
    );
    assert_eq!(directory.path().read_dir().unwrap().count(), 0);
    // Deliberate historical file: new workers must not touch it.
    std::fs::create_dir(directory.path().join("historical")).unwrap();
    let historical = directory.path().join("historical/goldilocks.csv");
    std::fs::write(&historical, "historical\n").unwrap();
    args[0] = "sweep";
    args.extend_from_slice(&["--threads", "1,32", "--repetitions", "2"]);
    let sweep = bench(directory.path(), &args);
    success(&sweep);
    let stderr = String::from_utf8_lossy(&sweep.stderr);
    assert_eq!(stderr.matches("timing_model=core-hot-verify").count(), 8);
    let progress: Vec<_> = stderr
        .lines()
        .filter(|s| s.starts_with("WARMUP VERIFIED ") || s.starts_with("VERIFIED "))
        .collect();
    assert_eq!(progress.len(), 8 * 3);
    for case in progress.chunks_exact(3) {
        assert!(case[0].starts_with("WARMUP VERIFIED "));
        assert!(case[1].contains(" repetition=1 "));
        assert!(case[2].contains(" repetition=2 "));
        assert_eq!(
            case[0].split("proof_size=").nth(1),
            case[1].split("proof_size=").nth(1)
        );
    }
    assert_eq!(std::fs::read_to_string(historical).unwrap(), "historical\n");
    let path = directory.path().join("ReedWeave_UB/goldilocks.csv");
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.lines().next().unwrap(), HEADER);
    assert_eq!(text.lines().count(), 17);
    for (index, row) in text.lines().skip(1).enumerate() {
        let columns: Vec<_> = row.split(',').collect();
        let degree = ["1", "2", "3", "5"][index / 4];
        let threads = if index % 4 < 2 { "1" } else { "32" };
        assert_eq!(
            &columns[..8],
            ["goldilocks", degree, "2", "1", "2", "2", "1", threads]
        );
        assert_eq!(columns.len(), 12);
        assert!(
            columns[8..11]
                .iter()
                .all(|v| v.parse::<f64>().unwrap() >= 0.0)
        );
        assert!(columns[11].parse::<f64>().unwrap() > 32.0 / 1024.0);
    }
    std::fs::write(&path, "incompatible\n").unwrap();
    assert!(!bench(directory.path(), &args).status.success());
    assert_eq!(std::fs::read_to_string(path).unwrap(), "incompatible\n");
}
#[test]
fn config_overlay_propagates_every_parameter_to_worker() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, "[pp]\nbase_field='invalid'\nextension_degree=4\nlog_d=0\nm=0\nblowup=0\nterminal_coefficients=0\nnum_queries=0\n[benchmark]\nthreads=[32]\nrepetitions=0\nverify_repetitions=0\ncpu_list='invalid'\nnuma_node=1024\n").unwrap();
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
            "--threads",
            "1",
            "--repetitions",
            "1",
            "--verify-repetitions",
            "3",
            "--no-binding",
        ],
    );
    success(&output);
    assert!(String::from_utf8_lossy(&output.stderr).contains("verify_repetitions=3"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("verify_warmups=1"));
    assert_eq!(
        directory
            .path()
            .join("ReedWeave_UB")
            .read_dir()
            .unwrap()
            .count(),
        1
    );
    let text =
        std::fs::read_to_string(directory.path().join("ReedWeave_UB/goldilocks.csv")).unwrap();
    assert_eq!(text.lines().count(), 2);
    assert!(
        text.lines()
            .nth(1)
            .unwrap()
            .starts_with("goldilocks,5,5,4,4,2,35,1,")
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
    let mut args = vec!["sweep"];
    args.extend_from_slice(PP);
    args.extend_from_slice(&["--max-memory-mib", "1"]);
    let output = bench(directory.path(), &args);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unmeasured"));
    assert_eq!(directory.path().read_dir().unwrap().count(), 0);
}

#[test]
fn binding_options_are_strict_and_output_is_csv_only() {
    let directory = tempfile::tempdir().unwrap();
    let mut args = vec!["run"];
    args.extend_from_slice(PP);
    let degree = args
        .iter()
        .position(|&arg| arg == "--extension-degree")
        .unwrap();
    args[degree + 1] = "2";
    args.extend_from_slice(&["--repetitions", "1", "--threads", "32"]);
    for extra in [
        vec!["--verify-repetitions", "0"],
        vec!["--cpu-list", "0"],
        vec!["--numa-node", "0"],
        vec!["--cpu-list", "0", "--numa-node", "0"], // fewer CPUs than workers
        vec!["--cpu-list", "0-31", "--numa-node", "1024"],
        vec!["--cpu-list", "0-31", "--no-binding"],
    ] {
        let mut invalid = args.clone();
        invalid.extend(extra);
        assert!(!bench(directory.path(), &invalid).status.success());
        assert_eq!(directory.path().read_dir().unwrap().count(), 0);
    }
    args.extend_from_slice(&["--verify-repetitions", "3"]);
    success(&bench(directory.path(), &args));
    success(&bench(directory.path(), &args)); // compatible append
    let path = directory.path().join("ReedWeave_UB/goldilocks.csv");
    let original = std::fs::read_to_string(&path).unwrap();
    assert_eq!(original.lines().count(), 3);
    assert_eq!(path.parent().unwrap().read_dir().unwrap().count(), 1);
    assert!(!path.with_extension("benchmark.txt").exists());
    // Timing settings are logged, not used as an on-disk append guard.
    *args.last_mut().unwrap() = "4";
    let output = bench(directory.path(), &args);
    success(&output);
    assert!(String::from_utf8_lossy(&output.stderr).contains("verify_repetitions=4"));
    let appended = std::fs::read_to_string(&path).unwrap();
    assert!(appended.starts_with(&original));
    assert_eq!(appended.lines().count(), 4);
    assert_eq!(path.parent().unwrap().read_dir().unwrap().count(), 1);
    // Existing sidecars are neither read nor overwritten/deleted.
    let legacy = path.with_extension("benchmark.txt");
    std::fs::write(&legacy, "legacy settings\n").unwrap();
    success(&bench(directory.path(), &args));
    assert_eq!(
        std::fs::read_to_string(legacy).unwrap(),
        "legacy settings\n"
    );
    assert_eq!(std::fs::read_to_string(path).unwrap().lines().count(), 5);
}
