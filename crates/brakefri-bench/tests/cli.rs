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
    "1",
    "--m",
    "1",
    "--blowup",
    "2",
    "--terminal-coefficients",
    "1",
    "--num-queries",
    "1",
];
const HEADER: &str = "base_field,extension_degree,log_d,m,blowup,terminal_coefficients,num_queries,threads,commit_time_ms,open_time_ms,verify_time_ms,proof_size_KiB";
fn bench(out: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_brakefri-bench"))
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
fn tiny_all_profiles_verified_isolated_and_versioned() {
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
    std::fs::create_dir(directory.path().join("BrakeFRI")).unwrap();
    let historical = directory.path().join("BrakeFRI/goldilocks.csv");
    std::fs::write(&historical, "historical\n").unwrap();
    args[0] = "sweep";
    args.extend_from_slice(&["--threads", "1,32", "--repetitions", "2"]);
    let sweep = bench(directory.path(), &args);
    success(&sweep);
    let stderr = String::from_utf8_lossy(&sweep.stderr);
    assert_eq!(stderr.matches("timing_model=core-v1").count(), 8);
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
    let path = directory.path().join("BrakeFRI/v3/goldilocks.csv");
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.lines().next().unwrap(), HEADER);
    assert_eq!(text.lines().count(), 17);
    for (index, row) in text.lines().skip(1).enumerate() {
        let columns: Vec<_> = row.split(',').collect();
        let degree = ["1", "2", "3", "5"][index / 4];
        let threads = if index % 4 < 2 { "1" } else { "32" };
        assert_eq!(
            &columns[..8],
            ["goldilocks", degree, "1", "1", "2", "1", "1", threads]
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
    std::fs::write(&path, "[pp]\nbase_field='invalid'\nextension_degree=4\nlog_d=0\nm=0\nblowup=0\nterminal_coefficients=0\nnum_queries=0\n[benchmark]\nthreads=[32]\nrepetitions=0\n").unwrap();
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
        ],
    );
    success(&output);
    let text =
        std::fs::read_to_string(directory.path().join("BrakeFRI/v3/goldilocks.csv")).unwrap();
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
    let mut args = vec!["sweep"];
    args.extend_from_slice(PP);
    args.extend_from_slice(&["--max-memory-mib", "1"]);
    let output = bench(directory.path(), &args);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unmeasured"));
    assert_eq!(directory.path().read_dir().unwrap().count(), 0);
}
