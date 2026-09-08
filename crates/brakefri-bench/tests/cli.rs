use std::{
    path::Path,
    process::{Command, Output},
};

fn bench(out: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_brakefri-bench"))
        .args(args)
        .arg("--config")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../configs/brakefri.toml"))
        .arg("--out")
        .arg(out)
        .output()
        .unwrap()
}

#[test]
fn commands_write_only_verified_trials_and_preserve_incompatible_files() {
    let directory = tempfile::tempdir().unwrap();
    let preflight = bench(
        directory.path(),
        &[
            "preflight",
            "--fields",
            "goldilocks-quadratic,f128-base",
            "--log-n",
            "14..15",
            "--threads",
            "1,32",
        ],
    );
    assert!(
        preflight.status.success(),
        "{}",
        String::from_utf8_lossy(&preflight.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&preflight.stdout).lines().count(),
        8
    );
    assert_eq!(directory.path().read_dir().unwrap().count(), 0);
    let sweep = bench(
        directory.path(),
        &[
            "sweep",
            "--fields",
            "goldilocks-quadratic,f128-base",
            "--log-n",
            "14",
            "--threads",
            "1,32",
            "--repetitions",
            "2",
        ],
    );
    assert!(
        sweep.status.success(),
        "{}",
        String::from_utf8_lossy(&sweep.stderr)
    );
    // Each child must verify one complete warmup before its two recorded trials.
    let stderr = String::from_utf8_lossy(&sweep.stderr);
    let progress: Vec<_> = stderr
        .lines()
        .filter(|line| line.starts_with("WARMUP VERIFIED ") || line.starts_with("VERIFIED "))
        .collect();
    assert_eq!(progress.len(), 4 * 3);
    for case in progress.chunks_exact(3) {
        assert!(case[0].starts_with("WARMUP VERIFIED "));
        assert!(case[1].contains(" repetition=1 "));
        assert!(case[2].contains(" repetition=2 "));
        // Resetting the point stream preserves the first measured proof.
        assert_eq!(
            case[0].split("proof_size=").nth(1),
            case[1].split("proof_size=").nth(1)
        );
    }
    assert_eq!(directory.path().read_dir().unwrap().count(), 1);
    assert_eq!(
        directory.path().join("blake3").read_dir().unwrap().count(),
        2
    );
    for field in ["goldilocks_quadratic", "f128_base"] {
        let text =
            std::fs::read_to_string(directory.path().join(format!("blake3/{field}.csv"))).unwrap();
        assert_eq!(text.lines().count(), 5);
        for (index, row) in text.lines().skip(1).enumerate() {
            let columns: Vec<_> = row.split(',').collect();
            assert_eq!(columns.len(), 9);
            let threads = if index < 2 { "1" } else { "32" };
            assert_eq!(&columns[..5], ["14", "64", "256", "0.5", threads]);
            assert!(
                columns[5..8]
                    .iter()
                    .all(|v| v.parse::<f64>().unwrap() >= 0.0)
            );
            assert!(columns[8].parse::<usize>().unwrap() > 32);
        }
    }
    let path = directory.path().join("blake3/f128_base.csv");
    std::fs::write(&path, "incompatible\n").unwrap();
    let rejected = bench(
        directory.path(),
        &[
            "run",
            "--field",
            "f128-base",
            "--log-n",
            "14",
            "--threads",
            "1",
            "--repetitions",
            "1",
        ],
    );
    assert!(!rejected.status.success());
    assert_eq!(std::fs::read_to_string(path).unwrap(), "incompatible\n");
    let limited = tempfile::tempdir().unwrap();
    let rejected = bench(
        limited.path(),
        &[
            "run",
            "--field",
            "f128-base",
            "--log-n",
            "30",
            "--threads",
            "1",
            "--max-memory-mib",
            "1",
        ],
    );
    assert!(!rejected.status.success());
    assert!(!limited.path().join("blake3/f128_base.csv").exists());
    assert_eq!(limited.path().read_dir().unwrap().count(), 0);
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("unmeasured"));
}
