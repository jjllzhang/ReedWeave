use super::*;
use brakefri_core::Profile;
use config::Common;

fn common(path: &std::path::Path) -> Common {
    Common {
        config: path.to_path_buf(),
        out: None,
        seed: None,
        repetitions: None,
        max_memory_mib: None,
        time_limit_seconds: None,
    }
}
fn case() -> Case {
    Case {
        field: Profile::GoldilocksQuadratic,
        log_n: 20,
        threads: 32,
    }
}
#[test]
fn cli_lists_ranges_and_checked_config_overrides() {
    let cli = Cli::try_parse_from([
        "bench",
        "preflight",
        "--fields",
        "goldilocks-quadratic,f128-base",
        "--log-n",
        "20..30",
        "--threads",
        "1,32",
        "--repetitions",
        "2",
    ])
    .unwrap();
    let Command::Preflight(mut matrix) = cli.command else {
        panic!()
    };
    matrix.common.config = "../../configs/brakefri.toml".into();
    let config = Config::load(&matrix.common).unwrap();
    let cases = config.cases(&matrix).unwrap();
    assert_eq!(cases.len(), 44);
    assert_eq!(cases[0].log_n, 20);
    assert_eq!(cases.last().unwrap().log_n, 30);
    assert_eq!(cases.last().unwrap().threads, 32);
    assert_eq!(config.settings(&matrix.common).repetitions, 2);
    matrix.common.repetitions = None;
    assert_eq!(config.settings(&matrix.common).repetitions, 5);
    for range in ["30..20", "10", "31", "20..=30", "20..30..30", "-1"] {
        assert!(config::sizes(range).is_err());
    }
    for args in [
        vec![
            "bench",
            "run",
            "--field",
            "unknown",
            "--log-n",
            "11",
            "--threads",
            "1",
        ],
        vec![
            "bench",
            "run",
            "--field",
            "f128-base",
            "--log-n",
            "11",
            "--threads",
            "-1",
        ],
    ] {
        assert!(Cli::try_parse_from(args).is_err());
    }
    let mut zero = case();
    zero.threads = 0;
    assert!(zero.params().is_err());
    let source = std::fs::read_to_string("../../configs/brakefri.toml").unwrap();
    for invalid in [
        source.replace("m = 1024", "m = 512"),
        source.replace("blowup = 2", "blowup = 4"),
        source.replace("num_queries = 244", "num_queries = 243"),
        source.replace("threads = [1, 32]", "threads = [0]"),
        source.replace("threads = [1, 32]", "threads = [1, 16]"),
        source.replace("repetitions = 5", "repetitions = 0"),
        source.replace("log_n_max = 30", "log_n_max = 31"),
    ] {
        let c: Config = toml::from_str(&invalid).unwrap();
        assert!(c.validate().is_err());
    }
    assert!(
        toml::from_str::<Config>(&source.replace("m = 1024", "m = 1024\nunrecognized = 7"))
            .is_err()
    );
    let mut c = common(std::path::Path::new("../../configs/brakefri.toml"));
    c.repetitions = Some(0);
    assert!(Config::load(&c).is_err());
}
#[test]
fn csv_exact_header_append_and_accounting() {
    let directory = tempfile::tempdir().unwrap();
    let case = case();
    let path = output::csv_path(&case, directory.path());
    assert!(path.ends_with("blake3/goldilocks_quadratic.csv"));
    let trial = output::VerifiedTrial {
        commit_time: 0.1,
        prove_time: 0.2,
        verify_time: 0.3,
        proof_size: 12345,
    };
    for _ in 0..2 {
        let mut file = output::open_csv(&path).unwrap();
        output::append_trial(&mut file, &case.params().unwrap(), case.threads, &trial).unwrap();
    }
    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0], output::HEADER);
    assert_eq!(
        lines[1],
        "20,1024,1024,0.5,32,0.100000000,0.200000000,0.300000000,12345"
    );
    assert!(lines.iter().all(|line| line.split(',').count() == 9));
    std::fs::write(&path, "wrong,header\n").unwrap();
    assert!(output::open_csv(&path).is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "wrong,header\n");
    std::fs::write(&path, format!("{}\n20,1024", output::HEADER)).unwrap();
    assert!(output::open_csv(&path).is_err());
}
#[test]
fn estimates_include_retained_data_and_resource_failures() {
    let mut c = case();
    c.log_n = 30;
    let estimate = Estimate::new(&c).unwrap();
    assert_eq!(estimate.coefficients, 8 << 30);
    assert_eq!(estimate.matrix, 16 << 30);
    assert!(estimate.scratch >= estimate.matrix);
    let params = c.params().unwrap();
    let tree_nodes: usize = (0..=params.rounds())
        .map(|j| 2 * params.layer_size(j).unwrap() - 1)
        .sum();
    assert_eq!(estimate.trees, tree_nodes as u64 * 32);
    let settings = Settings {
        output: "unused".into(),
        seed: 0,
        repetitions: 1,
        max_memory_mib: Some(1),
        time_limit_seconds: None,
    };
    assert!(
        resources::admit(
            &estimate,
            &settings,
            &Available {
                memory: Some(1 << 40),
                cpus: Some(3)
            }
        )
        .is_err()
    );
    c.field = Profile::F128Base;
    assert_eq!(Estimate::new(&c).unwrap().coefficients, 16 << 30);
    c.threads = usize::MAX;
    assert!(Estimate::new(&c).is_err());
}
