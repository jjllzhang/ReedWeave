use super::*;
use reedweave_jb_core::{BaseField, PublicParams};

pub(crate) fn case() -> Case {
    Case {
        pp: PublicParams {
            base_field: BaseField::Goldilocks,
            extension_degree: 2,
            log_d: 4,
            m: 2,
            blowup: 4,
            terminal_coefficients: 2,
            num_queries: 3,
            agreement_numerator: 3,
            agreement_denominator: 4,
        },
        threads: 1,
    }
}
const PP: &str = "[pp]\nbase_field='goldilocks'\nextension_degree=2\nlog_d=4\nm=2\nblowup=4\nterminal_coefficients=2\nnum_queries=3\nagreement_numerator=3\nagreement_denominator=4\n";
#[test]
fn overlay_then_validate_and_strict_schema() {
    let config: Config = toml::from_str(
        &PP.replace("m=2", "m=0")
            .replace("'goldilocks'", "'invalid'"),
    )
    .unwrap();
    let mut common = config::Common::default();
    assert!(config::cases(Some(&config), &common, None, false).is_err());
    common.pp.m = Some(2);
    common.pp.base_field = Some("goldilocks".into());
    assert_eq!(
        config::cases(Some(&config), &common, None, false).unwrap()[0]
            .pp
            .m,
        2
    );
    for invalid in [
        PP.replace("[pp]", "[protocol]"),
        PP.replace("m=2", "m=2\nunknown=1"),
        PP.replace("log_d=4\n", ""),
        format!("{PP}\n[benchmark]\nfields=['goldilocks']"),
        format!("{PP}\n[unknown]\nx=1"),
    ] {
        assert!(toml::from_str::<Config>(&invalid).is_err(), "{invalid}");
    }
    assert!(config::cases(None, &common, None, false).is_err());
    assert!(Config::load(&common).unwrap().is_none());
    let config: Config = toml::from_str(&format!("{PP}\n[benchmark]\nrepetitions=0")).unwrap();
    assert!(config::settings(Some(&config), &common).is_err());
    common.repetitions = Some(1);
    assert_eq!(
        config::settings(Some(&config), &common)
            .unwrap()
            .repetitions,
        1
    );
}
#[test]
fn lists_ranges_full_cases_and_old_switches() {
    let config: Config = toml::from_str(PP).unwrap();
    let cli = Cli::try_parse_from([
        "bench",
        "preflight",
        "--extension-degree",
        "1,2,3,5",
        "--log-d",
        "4,5..6",
        "--threads",
        "1,32",
    ])
    .unwrap();
    let Command::Preflight(matrix) = cli.command else {
        panic!()
    };
    let cases = config::cases(
        Some(&config),
        &matrix.common,
        matrix.threads.as_deref(),
        true,
    )
    .unwrap();
    assert_eq!(cases.len(), 24);
    assert_eq!(cases.last().unwrap().pp.extension_degree, 5);
    assert_eq!(cases.last().unwrap().pp.log_d, 6);
    assert!(config::cases(Some(&config), &matrix.common, None, false).is_err());
    for range in ["30..20", "64", "20..=30", "20..30..30", "-1", ""] {
        assert!(config::sizes(range).is_err());
    }
    assert_eq!(config::sizes("1,31..32").unwrap(), vec![1, 31, 32]);
    for switch in ["--d", "--log-n", "--field", "--fields"] {
        assert!(Cli::try_parse_from(["bench", "run", switch, "1"]).is_err());
    }
    let full = format!(
        "{PP}\n{}\n{}",
        PP.replace("[pp]", "[[cases]]"),
        PP.replace("[pp]", "[[cases]]")
            .replace("log_d=4", "log_d=5")
    );
    let config: Config = toml::from_str(&full).unwrap();
    let cases = config::cases(Some(&config), &config::Common::default(), None, true).unwrap();
    assert_eq!(cases.len(), 2);
    assert_eq!(cases[1].pp.log_d, 5);
}
#[test]
fn csv_exact_header_append_and_accounting() {
    let directory = tempfile::tempdir().unwrap();
    let case = case();
    let path = output::csv_path(&case, directory.path());
    assert!(path.ends_with("ReedWeave_JB/goldilocks.csv"));
    let trial = output::VerifiedTrial {
        commit_time: 0.1,
        prove_time: 0.2,
        verify_time: 0.3,
        proof_size: 12345,
    };
    for _ in 0..2 {
        let mut file = output::open_csv(&path, &case.params().unwrap()).unwrap();
        output::append_trial(&mut file, &case.params().unwrap(), case.threads, &trial).unwrap();
    }
    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0], output::HEADER);
    assert_eq!(
        lines[1],
        "goldilocks,2,4,2,4,2,3,3,4,1,100.000,200.000,300.000,12.056"
    );
    assert!(lines.iter().all(|line| line.split(',').count() == 14));
    for invalid in [
        "log_n,m,k,rho,threads,commit_time_ms,open_time_ms,verify_time_ms,proof_size_KiB\n"
            .to_string(),
        "wrong,header\n".into(),
        format!("{}\ngoldilocks", output::HEADER),
    ] {
        std::fs::write(&path, &invalid).unwrap();
        assert!(output::open_csv(&path, &case.params().unwrap()).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), invalid);
    }
}
#[test]
fn canonical_fraction_and_csv_configuration_guard() {
    let config: Config = toml::from_str(
        &PP.replace("numerator=3", "numerator=6")
            .replace("denominator=4", "denominator=8"),
    )
    .unwrap();
    let cases = config::cases(Some(&config), &config::Common::default(), None, false).unwrap();
    assert_eq!(cases[0].pp.agreement_numerator, 3);
    assert_eq!(cases[0].pp.agreement_denominator, 4);
    for incomplete in [
        PP.replace("agreement_numerator=3\n", ""),
        PP.replace("agreement_denominator=4\n", ""),
    ] {
        assert!(toml::from_str::<Config>(&incomplete).is_err());
    }
    let directory = tempfile::tempdir().unwrap();
    let case = case();
    let path = output::csv_path(&case, directory.path());
    let mut file = output::open_csv(&path, &case.params().unwrap()).unwrap();
    let trial = output::VerifiedTrial {
        commit_time: 0.0,
        prove_time: 0.0,
        verify_time: 0.0,
        proof_size: 2048,
    };
    output::append_trial(&mut file, &case.params().unwrap(), 1, &trial).unwrap();
    let original = std::fs::read_to_string(&path).unwrap();
    for field in 0..7 {
        let mut other = case.clone();
        match field {
            0 => other.pp.extension_degree = 3,
            1 => other.pp.m = 1,
            2 => other.pp.blowup = 8,
            3 => other.pp.terminal_coefficients = 4,
            4 => other.pp.num_queries = 4,
            5 => {
                other.pp.agreement_numerator = 4;
                other.pp.agreement_denominator = 5;
            }
            _ => {
                other.pp.agreement_numerator = 3;
                other.pp.agreement_denominator = 5;
            }
        }
        assert!(output::open_csv(&path, &other.params().unwrap()).is_err());
        assert!(output::append_trial(&mut file, &other.params().unwrap(), 32, &trial).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }
    for malformed in [
        original.replace(",3,4,1,", ",6,8,1,"),
        original.replace("0.000", "NaN"),
        original.replace(",1,0.000", ",2,0.000"),
        format!("{original}bad,row\n"),
    ] {
        std::fs::write(&path, &malformed).unwrap();
        assert!(output::open_csv(&path, &case.params().unwrap()).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), malformed);
    }
}

#[test]
fn dynamic_estimates_and_overflow_without_large_allocations() {
    let mut c = case();
    c.pp.log_d = 31;
    c.pp.m = 64;
    let estimate = Estimate::new(&c).unwrap();
    assert_eq!(estimate.coefficients, 8 << 31);
    assert_eq!(estimate.matrix, 32 << 31);
    assert_eq!(estimate.commitment, 64 + (64 + 1) * 16 + 128);
    let params = c.params().unwrap();
    let tree_nodes: usize = (0..params.rounds())
        .map(|j| 2 * params.layer_size(j).unwrap() - 1)
        .sum();
    assert_eq!(estimate.trees, tree_nodes as u64 * 32);
    let settings = Settings {
        measurement: Default::default(),
        output: "unused".into(),
        seed: 0,
        repetitions: 1,
        max_memory_mib: Some(1),
        time_limit_seconds: None,
    };
    let available = Available {
        memory: Some(1 << 40),
        cpus: Some(3),
    };
    assert!(resources::admit(&estimate, &settings, &available).is_err());
    let overflowing = Settings {
        max_memory_mib: Some(u64::MAX),
        ..settings
    };
    assert!(resources::admit(&estimate, &overflowing, &available).is_err());
    c.pp.extension_degree = 5;
    assert!(Estimate::new(&c).unwrap().scratch > estimate.scratch);
    c.pp.num_queries = usize::MAX;
    assert!(Estimate::new(&c).is_err());
    // Valid tiny geometry with enormous replacement-query count: the core's
    // deduplicated proof bound fits, but the conservative resource sum overflows.
    c = case();
    c.pp.log_d = 2;
    c.pp.m = 1;
    c.pp.blowup = 2;
    c.pp.terminal_coefficients = 2;
    c.pp.num_queries = usize::MAX / 64;
    c.params().unwrap();
    assert!(
        Estimate::new(&c)
            .unwrap_err()
            .to_string()
            .contains("overflow")
    );
    c = case();
    c.pp.log_d = usize::MAX;
    assert!(Estimate::new(&c).is_err());
    c = case();
    c.threads = usize::MAX;
    assert!(Estimate::new(&c).is_err());
    c = case();
    c.pp.num_queries += 1;
    assert!(Estimate::new(&c).unwrap().scratch > Estimate::new(&case()).unwrap().scratch);
}
