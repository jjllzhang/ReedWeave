use std::path::PathBuf;

use brakefri_core::{BrakeParams, Profile};
use clap::{Args, Parser, Subcommand};
use serde::Deserialize;

use crate::Result;

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Measured coefficient-input BrakeFRI PCS trials",
    long_about = "Measured coefficient-input BrakeFRI PCS trials. CLI values override the TOML benchmark settings; fixed protocol values are always validated. Sizes are inclusive. Only successful verified trials append numeric CSV rows. One initialized local thread pool serves all three phases. No warmups or untimed DFT cache preparation."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run one configuration with the configured repetition policy.
    Run(Run),
    /// Validate exact parameters and estimate memory without allocating proof data.
    Preflight(Matrix),
    /// Execute cases sequentially, with one isolated child process per case.
    Sweep(Matrix),
}
#[derive(Args, Debug, Clone)]
pub struct Common {
    #[arg(long, default_value = "configs/brakefri.toml")]
    pub config: PathBuf,
    /// Override the output directory (raw trials are appended).
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Fixture seed; independent of Fiat-Shamir. Same inputs across hashes/threads.
    #[arg(long)]
    pub seed: Option<u64>,
    /// Override repetitions for every selected size; must be positive.
    #[arg(long)]
    pub repetitions: Option<usize>,
    /// Admission limit for estimated peak MiB, not a hard RSS limit.
    #[arg(long)]
    pub max_memory_mib: Option<u64>,
    /// Wall time limit per child case, including fixtures, setup and all repetitions.
    #[arg(long)]
    pub time_limit_seconds: Option<u64>,
}
#[derive(Args, Debug)]
pub struct Run {
    #[command(flatten)]
    pub common: Common,
    #[arg(long)]
    pub field: Profile,
    #[arg(long)]
    pub log_n: usize,
    #[arg(long)]
    pub threads: usize,
    #[arg(long, hide = true)]
    pub worker: bool,
}
#[derive(Args, Debug)]
pub struct Matrix {
    #[command(flatten)]
    pub common: Common,
    #[arg(long, value_delimiter = ',')]
    pub fields: Option<Vec<Profile>>,
    /// Single size or inclusive range, for example 20..30.
    #[arg(long)]
    pub log_n: Option<String>,
    #[arg(long, value_delimiter = ',')]
    pub threads: Option<Vec<usize>>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub protocol: Protocol,
    pub benchmark: Benchmark,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Protocol {
    m: usize,
    blowup: usize,
    num_queries: usize,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Benchmark {
    pub fields: Vec<String>,
    pub log_n_min: usize,
    pub log_n_max: usize,
    pub threads: Vec<usize>,
    /// Repetitions per configuration, independent of polynomial size.
    pub repetitions: usize,
    pub output_dir: PathBuf,
    #[serde(default = "default_seed")]
    pub seed: u64,
    pub max_memory_mib: Option<u64>,
    pub time_limit_seconds: Option<u64>,
}
const fn default_seed() -> u64 {
    20260906
}
#[derive(Clone, Debug)]
pub struct Case {
    pub field: Profile,
    pub log_n: usize,
    pub threads: usize,
}
impl Case {
    pub fn params(&self) -> Result<BrakeParams> {
        if !matches!(self.threads, 1 | 32) {
            return Err("bench threads must be 1 or 32".into());
        }
        Ok(BrakeParams::new(self.field, self.log_n)?)
    }
    pub fn label(&self) -> String {
        format!(
            "{} log_n={} threads={}",
            field_name(self.field),
            self.log_n,
            self.threads
        )
    }
}
#[derive(Clone, Debug)]
pub struct Settings {
    pub output: PathBuf,
    pub seed: u64,
    pub repetitions: usize,
    pub max_memory_mib: Option<u64>,
    pub time_limit_seconds: Option<u64>,
}
impl Config {
    pub fn load(common: &Common) -> Result<Self> {
        let config: Self = toml::from_str(&std::fs::read_to_string(&common.config)?)?;
        config.validate()?;
        for (name, value) in [
            ("repetitions", common.repetitions.map(|v| v as u64)),
            ("max-memory-mib", common.max_memory_mib),
            ("time-limit-seconds", common.time_limit_seconds),
        ] {
            if value == Some(0) {
                return Err(format!("{name} must be positive").into());
            }
        }
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        let b = &self.benchmark;
        if b.fields.is_empty()
            || b.threads.is_empty()
            || b.threads.iter().any(|t| !matches!(t, 1 | 32))
        {
            return Err(
                "fields and threads must be nonempty; bench threads must be 1 or 32".into(),
            );
        }
        if b.repetitions == 0 || b.max_memory_mib == Some(0) || b.time_limit_seconds == Some(0) {
            return Err("repetitions and configured resource limits must be positive".into());
        }
        let sizes = sizes(&format!("{}..{}", b.log_n_min, b.log_n_max))?;
        for field in &b.fields {
            let profile = field.parse()?;
            for &size in &sizes {
                BrakeParams::with_fixed_values(
                    profile,
                    size,
                    self.protocol.m,
                    self.protocol.blowup,
                    self.protocol.num_queries,
                )?;
            }
        }
        Ok(())
    }
    pub fn settings(&self, common: &Common) -> Settings {
        let b = &self.benchmark;
        Settings {
            output: common.out.clone().unwrap_or_else(|| b.output_dir.clone()),
            seed: common.seed.unwrap_or(b.seed),
            repetitions: common.repetitions.unwrap_or(b.repetitions),
            max_memory_mib: common.max_memory_mib.or(b.max_memory_mib),
            time_limit_seconds: common.time_limit_seconds.or(b.time_limit_seconds),
        }
    }
    pub fn cases(&self, matrix: &Matrix) -> Result<Vec<Case>> {
        let b = &self.benchmark;
        let fields = match &matrix.fields {
            Some(fields) => fields.clone(),
            None => b
                .fields
                .iter()
                .map(|f| f.parse())
                .collect::<std::result::Result<Vec<_>, _>>()?,
        };
        let threads = matrix.threads.as_ref().unwrap_or(&b.threads);
        let sizes = sizes(
            &matrix
                .log_n
                .clone()
                .unwrap_or_else(|| format!("{}..{}", b.log_n_min, b.log_n_max)),
        )?;
        if fields.is_empty() || threads.is_empty() {
            return Err("case lists must be nonempty".into());
        }
        let mut cases = Vec::new();
        for field in fields {
            for &log_n in &sizes {
                for &threads in threads {
                    let case = Case {
                        field,
                        log_n,
                        threads,
                    };
                    case.params()?;
                    cases.push(case);
                }
            }
        }
        Ok(cases)
    }
}
pub fn sizes(input: &str) -> Result<Vec<usize>> {
    let (start, end) = match input.split_once("..") {
        Some((a, b)) => (a.parse::<usize>()?, b.parse::<usize>()?),
        None => {
            let n = input.parse::<usize>()?;
            (n, n)
        }
    };
    if !(11..=30).contains(&start) || !(start..=30).contains(&end) {
        return Err("sizes must be an inclusive ascending range within 11..30".into());
    }
    Ok((start..=end).collect())
}

pub fn field_name(field: Profile) -> &'static str {
    match field {
        Profile::GoldilocksQuadratic => "goldilocks-quadratic",
        Profile::F128Base => "f128-base",
    }
}
