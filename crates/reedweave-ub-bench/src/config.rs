use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use reedweave_runtime::benchmark::{DEFAULT_VERIFY_REPETITIONS, Measurement};
use reedweave_ub_core::{PublicParams, UbParams};
use serde::Deserialize;

use crate::Result;

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Measured ReedWeave_UB trials (timing_model=core-hot-verify): geometry validation only; security not evaluated"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}
#[derive(Subcommand, Debug)]
pub enum Command {
    /// One isolated case, with a verified warmup then measured repetitions.
    Run(Run),
    /// Validate geometry and resource admission without allocating proof data.
    Preflight(Matrix),
    /// Sequential isolated cases. Lists/ranges enumerate complete public parameters.
    Sweep(Matrix),
}
#[derive(Args, Debug, Clone, Default)]
pub struct PpArgs {
    #[arg(long)]
    pub base_field: Option<String>,
    /// Challenge extension degree(s): 1, 2, 3, or 5. Run accepts one.
    #[arg(long, value_delimiter = ',')]
    pub extension_degree: Option<Vec<usize>>,
    /// Capacity exponent(s), comma-separated or an inclusive range such as 20..24.
    #[arg(long)]
    pub log_d: Option<String>,
    #[arg(long)]
    pub m: Option<usize>,
    #[arg(long)]
    pub blowup: Option<usize>,
    #[arg(long)]
    pub terminal_coefficients: Option<usize>,
    #[arg(long)]
    pub num_queries: Option<usize>,
}
#[derive(Args, Debug, Clone, Default)]
pub struct Common {
    /// Explicit TOML config. Without this, every public parameter is required on CLI.
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[command(flatten)]
    pub pp: PpArgs,
    /// Output root; appends only to ReedWeave_UB/goldilocks.csv.
    #[arg(long)]
    pub out: Option<PathBuf>,
    #[arg(long)]
    pub seed: Option<u64>,
    #[arg(long)]
    pub repetitions: Option<usize>,
    /// Timed verifications of the same proof, after one untimed verification (default 32).
    #[arg(long)]
    pub verify_repetitions: Option<usize>,
    /// Linux CPU list, e.g. 0-31. Requires a matching --numa-node.
    #[arg(long)]
    pub cpu_list: Option<String>,
    /// Bind future worker memory allocations to this NUMA node (Linux MPOL_BIND).
    #[arg(long)]
    pub numa_node: Option<usize>,
    /// Ignore CPU/NUMA binding in the config; inherit the launch environment.
    #[arg(long, conflicts_with_all = ["cpu_list", "numa_node"])]
    pub no_binding: bool,
    /// Estimate-based admission cap, not an OS RSS limit.
    #[arg(long)]
    pub max_memory_mib: Option<u64>,
    /// Whole child wall limit, including setup and warmup.
    #[arg(long)]
    pub time_limit_seconds: Option<u64>,
}
#[derive(Args, Debug)]
pub struct Run {
    #[command(flatten)]
    pub common: Common,
    #[arg(long)]
    pub threads: Option<usize>,
    #[arg(long, hide = true)]
    pub worker: bool,
}
#[derive(Args, Debug)]
pub struct Matrix {
    #[command(flatten)]
    pub common: Common,
    #[arg(long, value_delimiter = ',')]
    pub threads: Option<Vec<usize>>,
}
/// Parse schema first, but defer semantic pp validation until after CLI overlays.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPp {
    pub base_field: String,
    pub extension_degree: usize,
    pub log_d: usize,
    pub m: usize,
    pub blowup: usize,
    pub terminal_coefficients: usize,
    pub num_queries: usize,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub pp: RawPp,
    #[serde(default)]
    pub benchmark: Benchmark,
    /// Optional complete sweep cases; CLI pp flags overlay every case.
    #[serde(default)]
    pub cases: Vec<RawPp>,
}
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Benchmark {
    pub log_d: Option<Vec<usize>>,
    pub extension_degrees: Option<Vec<usize>>,
    pub threads: Vec<usize>,
    pub repetitions: usize,
    pub verify_repetitions: usize,
    pub cpu_list: Option<String>,
    pub numa_node: Option<usize>,
    pub output_dir: PathBuf,
    pub seed: u64,
    pub max_memory_mib: Option<u64>,
    pub time_limit_seconds: Option<u64>,
}
impl Default for Benchmark {
    fn default() -> Self {
        Self {
            log_d: None,
            extension_degrees: None,
            threads: vec![1],
            repetitions: 5,
            verify_repetitions: DEFAULT_VERIFY_REPETITIONS,
            cpu_list: None,
            numa_node: None,
            output_dir: "results".into(),
            seed: 20260906,
            max_memory_mib: None,
            time_limit_seconds: None,
        }
    }
}
#[derive(Clone, Debug)]
pub struct Case {
    pub pp: PublicParams,
    pub threads: usize,
}
impl Case {
    pub fn params(&self) -> Result<UbParams> {
        if !matches!(self.threads, 1 | 32) {
            return Err("bench threads must be 1 or 32".into());
        }
        Ok(UbParams::new(self.pp.clone())?)
    }
    pub fn label(&self) -> String {
        let p = &self.pp;
        format!(
            "{} e={} log_d={} m={} blowup={} terminal_coefficients={} num_queries={} threads={}",
            p.base_field,
            p.extension_degree,
            p.log_d,
            p.m,
            p.blowup,
            p.terminal_coefficients,
            p.num_queries,
            self.threads
        )
    }
}
#[derive(Clone, Debug)]
pub struct Settings {
    pub measurement: Measurement,
    pub output: PathBuf,
    pub seed: u64,
    pub repetitions: usize,
    pub max_memory_mib: Option<u64>,
    pub time_limit_seconds: Option<u64>,
}
impl Config {
    pub fn load(common: &Common) -> Result<Option<Self>> {
        common
            .config
            .as_ref()
            .map(|path| -> Result<Self> { Ok(toml::from_str(&std::fs::read_to_string(path)?)?) })
            .transpose()
    }
}
pub fn settings(config: Option<&Config>, common: &Common) -> Result<Settings> {
    let default = Benchmark::default();
    let b = config.map(|c| &c.benchmark).unwrap_or(&default);
    let (cpu_list, numa_node) = if common.no_binding {
        (None, None)
    } else {
        (
            common.cpu_list.as_deref().or(b.cpu_list.as_deref()),
            common.numa_node.or(b.numa_node),
        )
    };
    let settings = Settings {
        measurement: Measurement::new(
            common.verify_repetitions.unwrap_or(b.verify_repetitions),
            cpu_list,
            numa_node,
        )?,
        output: common.out.clone().unwrap_or_else(|| b.output_dir.clone()),
        seed: common.seed.unwrap_or(b.seed),
        repetitions: common.repetitions.unwrap_or(b.repetitions),
        max_memory_mib: common.max_memory_mib.or(b.max_memory_mib),
        time_limit_seconds: common.time_limit_seconds.or(b.time_limit_seconds),
    };
    if settings.repetitions == 0
        || settings.max_memory_mib == Some(0)
        || settings.time_limit_seconds == Some(0)
    {
        return Err("repetitions and resource limits must be positive".into());
    }
    Ok(settings)
}
pub fn cases(
    config: Option<&Config>,
    common: &Common,
    threads: Option<&[usize]>,
    matrix: bool,
) -> Result<Vec<Case>> {
    let default = Benchmark::default();
    let b = config.map(|c| &c.benchmark).unwrap_or(&default);
    let threads = threads.unwrap_or(&b.threads);
    if threads.is_empty() {
        return Err("threads must be nonempty".into());
    }
    let sources: Vec<Option<&RawPp>> = match config {
        Some(c) if matrix && !c.cases.is_empty() => c.cases.iter().map(Some).collect(),
        Some(c) => vec![Some(&c.pp)],
        None => vec![None],
    };
    let a = &common.pp;
    let mut result = Vec::new();
    for raw in sources {
        let required = |value: Option<usize>, name: &str| -> Result<usize> {
            value.ok_or_else(|| {
                format!("missing public parameter --{name}; supply complete CLI pp or --config")
                    .into()
            })
        };
        let base_field = a
            .base_field
            .as_deref()
            .or(raw.map(|p| p.base_field.as_str()))
            .ok_or("missing public parameter --base-field")?
            .parse()?;
        let degrees = a
            .extension_degree
            .clone()
            .or_else(|| matrix.then(|| b.extension_degrees.clone()).flatten())
            .or_else(|| raw.map(|p| vec![p.extension_degree]))
            .ok_or("missing public parameter --extension-degree")?;
        let logs = a
            .log_d
            .as_deref()
            .map(sizes)
            .transpose()?
            .or_else(|| matrix.then(|| b.log_d.clone()).flatten())
            .or_else(|| raw.map(|p| vec![p.log_d]))
            .ok_or("missing public parameter --log-d")?;
        if degrees.is_empty() || logs.is_empty() {
            return Err("pp lists must be nonempty".into());
        }
        for &extension_degree in &degrees {
            for &log_d in &logs {
                for &threads in threads {
                    let case = Case {
                        pp: PublicParams {
                            base_field,
                            extension_degree,
                            log_d,
                            m: required(a.m.or(raw.map(|p| p.m)), "m")?,
                            blowup: required(a.blowup.or(raw.map(|p| p.blowup)), "blowup")?,
                            terminal_coefficients: required(
                                a.terminal_coefficients
                                    .or(raw.map(|p| p.terminal_coefficients)),
                                "terminal-coefficients",
                            )?,
                            num_queries: required(
                                a.num_queries.or(raw.map(|p| p.num_queries)),
                                "num-queries",
                            )?,
                        },
                        threads,
                    };
                    case.params()?;
                    result.push(case);
                }
            }
        }
    }
    if !matrix && result.len() != 1 {
        return Err("run requires exactly one pp and thread count".into());
    }
    Ok(result)
}
pub fn sizes(input: &str) -> Result<Vec<usize>> {
    let mut result = Vec::new();
    for part in input.split(',') {
        let (start, end) = match part.split_once("..") {
            Some((a, b)) => (a.parse::<usize>()?, b.parse::<usize>()?),
            None => {
                let n = part.parse::<usize>()?;
                (n, n)
            }
        };
        // No old 14..30 policy; larger exponents cannot represent a usize capacity.
        if start > end || end >= usize::BITS as usize {
            return Err(
                "log_d must be an ascending range of representable capacity exponents".into(),
            );
        }
        result.extend(start..=end);
    }
    Ok(result)
}
