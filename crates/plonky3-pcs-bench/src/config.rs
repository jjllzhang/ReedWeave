use crate::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum Protocol {
    Fri,
    Stir,
}
impl Protocol {
    pub fn name(self) -> &'static str {
        match self {
            Self::Fri => "fri",
            Self::Stir => "stir",
        }
    }
}
#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum Field {
    Goldilocks,
    F128,
}
impl Field {
    pub fn name(self) -> &'static str {
        match self {
            Self::Goldilocks => "goldilocks",
            Self::F128 => "f128",
        }
    }
    pub fn extension_degree(self) -> usize {
        match self {
            Self::Goldilocks => 3,
            Self::F128 => 2,
        }
    }
    pub fn base_bytes(self) -> usize {
        match self {
            Self::Goldilocks => 8,
            Self::F128 => 16,
        }
    }
}
#[derive(Parser)]
#[command(
    version,
    about = "Coefficient-input Plonky3 FRI/STIR PCS benchmarks; fixed audited 100-bit parameters, zero PoW"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}
#[derive(Subcommand)]
pub enum Command {
    /// One configuration: one discarded warmup, then measured repetitions.
    Run(Run),
    /// All requested configurations, sequentially in isolated child processes.
    Sweep(Matrix),
    /// Derive parameters and estimate memory; no proof data is allocated.
    Preflight(Matrix),
}
#[derive(Args, Clone, Debug)]
pub struct Settings {
    #[arg(long, default_value = "results/plonky3")]
    pub out: PathBuf,
    #[arg(long, default_value_t = 20260906)]
    pub seed: u64,
    #[arg(long, default_value_t = 5)]
    pub repetitions: usize,
    /// Estimated memory admission cap, additionally limited by available memory.
    #[arg(long)]
    pub max_memory_mib: Option<u64>,
    /// Whole child case wall time, including warmup and all repetitions.
    #[arg(long)]
    pub time_limit_seconds: Option<u64>,
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        if self.repetitions == 0
            || self.max_memory_mib == Some(0)
            || self.time_limit_seconds == Some(0)
        {
            return Err("repetitions and resource limits must be positive".into());
        }
        Ok(())
    }
}
#[derive(Args)]
pub struct Run {
    #[command(flatten)]
    pub settings: Settings,
    #[command(flatten)]
    pub case: Case,
    #[arg(long, hide = true)]
    pub worker: bool,
}
#[derive(Args, Clone, Debug)]
pub struct Case {
    #[arg(long, value_enum)]
    pub protocol: Protocol,
    /// Coefficient field; challenge extension is cubic / quadratic respectively.
    #[arg(long, value_enum)]
    pub field: Field,
    #[arg(long)]
    pub log_n: usize,
    #[arg(long)]
    pub threads: usize,
}
impl Case {
    pub fn validate(&self) -> Result<()> {
        if !(20..=30).contains(&self.log_n) || !matches!(self.threads, 1 | 32) {
            return Err("log_n must be 20..=30 and threads must be 1 or 32".into());
        }
        if brakefri_primitives::TERMINAL_COEFFICIENTS != 128 {
            return Err("BrakeFRI terminal size changed; renew the FRI security audit".into());
        }
        Ok(())
    }
    pub fn label(&self) -> String {
        format!(
            "{} {} extension={} log_n={} threads={}",
            self.protocol.name(),
            self.field.name(),
            self.field.extension_degree(),
            self.log_n,
            self.threads
        )
    }
    pub fn csv_path(&self, settings: &Settings) -> PathBuf {
        settings
            .out
            .join(self.protocol.name())
            .join("blake3")
            .join(format!(
                "{}_extension{}.csv",
                self.field.name(),
                self.field.extension_degree()
            ))
    }
}
#[derive(Args)]
pub struct Matrix {
    #[command(flatten)]
    pub settings: Settings,
    #[arg(long, value_enum, value_delimiter = ',', default_value = "fri,stir")]
    pub protocols: Vec<Protocol>,
    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        default_value = "goldilocks,f128"
    )]
    pub fields: Vec<Field>,
    /// Inclusive range of coefficient-count exponents.
    #[arg(long, default_value = "20..30")]
    pub log_n: String,
    #[arg(long, value_delimiter = ',', default_value = "1,32")]
    pub threads: Vec<usize>,
}
impl Matrix {
    pub fn cases(&self) -> Result<Vec<Case>> {
        self.settings.validate()?;
        let (lo, hi) = self
            .log_n
            .split_once("..")
            .unwrap_or((&self.log_n, &self.log_n));
        let (lo, hi) = (lo.parse::<usize>()?, hi.parse::<usize>()?);
        if !(20..=30).contains(&lo) || !(lo..=30).contains(&hi) {
            return Err(
                "log_n must be a single exponent or ascending inclusive range within 20..30".into(),
            );
        }
        let mut result = Vec::new();
        for &protocol in &self.protocols {
            for &field in &self.fields {
                for log_n in lo..=hi {
                    for &threads in &self.threads {
                        let case = Case {
                            protocol,
                            field,
                            log_n,
                            threads,
                        };
                        case.validate()?;
                        result.push(case);
                    }
                }
            }
        }
        if result.is_empty() {
            return Err("case matrix must not be empty".into());
        }
        Ok(result)
    }
}
