use crate::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum Protocol {
    Fri,
    Stir,
    Whir,
}
impl Protocol {
    pub fn name(self) -> &'static str {
        match self {
            Self::Fri => "fri",
            Self::Stir => "stir",
            Self::Whir => "whir",
        }
    }
    pub fn timing_model(self) -> &'static str {
        match self {
            Self::Fri | Self::Stir | Self::Whir => "core-v1",
        }
    }
    pub fn max_log_n(self) -> usize {
        if self == Self::Whir { 28 } else { 30 }
    }
    pub fn fields(self) -> &'static [Field] {
        &[Field::Goldilocks]
    }
}
#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum Field {
    Goldilocks,
}
impl Field {
    pub fn name(self) -> &'static str {
        match self {
            Self::Goldilocks => "goldilocks",
        }
    }
    pub fn extension_degree(self) -> usize {
        match self {
            Self::Goldilocks => 3,
        }
    }
    pub fn base_bytes(self) -> usize {
        match self {
            Self::Goldilocks => 8,
        }
    }
}
#[derive(Parser)]
#[command(
    version,
    about = crate::params::PROFILE_ABOUT
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
    /// Result root: FRI/STIR use <protocol>/goldilocks.csv; WHIR uses WHIR/goldilocks.csv.
    #[arg(long, default_value = "results")]
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
    /// Attempt cases even when the conservative estimate exceeds available RAM.
    /// May cause an OS OOM kill. An explicit --max-memory-mib is still enforced.
    #[arg(long)]
    pub allow_memory_overcommit: bool,
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
    /// Goldilocks input field with cubic challenges.
    #[arg(long, value_enum)]
    pub field: Field,
    #[arg(long)]
    pub log_n: usize,
    #[arg(long)]
    pub threads: usize,
}
impl Case {
    pub fn validate(&self) -> Result<()> {
        if !(20..=self.protocol.max_log_n()).contains(&self.log_n) {
            return Err(format!(
                "{} log_n must be 20..={}",
                self.protocol.name(),
                self.protocol.max_log_n()
            )
            .into());
        }
        if !matches!(self.threads, 1 | 32) {
            return Err("threads must be 1 or 32".into());
        }
        Ok(())
    }
    pub fn label(&self) -> String {
        format!(
            "{} {} extension={} log_n={} threads={} rate={}{}",
            self.protocol.name(),
            self.field.name(),
            self.field.extension_degree(),
            self.log_n,
            self.threads,
            crate::params::RATE,
            if self.protocol == Protocol::Whir {
                " input=hypercube_evaluations opening=prescribed_multilinear"
            } else {
                ""
            }
        )
    }
    pub fn csv_path(&self, settings: &Settings) -> PathBuf {
        settings
            .out
            .join(match self.protocol {
                Protocol::Fri => "FRI",
                Protocol::Stir => "STIR",
                Protocol::Whir => "WHIR",
            })
            .join(format!("{}.csv", self.field.name()))
    }
}
#[derive(Args)]
pub struct Matrix {
    #[command(flatten)]
    pub settings: Settings,
    #[arg(long, value_enum, value_delimiter = ',', default_value = "fri,stir")]
    pub protocols: Vec<Protocol>,
    /// Default: Goldilocks for every protocol.
    #[arg(long, value_enum, value_delimiter = ',')]
    pub fields: Vec<Field>,
    /// Inclusive input-size exponents. Default: WHIR 20..28, FRI/STIR 20..30.
    #[arg(long)]
    pub log_n: Option<String>,
    #[arg(long, value_delimiter = ',', default_value = "1,32")]
    pub threads: Vec<usize>,
}
impl Matrix {
    pub fn cases(&self) -> Result<Vec<Case>> {
        self.settings.validate()?;
        let mut result = Vec::new();
        for &protocol in &self.protocols {
            let (lo, hi) = if let Some(range) = &self.log_n {
                let (lo, hi) = range.split_once("..").unwrap_or((range, range));
                (lo.parse::<usize>()?, hi.parse::<usize>()?)
            } else {
                (20, protocol.max_log_n())
            };
            if !(20..=protocol.max_log_n()).contains(&lo)
                || !(lo..=protocol.max_log_n()).contains(&hi)
            {
                return Err(format!(
                    "{} log_n must be a single exponent or ascending inclusive range within 20..{}",
                    protocol.name(),
                    protocol.max_log_n()
                )
                .into());
            }
            let fields = if self.fields.is_empty() {
                protocol.fields()
            } else {
                &self.fields
            };
            for &field in fields {
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
