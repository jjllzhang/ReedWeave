mod config;
mod crypto;
mod output;
mod params;
mod resources;
mod runner;
mod whir;
mod whir_params;

use clap::Parser;
use config::{Case, Cli, Command, Settings};
use std::{
    process::{Command as Process, ExitCode},
    thread,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn main() -> ExitCode {
    match execute(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("plonky3-pcs-bench: {error}");
            ExitCode::FAILURE
        }
    }
}
fn execute(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Run(run) => {
            run.settings.validate()?;
            run.case.validate()?;
            if run.worker {
                runner::run(&run.case, &run.settings)
            } else {
                isolated(&run.case, &run.settings)
            }
        }
        Command::Sweep(matrix) => matrix_run(matrix, true),
        Command::Preflight(matrix) => matrix_run(matrix, false),
    }
}
fn preflight(case: &Case, settings: &Settings) -> Result<()> {
    let audit = runner::audit(case)?;
    let terminal_kind = if case.protocol == config::Protocol::Whir {
        "terminal_evaluations"
    } else {
        "terminal_coefficients"
    };
    eprintln!(
        "{}: algebraic_bound_bits={:.9} {}={} queries={} radii={} estimated_peak_mib={} available_bytes={:?}",
        case.label(),
        audit.bits,
        terminal_kind,
        audit.terminal,
        audit.queries_text(),
        audit.radii_text(),
        resources::estimated_peak(case).div_ceil(1 << 20),
        resources::available_memory()
    );
    resources::admit(case, settings)
}
fn matrix_run(matrix: config::Matrix, measure: bool) -> Result<()> {
    let cases = matrix.cases()?;
    let mut failures = 0;
    for case in cases {
        let result = if measure {
            isolated(&case, &matrix.settings)
        } else {
            preflight(&case, &matrix.settings)
        };
        if let Err(error) = result {
            failures += 1;
            eprintln!("FAILED {}: {error}", case.label());
        }
    }
    if failures != 0 {
        return Err(format!(
            "{failures} case(s) failed or were resource limited; unfinished trials are unmeasured"
        )
        .into());
    }
    Ok(())
}
fn isolated(case: &Case, settings: &Settings) -> Result<()> {
    preflight(case, settings)?;
    output::open(&case.csv_path(settings))?;
    let mut command = Process::new(std::env::current_exe()?);
    command
        .args([
            "run",
            "--worker",
            "--protocol",
            case.protocol.name(),
            "--field",
            case.field.name(),
        ])
        .arg("--log-n")
        .arg(case.log_n.to_string())
        .arg("--threads")
        .arg(case.threads.to_string())
        .arg("--out")
        .arg(&settings.out)
        .arg("--seed")
        .arg(settings.seed.to_string())
        .arg("--repetitions")
        .arg(settings.repetitions.to_string());
    if settings.allow_memory_overcommit {
        command.arg("--allow-memory-overcommit");
    }
    if let Some(limit) = settings.max_memory_mib {
        command.arg("--max-memory-mib").arg(limit.to_string());
    }
    if let Some(limit) = settings.time_limit_seconds {
        command.arg("--time-limit-seconds").arg(limit.to_string());
    }
    let started = Instant::now();
    let mut child = command.spawn()?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    Ok(())
                } else {
                    Err(format!("child exited with {status}").into())
                };
            }
            Ok(None) => (),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.into());
            }
        }
        if settings
            .time_limit_seconds
            .is_some_and(|limit| started.elapsed() >= Duration::from_secs(limit))
        {
            let _ = child.kill();
            child.wait()?;
            return Err("case time limit exceeded; completed rows retained".into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}
