mod config;
mod output;
mod resources;
mod runner;
#[cfg(test)]
mod tests;

use clap::Parser;
use config::{Case, Cli, Command, Config, Settings};
use resources::{Available, Estimate};
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
            eprintln!("brakefri-bench: {error}");
            ExitCode::FAILURE
        }
    }
}
fn execute(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Run(run) => {
            let config = Config::load(&run.common)?;
            let threads = run.threads.map(|t| vec![t]);
            let case =
                config::cases(config.as_ref(), &run.common, threads.as_deref(), false)?.remove(0);
            let settings = config::settings(config.as_ref(), &run.common)?;
            if run.worker {
                runner::run(&case, &settings)
            } else {
                isolated(&case, &settings)
            }
        }
        Command::Preflight(matrix) => execute_matrix(matrix, false),
        Command::Sweep(matrix) => execute_matrix(matrix, true),
    }
}
fn execute_matrix(matrix: config::Matrix, measure: bool) -> Result<()> {
    let config = Config::load(&matrix.common)?;
    let cases = config::cases(
        config.as_ref(),
        &matrix.common,
        matrix.threads.as_deref(),
        true,
    )?;
    let settings = config::settings(config.as_ref(), &matrix.common)?;
    let mut failures = 0;
    for case in cases {
        let result = if measure {
            isolated(&case, &settings)
        } else {
            let available = Available::detect();
            let estimate = Estimate::new(&case)?;
            println!(
                "{} repetitions={} time_limit_seconds={:?}",
                resources::describe(&case, &estimate, &available),
                settings.repetitions,
                settings.time_limit_seconds
            );
            resources::admit(&estimate, &settings, &available)
        };
        if let Err(error) = result {
            failures += 1;
            eprintln!("{}: {error}", case.label());
        }
    }
    if failures > 0 {
        Err(format!(
            "{failures} case(s) failed or were resource limited; no measurements fabricated"
        )
        .into())
    } else {
        Ok(())
    }
}
fn isolated(case: &Case, settings: &Settings) -> Result<()> {
    let result = (|| -> Result<()> {
        let available = Available::detect();
        let estimate = Estimate::new(case)?;
        let description = resources::describe(case, &estimate, &available);
        eprintln!("{description}");
        resources::admit(&estimate, settings, &available)?;
        // Reject incompatible files before launching any expensive work.
        output::open_csv(&output::csv_path(case, &settings.output))?;
        let mut command = Process::new(std::env::current_exe()?);
        command
            .arg("run")
            .arg("--worker")
            // Fully resolved pp, never a config path whose defaults could lose an overlay.
            .arg("--base-field")
            .arg(case.pp.base_field.to_string())
            .arg("--extension-degree")
            .arg(case.pp.extension_degree.to_string())
            .arg("--log-d")
            .arg(case.pp.log_d.to_string())
            .arg("--m")
            .arg(case.pp.m.to_string())
            .arg("--blowup")
            .arg(case.pp.blowup.to_string())
            .arg("--terminal-coefficients")
            .arg(case.pp.terminal_coefficients.to_string())
            .arg("--num-queries")
            .arg(case.pp.num_queries.to_string())
            .arg("--threads")
            .arg(case.threads.to_string())
            .arg("--out")
            .arg(&settings.output)
            .arg("--seed")
            .arg(settings.seed.to_string())
            .arg("--repetitions")
            .arg(settings.repetitions.to_string());
        if let Some(limit) = settings.max_memory_mib {
            command.arg("--max-memory-mib").arg(limit.to_string());
        }
        if let Some(limit) = settings.time_limit_seconds {
            command.arg("--time-limit-seconds").arg(limit.to_string());
        }
        let started = Instant::now();
        let mut child = command.spawn()?;
        if settings.time_limit_seconds.is_none() {
            let status = child.wait()?;
            return if status.success() {
                Ok(())
            } else {
                Err(
                    format!("child exited with {status}; unfinished trials remain unmeasured")
                        .into(),
                )
            };
        }
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if status.success() {
                        return Ok(());
                    }
                    return Err(format!(
                        "child exited with {status}; unfinished trials remain unmeasured"
                    )
                    .into());
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
                return Err("case wall time limit exceeded; completed verified rows retained, unfinished trials unmeasured".into());
            }
            thread::sleep(Duration::from_millis(20));
        }
    })();
    if let Err(error) = &result {
        eprintln!("FAILED {}: {error}", case.label());
    } else {
        eprintln!("DONE {}", case.label());
    }
    result
}
