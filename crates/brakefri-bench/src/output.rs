use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use brakefri_core::BrakeParams;

use crate::{Result, config::Case};

pub const HEADER: &str = "base_field,extension_degree,log_d,m,blowup,terminal_coefficients,num_queries,threads,commit_time_ms,open_time_ms,verify_time_ms,proof_size_KiB";

pub fn csv_path(_case: &Case, output: &Path) -> PathBuf {
    output.join("BrakeFRI/v3/goldilocks.csv")
}
/// The sweep owns one child at a time. Separate invocations must use separate output
/// directories; concurrent writers to the same result series are unsupported.
pub fn open_csv(path: &Path) -> Result<File> {
    fs::create_dir_all(path.parent().ok_or("CSV has no parent directory")?)?;
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)?;
    if file.metadata()?.len() == 0 {
        let mut file = file;
        writeln!(file, "{HEADER}")?;
        file.flush()?;
        return Ok(file);
    }
    let mut reader = BufReader::new(&file);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line != format!("{HEADER}\n") {
        return Err(format!(
            "refusing to append to {}: CSV header mismatch",
            path.display()
        )
        .into());
    }
    // Detect interrupted writes rather than appending a valid row to a partial row.
    use std::io::{Read, Seek, SeekFrom};
    let mut tail = &file;
    tail.seek(SeekFrom::End(-1))?;
    let mut byte = [0];
    tail.read_exact(&mut byte)?;
    if byte != [b'\n'] {
        return Err("refusing to append to incomplete CSV row".into());
    }
    Ok(file)
}

/// Internal measurements use seconds and bytes; CSV output converts to ms and KiB.
#[derive(Debug)]
pub struct VerifiedTrial {
    pub commit_time: f64,
    pub prove_time: f64,
    pub verify_time: f64,
    pub proof_size: usize,
}
pub fn append_trial(
    file: &mut File,
    params: &BrakeParams,
    threads: usize,
    trial: &VerifiedTrial,
) -> Result<()> {
    if [trial.commit_time, trial.prove_time, trial.verify_time]
        .iter()
        .any(|t| !t.is_finite() || *t < 0.0)
        || trial.proof_size < 32
    {
        return Err("invalid measured trial".into());
    }
    let row = format!(
        "{},{},{},{},{},{},{},{},{:.3},{:.3},{:.3},{:.3}\n",
        params.base_field(),
        params.extension_degree(),
        params.log_d(),
        params.m(),
        params.blowup(),
        params.terminal_coefficient_count(),
        params.num_queries(),
        threads,
        trial.commit_time * 1000.0,
        trial.prove_time * 1000.0,
        trial.verify_time * 1000.0,
        trial.proof_size as f64 / 1024.0
    );
    file.write_all(row.as_bytes())?;
    file.flush()?;
    Ok(())
}
