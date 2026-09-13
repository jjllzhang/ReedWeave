use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use reedweave_jb_core::{JbParams, PublicParams};

use crate::{Result, config::Case};

pub const HEADER: &str = "base_field,extension_degree,log_d,m,blowup,terminal_coefficients,num_queries,agreement_numerator,agreement_denominator,threads,commit_time_ms,open_time_ms,verify_time_ms,proof_size_KiB";

pub fn csv_path(_case: &Case, output: &Path) -> PathBuf {
    output.join("ReedWeave_JB/goldilocks.csv")
}

pub fn parameter_identity(params: &JbParams) -> String {
    format!(
        "{},{},{},{},{},{},{},{},{}",
        params.base_field(),
        params.extension_degree(),
        params.log_d(),
        params.m(),
        params.blowup(),
        params.terminal_coefficient_count(),
        params.num_queries(),
        params.agreement_numerator(),
        params.agreement_denominator(),
    )
}

/// The sweep owns one child at a time. Separate invocations must use separate output
/// directories; concurrent writers to the same result series are unsupported.
/// Validate every existing row before doing expensive work or appending anything.
pub fn open_csv(path: &Path, params: &JbParams) -> Result<File> {
    fs::create_dir_all(path.parent().ok_or("CSV has no parent directory")?)?;
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)?;
    if file.metadata()?.len() == 0 {
        writeln!(file, "{HEADER}")?;
        file.flush()?;
    }
    validate_csv(&mut file, params)?;
    Ok(file)
}

fn validate_csv(file: &mut File, expected: &JbParams) -> Result<()> {
    file.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line != format!("{HEADER}\n") {
        return Err("refusing to append: CSV header mismatch".into());
    }
    let mut identities = BTreeMap::new();
    identities.insert(expected.log_d(), parameter_identity(expected));
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if !line.ends_with('\n') {
            return Err("refusing to append to incomplete CSV row".into());
        }
        let columns: Vec<_> = line.trim_end_matches('\n').split(',').collect();
        if columns.len() != 14 {
            return Err("refusing to append: malformed CSV row".into());
        }
        let params = JbParams::new(PublicParams {
            base_field: columns[0].parse()?,
            extension_degree: columns[1].parse()?,
            log_d: columns[2].parse()?,
            m: columns[3].parse()?,
            blowup: columns[4].parse()?,
            terminal_coefficients: columns[5].parse()?,
            num_queries: columns[6].parse()?,
            agreement_numerator: columns[7].parse()?,
            agreement_denominator: columns[8].parse()?,
        })?;
        let identity = parameter_identity(&params);
        if columns[..9].join(",") != identity {
            return Err("refusing to append: noncanonical public parameters".into());
        }
        if identities
            .insert(params.log_d(), identity.clone())
            .is_some_and(|previous| previous != identity)
        {
            return Err(
                "mixed public parameters at the same log_d; use separate output roots".into(),
            );
        }
        if !matches!(columns[9], "1" | "32") {
            return Err("invalid CSV thread count".into());
        }
        for (index, column) in columns[10..].iter().enumerate() {
            let value: f64 = column.parse()?;
            if !value.is_finite() || value < 0.0 || (index == 3 && value <= 32.0 / 1024.0) {
                return Err("invalid measured CSV metric".into());
            }
        }
    }
    Ok(())
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
    params: &JbParams,
    threads: usize,
    trial: &VerifiedTrial,
) -> Result<()> {
    if [trial.commit_time, trial.prove_time, trial.verify_time]
        .iter()
        .any(|t| !t.is_finite() || *t < 0.0)
        || trial.proof_size <= 32
        || !matches!(threads, 1 | 32)
    {
        return Err("invalid measured trial".into());
    }
    validate_csv(file, params)?;
    let row = format!(
        "{},{},{:.3},{:.3},{:.3},{:.3}\n",
        parameter_identity(params),
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
