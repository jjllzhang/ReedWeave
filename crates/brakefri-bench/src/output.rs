use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use brakefri_core::{BrakeParams, M, Profile};

use crate::{Result, config::Case};

pub const HEADER: &str = "log_n,m,k,rho,threads,commit_time,prove_time,verify_time,proof_size";

pub fn csv_path(case: &Case, output: &Path) -> PathBuf {
    let field = match case.field {
        Profile::GoldilocksQuadratic => "goldilocks",
        Profile::F128Base => "f128",
    };
    output.join("BrakeFRI").join(format!("{field}.csv"))
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
        "{},{M},{},0.5,{},{:.9},{:.9},{:.9},{}\n",
        params.log_n(),
        params.k(),
        threads,
        trial.commit_time,
        trial.prove_time,
        trial.verify_time,
        trial.proof_size
    );
    file.write_all(row.as_bytes())?;
    file.flush()?;
    Ok(())
}
