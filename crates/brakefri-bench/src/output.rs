use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};

use crate::{
    Result,
    config::{Case, Settings, field_name},
};

pub const HEADER: &str = "log_n,m,k,rho,threads,commit_time,prove_time,verify_time,proof_size";
const BUILD: &str = include_str!(concat!(env!("OUT_DIR"), "/build.txt"));
const LOCK: &str = include_str!("../../../Cargo.lock");

pub fn csv_path(case: &Case, output: &Path) -> PathBuf {
    output
        .join(case.hash.name())
        .join(format!("{}.csv", field_name(case.field).replace('-', "_")))
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
pub fn append_trial(file: &mut File, case: &Case, trial: &VerifiedTrial) -> Result<()> {
    if [trial.commit_time, trial.prove_time, trial.verify_time]
        .iter()
        .any(|t| !t.is_finite() || *t < 0.0)
        || trial.proof_size < 32
    {
        return Err("invalid measured trial".into());
    }
    let row = format!(
        "{},1024,{},0.5,{},{:.9},{:.9},{:.9},{}\n",
        case.log_n,
        case.params()?.k(),
        case.threads,
        trial.commit_time,
        trial.prove_time,
        trial.verify_time,
        trial.proof_size
    );
    file.write_all(row.as_bytes())?;
    file.flush()?;
    Ok(())
}

pub fn log(output: &Path, message: &str) -> Result<()> {
    fs::create_dir_all(output)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(output.join("run.log"))?;
    writeln!(file, "{:?} {message}", SystemTime::now())?;
    Ok(())
}
pub fn metadata(case: &Case, settings: &Settings) -> Result<()> {
    // Store actual compiler output and locked sources, rather than requiring rustc at runtime.
    // Each invocation gets immutable metadata; different builds never overwrite prior records.
    let directory = settings.output.join("metadata");
    fs::create_dir_all(&directory)?;
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_nanos();
    let stem = format!("{timestamp}-{}", std::process::id());
    fs::write(directory.join(format!("{stem}.lock")), LOCK)?;
    fs::write(
        directory.join(format!("{stem}.txt")),
        format!(
            "{BUILD}\ncase={}\nseed={}\nfixture=SplitMix64-v1, canonical little-endian rejection\nrepetitions={}\nwarmups=0\ndft_cache=fresh configuration each trial, twiddle construction timed\nstate=reused immutably from timed commit for timed prove\npoint=new fixture sample after commitment, public y verified against intended statement\nmax_memory_mib={:?}\ntime_limit_seconds={:?}\n",
            case.label(),
            settings.seed,
            settings.repetitions,
            settings.max_memory_mib,
            settings.time_limit_seconds
        ),
    )?;
    log(
        &settings.output,
        &format!(
            "START {} seed={} repetitions={} metadata={stem}",
            case.label(),
            settings.seed,
            settings.repetitions
        ),
    )
}
