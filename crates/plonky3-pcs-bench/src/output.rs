use crate::{
    Result,
    config::{Case, Settings},
    params::Audit,
};
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::Path,
};

pub const REVISION: &str = "9d496524560f3c699473906c6f50fca7cf343730";
const HEADER: &str = "protocol,base_field,extension_degree,log_n,rate,queries_by_round,radii_by_round,terminal_coefficients,target_bits,algebraic_bound_bits,pow_bits,threads,seed,repetition,commit_time,prove_time,verify_time,commitment_size,opening_proof_size,proof_size,plonky3_revision\n";

pub struct Trial {
    pub commit_time: f64,
    pub prove_time: f64,
    pub verify_time: f64,
    pub commitment_size: usize,
    pub opening_proof_size: usize,
}
pub fn open(path: &Path) -> Result<File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(path)?;
    if file.metadata()?.len() == 0 {
        file.write_all(HEADER.as_bytes())?;
        file.flush()?;
    } else {
        let mut header = String::new();
        BufReader::new(&mut file).read_line(&mut header)?;
        if header != HEADER {
            return Err(format!("CSV header mismatch: {}", path.display()).into());
        }
        file.seek(SeekFrom::End(-1))?;
        let mut last = [0];
        file.read_exact(&mut last)?;
        if last != [b'\n'] {
            return Err(format!("incomplete CSV row: {}", path.display()).into());
        }
    }
    Ok(file)
}
pub fn append(
    file: &mut File,
    case: &Case,
    settings: &Settings,
    audit: &Audit,
    repetition: usize,
    trial: &Trial,
) -> Result<()> {
    writeln!(
        file,
        "{},{},{},{},0.5,{},{},{},100,{:.9},0,{},{},{},{:.9},{:.9},{:.9},{},{},{},{}",
        case.protocol.name(),
        case.field.name(),
        case.field.extension_degree(),
        case.log_n,
        audit.queries_text(),
        audit.radii_text(),
        audit.terminal,
        audit.bits,
        case.threads,
        settings.seed,
        repetition,
        trial.commit_time,
        trial.prove_time,
        trial.verify_time,
        trial.commitment_size,
        trial.opening_proof_size,
        trial.commitment_size + trial.opening_proof_size,
        REVISION
    )?;
    file.flush()?;
    Ok(())
}
