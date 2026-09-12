use crate::{Result, config::Case};
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::Path,
};

pub const REVISION: &str = "9d496524560f3c699473906c6f50fca7cf343730";
const HEADER: &str =
    "log_n,rho,threads,commit_time_ms,open_time_ms,verify_time_ms,proof_size_KiB\n";

/// Internal measurements use seconds and bytes; CSV output converts to ms and KiB.
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
pub fn append(file: &mut File, case: &Case, trial: &Trial) -> Result<()> {
    writeln!(
        file,
        "{},1/2,{},{:.3},{:.3},{:.3},{:.3}",
        case.log_n,
        case.threads,
        trial.commit_time * 1000.0,
        trial.prove_time * 1000.0,
        trial.verify_time * 1000.0,
        (trial.commitment_size + trial.opening_proof_size) as f64 / 1024.0
    )?;
    file.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Field, Protocol, Settings};

    #[test]
    fn compact_results_use_protocol_and_base_field_paths() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("pcs-output-{}-{unique}", std::process::id()));
        let settings = Settings {
            out: root.clone(),
            seed: 20260906,
            repetitions: 5,
            max_memory_mib: None,
            time_limit_seconds: None,
        };
        for (protocol, directory) in [
            (Protocol::Fri, "FRI"),
            (Protocol::Stir, "STIR"),
            (Protocol::Whir, "WHIR"),
        ] {
            for (field, filename) in [(Field::Goldilocks, "goldilocks.csv")] {
                if !protocol.fields().contains(&field) {
                    continue;
                }
                let case = Case {
                    protocol,
                    field,
                    log_n: 20,
                    threads: 32,
                };
                let path = case.csv_path(&settings);
                assert_eq!(path, root.join(directory).join(filename));
                assert_eq!(protocol.timing_model(), "core-v1");
                let trial = Trial {
                    commit_time: 1.0,
                    prove_time: 2.0,
                    verify_time: 3.0,
                    commitment_size: 33,
                    opening_proof_size: 100,
                };
                let mut file = open(&path).unwrap();
                append(&mut file, &case, &trial).unwrap();
                drop(file);
                assert_eq!(
                    std::fs::read_to_string(&path).unwrap(),
                    format!("{HEADER}20,1/2,32,1000.000,2000.000,3000.000,0.130\n")
                );
                assert!(open(&path).is_ok());
                let old_header =
                    "log_n,rho,threads,commit_time,prove_time,verify_time,proof_size\n";
                std::fs::write(&path, old_header).unwrap();
                assert!(open(&path).is_err());
                assert_eq!(std::fs::read_to_string(&path).unwrap(), old_header);
                std::fs::write(&path, "old_header\n").unwrap();
                assert!(open(&path).is_err());
                std::fs::write(&path, format!("{HEADER}20,0.5")).unwrap();
                assert!(open(&path).is_err());
            }
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
