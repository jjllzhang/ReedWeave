//! Opt-in Linux diagnostics, not a production timing API.
//! Enable `open-profiling` and set REEDWEAVE_OPEN_PROFILE to a fresh JSONL path.
//! Fault/CPU counters cover all threads of this process, not child processes.
//! NUMA snapshots report resident mapped bytes, not migration or remote accesses.
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};

static RUN: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy)]
struct Usage {
    minor: i64,
    major: i64,
    user_us: i64,
    system_us: i64,
}
impl Usage {
    fn capture() -> Self {
        // SAFETY: getrusage initializes a correctly sized writable C structure.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) }, 0);
        Self {
            minor: usage.ru_minflt,
            major: usage.ru_majflt,
            user_us: usage.ru_utime.tv_sec * 1_000_000 + usage.ru_utime.tv_usec,
            system_us: usage.ru_stime.tv_sec * 1_000_000 + usage.ru_stime.tv_usec,
        }
    }
}

fn numa_bytes(text: &str) -> BTreeMap<usize, u64> {
    let mut nodes = BTreeMap::new();
    for line in text.lines() {
        // Unpopulated mappings (e.g. vvar) have neither nodes nor page-size fields.
        if !line
            .split_whitespace()
            .any(|field| field.starts_with('N') && field.contains('='))
        {
            continue;
        }
        let page_bytes = line
            .split_whitespace()
            .find_map(|field| field.strip_prefix("kernelpagesize_kB="))
            .and_then(|value| value.parse::<u64>().ok())
            .expect("numa_maps mapping lacks kernel page size")
            * 1024;
        for field in line.split_whitespace() {
            if let Some((node, pages)) = field.strip_prefix('N').and_then(|s| s.split_once('='))
                && let (Ok(node), Ok(pages)) = (node.parse::<usize>(), pages.parse::<u64>())
            {
                *nodes.entry(node).or_insert(0) += pages * page_bytes;
            }
        }
    }
    nodes
}
fn capture_numa() -> BTreeMap<usize, u64> {
    numa_bytes(&fs::read_to_string("/proc/self/numa_maps").expect("read NUMA snapshot"))
}
fn node_json(nodes: &BTreeMap<usize, u64>) -> String {
    format!(
        "{{{}}}",
        nodes
            .iter()
            .map(|(node, bytes)| format!("\"{node}\":{bytes}"))
            .collect::<Vec<_>>()
            .join(",")
    )
}

struct Event {
    stage: &'static str,
    round: Option<usize>,
    wall_ms: f64,
    before: Usage,
    after: Usage,
    numa_before: BTreeMap<usize, u64>,
    numa_after: BTreeMap<usize, u64>,
}

pub(crate) struct OpenProfiler {
    file: File,
    run: usize,
    events: Vec<Event>,
}
impl OpenProfiler {
    pub(crate) fn new() -> Option<Self> {
        let path = std::env::var_os("REEDWEAVE_OPEN_PROFILE")?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open phase profile");
        Some(Self {
            file,
            run: RUN.fetch_add(1, Ordering::Relaxed),
            events: Vec::new(),
        })
    }

    pub(crate) fn measure<R>(
        &mut self,
        stage: &'static str,
        round: Option<usize>,
        operation: impl FnOnce() -> R,
    ) -> R {
        // Snapshot work is deliberately outside each phase's wall and CPU timers.
        let numa_before = capture_numa();
        let before = Usage::capture();
        let start = Instant::now();
        let result = operation();
        let wall_ms = start.elapsed().as_secs_f64() * 1000.0;
        let after = Usage::capture();
        let numa_after = capture_numa();
        self.events.push(Event {
            stage,
            round,
            wall_ms,
            before,
            after,
            numa_before,
            numa_after,
        });
        result
    }
}
impl Drop for OpenProfiler {
    fn drop(&mut self) {
        // Batch output so file I/O does not interrupt each operation. The enclosing
        // prove timer still includes diagnostics overhead: do not use it as a baseline.
        for e in &self.events {
            let round = e.round.map_or_else(|| "null".into(), |r| r.to_string());
            writeln!(self.file,
                "{{\"run\":{},\"stage\":\"{}\",\"round\":{},\"wall_ms\":{:.6},\"minor_faults\":{},\"major_faults\":{},\"user_cpu_ms\":{:.6},\"system_cpu_ms\":{:.6},\"numa_before_bytes\":{},\"numa_after_bytes\":{}}}",
                self.run, e.stage, round, e.wall_ms,
                e.after.minor - e.before.minor, e.after.major - e.before.major,
                (e.after.user_us - e.before.user_us) as f64 / 1000.0,
                (e.after.system_us - e.before.system_us) as f64 / 1000.0,
                node_json(&e.numa_before), node_json(&e.numa_after),
            ).expect("write phase profile");
        }
        self.file.flush().expect("flush phase profile");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counts_nodes_with_mapping_page_sizes() {
        let text = "1000 bind:0 anon=3 N0=2 N1=1 kernelpagesize_kB=4\n2000 default N1=2 kernelpagesize_kB=2048\n3000 default\n";
        assert_eq!(
            numa_bytes(text),
            BTreeMap::from([(0, 8192), (1, 4096 + 2 * 2048 * 1024)])
        );
    }
    #[test]
    fn live_counters_and_numa_are_available() {
        let a = Usage::capture();
        let b = Usage::capture();
        assert!(b.minor >= a.minor && b.major >= a.major);
        assert!(!capture_numa().is_empty());
    }
}
