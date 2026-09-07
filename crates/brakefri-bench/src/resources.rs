use std::{fs, path::Path};

use brakefri_core::{B, M, Q};

use crate::{
    Result,
    config::{Case, Settings},
};

const MIB: u64 = 1 << 20;

#[derive(Debug)]
pub struct Estimate {
    pub coefficients: u64,
    pub matrix: u64,
    pub trees: u64,
    pub scratch: u64,
    pub peak: u64,
}
impl Estimate {
    pub fn new(case: &Case) -> Result<Self> {
        let params = case.params()?;
        let n = params.n() as u64;
        let domain = params.domain_size() as u64;
        let base = case.field.base_bytes() as u64;
        let coefficients = n * base;
        let matrix = B as u64 * coefficients;
        // Initial binary tree plus all successively halved scalar trees.
        let trees = (4 * domain - params.rounds() as u64 - 5) * 32;
        // Conservatively allow a full normalization buffer, twiddles, combined/folded
        // challenge buffers, simultaneous typed/wire/decoded proofs, and worker stacks.
        let scratch = matrix
            + domain * base
            + 8 * domain * 16
            + 6 * (2 * Q as u64 * M as u64 * base
                + 2 * Q as u64 * params.rounds() as u64 * 16
                + 2 * Q as u64 * params.rounds() as u64 * params.rounds() as u64 * 32);
        let scratch = scratch
            .checked_add(
                (case.threads as u64)
                    .checked_mul(2 * MIB)
                    .ok_or("thread memory estimate overflow")?,
            )
            .ok_or("scratch memory estimate overflow")?;
        let subtotal = coefficients
            .checked_add(matrix)
            .and_then(|n| n.checked_add(trees))
            .and_then(|n| n.checked_add(scratch))
            .ok_or("memory estimate overflow")?;
        let peak = subtotal
            .checked_add(subtotal / 4)
            .and_then(|n| n.checked_add(32 * MIB))
            .ok_or("memory estimate overflow")?;
        Ok(Self {
            coefficients,
            matrix,
            trees,
            scratch,
            peak,
        })
    }
}

#[derive(Debug)]
pub struct Available {
    pub memory: Option<u64>,
    pub cpus: Option<usize>,
}
impl Available {
    pub fn detect() -> Self {
        let host = fs::read_to_string("/proc/meminfo").ok().and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("MemAvailable:").and_then(|s| {
                    s.split_whitespace()
                        .next()?
                        .parse::<u64>()
                        .ok()?
                        .checked_mul(1024)
                })
            })
        });
        // Linux cgroup v2 and v1 headroom, including ancestor limits. Other platforms
        // report unavailable memory explicitly and can use a configured admission cap.
        let mut memory = host;
        if let Ok(text) = fs::read_to_string("/proc/self/cgroup") {
            for line in text.lines() {
                let parts: Vec<_> = line.splitn(3, ':').collect();
                if parts.len() != 3 {
                    continue;
                }
                let (root, limit, usage) = if parts[0] == "0" && parts[1].is_empty() {
                    ("/sys/fs/cgroup", "memory.max", "memory.current")
                } else if parts[1].split(',').any(|s| s == "memory") {
                    (
                        "/sys/fs/cgroup/memory",
                        "memory.limit_in_bytes",
                        "memory.usage_in_bytes",
                    )
                } else {
                    continue;
                };
                // Namespace-relative paths may not exist; the mounted root is always checked.
                let relative = parts[2].trim_start_matches('/');
                if !Path::new(relative)
                    .components()
                    .any(|c| c == std::path::Component::ParentDir)
                {
                    let path = Path::new(root).join(relative);
                    for ancestor in path.ancestors().take_while(|p| p.starts_with(root)) {
                        memory = minimum(memory, cgroup_remaining(ancestor, limit, usage));
                    }
                }
                memory = minimum(memory, cgroup_remaining(Path::new(root), limit, usage));
            }
        }
        Self {
            memory,
            cpus: std::thread::available_parallelism().ok().map(usize::from),
        }
    }
}
fn cgroup_remaining(path: &Path, limit: &str, usage: &str) -> Option<u64> {
    let limit = fs::read_to_string(path.join(limit))
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()?;
    let usage = fs::read_to_string(path.join(usage))
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()?;
    Some(limit.saturating_sub(usage))
}
fn minimum(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}
pub fn admit(estimate: &Estimate, settings: &Settings, available: &Available) -> Result<()> {
    let configured = settings
        .max_memory_mib
        .map(|m| m.checked_mul(MIB).ok_or("memory limit overflow"))
        .transpose()?;
    let usable = minimum(configured, available.memory.map(|m| m / 5 * 4));
    if let Some(limit) = usable {
        if estimate.peak > limit {
            return Err(format!(
                "unmeasured: estimated peak {} MiB exceeds admission budget {} MiB",
                estimate.peak.div_ceil(MIB),
                limit / MIB
            )
            .into());
        }
    } else {
        return Err(
            "unmeasured: available memory unknown; set --max-memory-mib to an appropriate budget"
                .into(),
        );
    }
    Ok(())
}
pub fn describe(case: &Case, estimate: &Estimate, available: &Available) -> String {
    format!(
        "{}: exact parameters PASS; estimated bytes coefficients={} matrix={} trees={} scratch={} peak_with_overhead={}; available_memory_bytes={:?} available_cpus={:?}",
        case.label(),
        estimate.coefficients,
        estimate.matrix,
        estimate.trees,
        estimate.scratch,
        estimate.peak,
        available.memory,
        available.cpus
    )
}
