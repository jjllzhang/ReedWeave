use std::{fs, path::Path};

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
    pub commitment: u64,
    pub peak: u64,
}
impl Estimate {
    pub fn new(case: &Case) -> Result<Self> {
        let params = case.params()?;
        let d = u64::try_from(params.d())?;
        let domain = u64::try_from(params.domain_size())?;
        let challenge = mul(&[8, u64::try_from(params.extension_degree())?])?;
        let q = u64::try_from(params.num_queries())?;
        let m = u64::try_from(params.m())?;
        let rounds = u64::try_from(params.rounds())?;
        let coefficients = mul(&[d, 8])?;
        let matrix = mul(&[u64::try_from(params.blowup())?, coefficients])?;
        // Initial base-row tree and t-1 intermediate scalar trees; no terminal tree.
        let mut trees = 0;
        let mut layer = domain;
        for _ in 0..params.rounds() {
            let nodes = mul(&[2, layer])?
                .checked_sub(1)
                .ok_or("tree estimate underflow")?;
            trees = add(&[trees, mul(&[nodes, 32])?])?;
            layer /= 2;
        }
        // Context/root, explicit zeta, m DEEP answers and conservative framing.
        let commitment = add(&[64, mul(&[add(&[m, 1])?, challenge])?, 128])?;
        // Full normalization buffer, twiddles, simultaneous challenge/fold buffers,
        // typed/wire/decoded proofs (including framing), and worker stacks.
        let proof = add(&[
            mul(&[2, q, m, 8])?,
            mul(&[2, q, rounds, challenge])?,
            mul(&[
                u64::try_from(params.terminal_coefficient_count())?,
                challenge,
            ])?,
            mul(&[2, q, rounds, u64::try_from(params.log_domain_size())?, 32])?,
            mul(&[m, challenge])?,
            mul(&[4, rounds, challenge])?,
            mul(&[rounds - 1, 32])?,
            mul(&[add(&[rounds, 1])?, 128])?,
        ])?;
        let scratch = add(&[
            matrix,
            mul(&[domain, 8])?,
            mul(&[8, domain, challenge])?,
            mul(&[6, proof])?,
            // Prover-owned + returned typed commitments, wire and decoded copies,
            // with headroom for transcript serialization and validation scratch.
            mul(&[6, commitment])?,
            mul(&[u64::try_from(case.threads)?, 2, MIB])?,
        ])?;
        let subtotal = add(&[coefficients, matrix, trees, scratch])?;
        let peak = add(&[subtotal, subtotal / 4, 32 * MIB])?;
        Ok(Self {
            coefficients,
            matrix,
            trees,
            scratch,
            commitment,
            peak,
        })
    }
}

fn mul(values: &[u64]) -> Result<u64> {
    values.iter().try_fold(1u64, |a, &b| {
        a.checked_mul(b)
            .ok_or_else(|| "memory estimate overflow".into())
    })
}
fn add(values: &[u64]) -> Result<u64> {
    values.iter().try_fold(0u64, |a, &b| {
        a.checked_add(b)
            .ok_or_else(|| "memory estimate overflow".into())
    })
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
        "{}: geometry valid; security not evaluated; estimated bytes coefficients={} matrix={} trees={} scratch={} commitment={} peak_with_overhead={}; available_memory_bytes={:?} available_cpus={:?}",
        case.label(),
        estimate.coefficients,
        estimate.matrix,
        estimate.trees,
        estimate.scratch,
        estimate.commitment,
        estimate.peak,
        available.memory,
        available.cpus
    )
}
