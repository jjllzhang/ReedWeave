//! Conservative admission estimates; these are not measured RSS or hard limits.
use crate::{
    Result,
    config::{Case, Settings},
};
use std::{fs, path::Path};
const MIB: u64 = 1 << 20;

pub fn estimated_peak(case: &Case) -> u64 {
    let n = 1u64 << case.log_n;
    let base = case.field.base_bytes() as u64;
    let extension = base * case.field.extension_degree() as u64;
    // Coefficient/evaluation conversion and base LDEs: eight n-sized buffers.
    // Extension codewords halve each round in both protocols; allow eight
    // initial-domain buffers for retained layers, quotients, LDE/DFT scratch.
    // Binary-tree nodes across all layers: bounded by eight initial-domain
    // digests, including initial/folded trees and tree-construction scratch.
    let subtotal =
        8 * n * base + 8 * (2 * n) * extension + 8 * (2 * n) * 32 + case.threads as u64 * 2 * MIB;
    // Covers allocator overhead plus serialized/decoded proof and metadata.
    subtotal + subtotal / 4 + 64 * MIB
}

fn minimum(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}
fn remaining(path: &Path, limit: &str, usage: &str) -> Option<u64> {
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
pub fn available_memory() -> Option<u64> {
    let mut memory = fs::read_to_string("/proc/meminfo").ok().and_then(|text| {
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
            let relative = Path::new(parts[2].trim_start_matches('/'));
            if !relative
                .components()
                .any(|c| c == std::path::Component::ParentDir)
            {
                for path in Path::new(root)
                    .join(relative)
                    .ancestors()
                    .take_while(|p| p.starts_with(root))
                {
                    memory = minimum(memory, remaining(path, limit, usage));
                }
            }
            memory = minimum(memory, remaining(Path::new(root), limit, usage));
        }
    }
    memory
}
pub fn admit(case: &Case, settings: &Settings) -> Result<()> {
    let configured = settings
        .max_memory_mib
        .map(|v| v.checked_mul(MIB).ok_or("memory cap overflow"))
        .transpose()?;
    let limit = minimum(configured, available_memory().map(|v| v / 5 * 4))
        .ok_or("available memory unknown; specify --max-memory-mib")?;
    let peak = estimated_peak(case);
    if peak > limit {
        return Err(format!(
            "unmeasured: estimated peak {} MiB exceeds {} MiB admission budget",
            peak.div_ceil(MIB),
            limit / MIB
        )
        .into());
    }
    Ok(())
}
