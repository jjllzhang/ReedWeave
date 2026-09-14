//! Benchmark-only placement, hot verification timing, and campaign provenance.
//! Binding changes only the calling worker, never global kernel settings.
#[cfg(target_os = "linux")]
use std::fs;
use std::{collections::BTreeSet, hint::black_box, io, num::NonZeroUsize, time::Instant};

pub const TIMING_MODEL: &str = "core-hot-verify";
pub const DEFAULT_VERIFY_REPETITIONS: usize = 32;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

/// Explicit CPU set and one NUMA memory node. CPU ranges use Linux list syntax.
#[derive(Clone, Debug)]
pub struct Binding {
    cpus: Vec<usize>,
    node: usize,
}
impl Binding {
    pub fn new(cpu_list: &str, node: usize) -> io::Result<Self> {
        // Bounded masks avoid unchecked allocation from CLI input.
        if node >= 1024 {
            return Err(invalid("NUMA node must be below 1024"));
        }
        Ok(Self {
            cpus: parse_cpu_list(cpu_list)?,
            node,
        })
    }
    pub fn cpu_list(&self) -> String {
        self.cpus
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
    pub fn node(&self) -> usize {
        self.node
    }

    /// Read-only preflight. Kernel permission to set memory policy is checked
    /// only when the worker applies the binding; failure never falls back silently.
    pub fn validate(&self, threads: usize) -> io::Result<()> {
        if threads == 0 || self.cpus.len() < threads {
            return Err(invalid(
                "CPU binding must contain at least as many CPUs as worker threads",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            let allowed = linux::allowed_cpus()?;
            let node_cpus = parse_cpu_list(&fs::read_to_string(format!(
                "/sys/devices/system/node/node{}/cpulist",
                self.node
            ))?)?;
            let status = fs::read_to_string("/proc/self/status")?;
            let mems = status
                .lines()
                .find_map(|line| line.strip_prefix("Mems_allowed_list:"))
                .ok_or_else(|| invalid("cannot read allowed memory nodes"))?;
            let mems = parse_cpu_list(mems)?;
            if !mems.contains(&self.node) {
                return Err(invalid("requested NUMA memory node is not allowed"));
            }
            if self
                .cpus
                .iter()
                .any(|cpu| !allowed.contains(cpu) || !node_cpus.contains(cpu))
            {
                return Err(invalid(
                    "requested CPUs must be allowed and belong to the selected NUMA node",
                ));
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(invalid("explicit CPU/NUMA binding requires Linux"))
        }
    }

    /// Apply before creating the thread pool or allocating polynomial data.
    /// New threads inherit the CPU mask and MPOL_BIND memory policy. This is a
    /// CPU-set restriction, not per-thread pinning or reservation of physical cores.
    /// On failure, discard the isolated worker (placement may be partially applied).
    pub fn apply(&self, threads: usize) -> io::Result<()> {
        self.validate(threads)?;
        #[cfg(target_os = "linux")]
        {
            linux::apply(self)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(invalid("explicit CPU/NUMA binding requires Linux"))
        }
    }
}

fn parse_cpu_list(input: &str) -> io::Result<Vec<usize>> {
    let mut cpus = BTreeSet::new();
    for part in input.trim().split(',') {
        let part = part.trim();
        let (first, last) = part.split_once('-').unwrap_or((part, part));
        let first: usize = first
            .parse()
            .map_err(|_| invalid("invalid CPU/node list"))?;
        let last: usize = last.parse().map_err(|_| invalid("invalid CPU/node list"))?;
        if first > last || last >= 1024 {
            return Err(invalid("CPU/node ranges must be ascending and below 1024"));
        }
        cpus.extend(first..=last);
    }
    if cpus.is_empty() {
        return Err(invalid("CPU list must not be empty"));
    }
    Ok(cpus.into_iter().collect())
}

#[derive(Clone, Debug)]
pub struct Measurement {
    verify_repetitions: NonZeroUsize,
    pub binding: Option<Binding>,
}
impl Default for Measurement {
    fn default() -> Self {
        Self {
            verify_repetitions: NonZeroUsize::new(DEFAULT_VERIFY_REPETITIONS).unwrap(),
            binding: None,
        }
    }
}
impl Measurement {
    pub fn new(
        verify_repetitions: usize,
        cpu_list: Option<&str>,
        node: Option<usize>,
    ) -> io::Result<Self> {
        let verify_repetitions = NonZeroUsize::new(verify_repetitions)
            .ok_or_else(|| invalid("verify repetitions must be positive"))?;
        let binding = match (cpu_list, node) {
            (None, None) => None,
            (Some(cpus), Some(node)) => Some(Binding::new(cpus, node)?),
            _ => {
                return Err(invalid(
                    "--cpu-list and --numa-node must be supplied together",
                ));
            }
        };
        Ok(Self {
            verify_repetitions,
            binding,
        })
    }
    pub fn verify_repetitions(&self) -> usize {
        self.verify_repetitions.get()
    }
    pub fn validate(&self, threads: usize) -> io::Result<()> {
        if let Some(binding) = &self.binding {
            binding.validate(threads)?;
        }
        Ok(())
    }
    pub fn apply(&self, threads: usize) -> io::Result<()> {
        if let Some(binding) = &self.binding {
            binding.apply(threads)?;
        }
        Ok(())
    }
    /// One untimed verification primes the same immutable proof, followed by B
    /// complete verifications under a single timer. Any failure aborts the trial.
    /// This measures hot amortized verification cost, not cold request latency.
    pub fn time_verification<E>(
        &self,
        mut verify: impl FnMut() -> Result<(), E>,
    ) -> Result<f64, E> {
        black_box(verify())?;
        let start = Instant::now();
        for _ in 0..self.verify_repetitions() {
            black_box(verify())?;
        }
        Ok(start.elapsed().as_secs_f64() / self.verify_repetitions() as f64)
    }
    /// Measurement settings for preflight output and stderr logging only.
    /// These settings are not stored in or checked against CSV files.
    pub fn campaign(&self, seed: u64) -> io::Result<String> {
        let placement = if let Some(binding) = &self.binding {
            format!(
                "cpu_list={}\nmemory_policy=bind\nnuma_node={}\n",
                binding.cpu_list(),
                binding.node()
            )
        } else {
            #[cfg(target_os = "linux")]
            {
                linux::inherited_placement()?
            }
            #[cfg(not(target_os = "linux"))]
            {
                "cpu_list=inherited\nmemory_policy=inherited\n".to_string()
            }
        };
        Ok(format!(
            "timing_model={TIMING_MODEL}\nverify_repetitions={}\nverify_warmups=1\nseed={seed}\n{placement}",
            self.verify_repetitions()
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::mem::size_of;

    pub fn allowed_cpus() -> io::Result<Vec<usize>> {
        // SAFETY: cpu_set_t is plain C storage; the syscall writes within its size.
        let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        if unsafe { libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &mut mask) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((0..libc::CPU_SETSIZE as usize)
            .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &mask) })
            .collect())
    }
    pub fn apply(binding: &Binding) -> io::Result<()> {
        if fs::read_dir("/proc/self/task")?.count() != 1 {
            return Err(invalid(
                "apply binding in the isolated worker before creating any threads",
            ));
        }
        // SAFETY: initialized mask, validated bounded CPU indices and full size.
        let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        for &cpu in &binding.cpus {
            if cpu >= libc::CPU_SETSIZE as usize {
                return Err(invalid("CPU exceeds affinity mask capacity"));
            }
            unsafe {
                libc::CPU_SET(cpu, &mut mask);
            }
        }
        if unsafe { libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &mask) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let bits = libc::c_ulong::BITS as usize;
        let mut nodes = vec![0 as libc::c_ulong; binding.node / bits + 1];
        nodes[binding.node / bits] |= 1 << (binding.node % bits);
        // SAFETY: nodemask spans maxnode bits; MPOL_BIND changes only this thread's
        // policy for future allocations. The isolated worker exits on any error.
        if unsafe {
            libc::syscall(
                libc::SYS_set_mempolicy,
                libc::MPOL_BIND,
                nodes.as_ptr(),
                nodes.len() * bits,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if allowed_cpus()? != binding.cpus {
            return Err(invalid("effective CPU binding differs from request"));
        }
        let (mode, nodes) = memory_policy()?;
        let selected: Vec<_> = nodes
            .iter()
            .enumerate()
            .flat_map(|(i, &word)| {
                (0..bits)
                    .filter(move |&bit| word & (1 << bit) != 0)
                    .map(move |bit| i * bits + bit)
            })
            .collect();
        if mode != libc::MPOL_BIND || selected != [binding.node] {
            return Err(invalid("effective memory policy differs from request"));
        }
        Ok(())
    }
    fn memory_policy() -> io::Result<(libc::c_int, Vec<libc::c_ulong>)> {
        let mut mode = 0;
        let mut nodes = vec![0; 1024 / libc::c_ulong::BITS as usize];
        // SAFETY: writable mode and mask buffers match maxnode=1024; flags=0
        // queries this thread's policy, so the address argument is unused.
        if unsafe {
            libc::syscall(
                libc::SYS_get_mempolicy,
                &mut mode,
                nodes.as_mut_ptr(),
                1024usize,
                std::ptr::null::<libc::c_void>(),
                0usize,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok((mode, nodes))
    }
    pub fn inherited_placement() -> io::Result<String> {
        let cpus = allowed_cpus()?
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",");
        // Some sandboxes forbid get_mempolicy even when no binding is requested.
        // Mark this explicitly; never claim a verified binding in inherited mode.
        let policy = match memory_policy() {
            Ok((mode, nodes)) => format!("{mode}:{nodes:?}"),
            Err(_) => "unavailable".into(),
        };
        Ok(format!(
            "cpu_list=inherited:{cpus}\nmemory_policy=inherited:{policy}\n"
        ))
    }
}

#[cfg(test)]
#[path = "benchmark_tests.rs"]
mod tests;
