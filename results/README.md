# BrakeFRI benchmark results

All **330 configurations and 1,110 trials** completed successfully on 2026-09-06, with no failures or omissions. This directory keeps the six main measurement CSVs and this summary. Logs, per-case metadata, duplicate dependency snapshots, and preliminary M5 validation files were removed during cleanup; the original artifacts remain in Git history at `e767ef1`.

## Data files

Each hash directory (`keccak256/`, `sha256/`, `blake3/`) contains:

- `goldilocks_quadratic.csv`: Goldilocks base field with quadratic challenges.
- `f128_base.csv`: F128 base field and challenges.

Each CSV contains 185 trials across 55 size/thread configurations, with exactly:

```csv
log_n,m,k,rho,threads,commit_time,prove_time,verify_time,proof_size
```

Times are measured seconds. `proof_size` is the actual 32-byte initial commitment plus the evaluation-proof bytes verified in that trial. Public claims and transcript context are excluded. Commitment/proving times include encoding; verification time includes decoding. Raw repetitions are preserved.

## Campaign settings

- Sizes: every `log_n=20..30`, with `n=2^log_n` coefficients.
- Threads: 1, 2, 4, 8, 16, shared by all three phases.
- Repetitions: five for sizes 20–24, three for 25–27, one for 28–30.
- Protocol: `m=1024`, `k=n/1024`, blowup 2, rate 0.5, 244 queries.
- Fixtures: SplitMix64-v1, seed `20260906`; identical coefficients across repetitions and successive evaluation points. No warmups or untimed DFT-cache preparation.
- Machine: AMD EPYC 9754, 128 physical cores / 256 logical CPUs, about 503 GiB RAM, no swap or explicit CPU/NUMA binding.
- Build: Rust 1.95.0, LLVM 22.1.2, x86_64 Linux, default release optimization, no extra Rust flags.
- Measured source: `fd1b8c5b5e97a3652e02cc7e393606ff95dea33f`; one unchanged binary, dependency lockfile, and configuration throughout the campaign.

Cases ran sequentially in fresh child processes. Total campaign wall time was 3 hours 23 minutes. The host was not exclusively reserved; checks overlapped roughly the first second of the campaign. Large configurations have one trial each, so small timing differences should be interpreted cautiously. Peak RSS was not measured.

## Largest-instance results

Single measured trials at `log_n=30`, threads=16:

| Hash | Profile | Commit (s) | Prove (s) | Verify (ms) | Proof bytes |
|---|---|---:|---:|---:|---:|
| keccak256 | goldilocks-quadratic | 22.830 | 19.684 | 44.260 | 5,200,039 |
| keccak256 | f128-base | 57.282 | 70.531 | 73.977 | 9,202,471 |
| sha256 | goldilocks-quadratic | 24.102 | 20.333 | 32.092 | 5,204,359 |
| sha256 | f128-base | 45.860 | 62.280 | 51.100 | 9,206,087 |
| blake3 | goldilocks-quadratic | 20.415 | 16.298 | 31.589 | 5,182,920 |
| blake3 | f128-base | 46.755 | 64.829 | 56.555 | 9,203,399 |

## Reproduce

From the repository root, build the measured revision with its committed lockfile and configuration. Use a fresh output directory to avoid appending another series to these CSVs:

```sh
cargo build --release -p brakefri-bench --locked

target/release/brakefri-bench sweep \
  --fields goldilocks-quadratic,f128-base \
  --hashes keccak256,sha256,blake3 --log-n 20..30 --threads 1,2,4,8,16 \
  --config configs/brakefri.toml --out /tmp/brakefri-new-series
```
