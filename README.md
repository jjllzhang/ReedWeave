# ReedWeave

Rust research implementation of two polynomial commitment schemes over Goldilocks:

- **ReedWeave_UB**: the unique-decoding base construction.
- **ReedWeave_JB**: the DEEP-enhanced construction strictly below the Johnson radius.

This is experimental research software, not an audited or production-ready cryptographic library.

## Code layout

| Path | Purpose |
|---|---|
| `crates/reedweave-ub-core` | UB commitment, proof generation, verification and codecs |
| `crates/reedweave-jb-core` | JB commitment, proof generation, verification and codecs |
| `crates/reedweave-primitives` | Shared field arithmetic, hashing, FFT and transcripts |
| `crates/reedweave-runtime` | Execution budgets and Rayon thread pools |
| `crates/reedweave-{ub,jb}-bench` | ReedWeave benchmark runners and CSV output |
| `crates/plonky3-pcs-bench` | FRI, STIR and WHIR comparison benchmarks |
| `configs/` | Benchmark parameters and runtime settings |
| `scripts/` | Parameter calculators and plotting tools |
| `results/` | Bundled measurements and figures |

## Build and test

Requires **Rust 1.95+**. Run all commands from the repository root. Dependencies are pinned in `Cargo.lock`, so no local Plonky3 checkout is needed.

```sh
cargo build --release --locked \
  -p reedweave-ub-bench -p reedweave-jb-bench -p plonky3-pcs-bench

cargo test --workspace --locked
```

## Run ReedWeave benchmarks

The supplied [UB config](configs/reedweave_ub.toml) and [JB config](configs/reedweave_jb.toml) cover `log_d=20..28` at code rate `1/4`. Each case performs one discarded warmup and five measured trials.

The examples below use one thread and `--no-binding` to disable the configs' machine-specific CPU/NUMA binding. Supported thread counts are **1 and 32**. For 32-thread measurements, replace `--threads 1` with `--threads 32` on a suitable machine.

### 1. Check parameters and available resources

Preflight checks the configured sweep without generating proofs or writing results.

```sh
target/release/reedweave-ub-bench preflight \
  --config configs/reedweave_ub.toml --threads 1 --no-binding

target/release/reedweave-jb-bench preflight \
  --config configs/reedweave_jb.toml --threads 1 --no-binding
```

### 2. Run a single case

`run` reads `[pp]` from the config, which selects `log_d=20` in the supplied files.

```sh
target/release/reedweave-ub-bench run \
  --config configs/reedweave_ub.toml --threads 1 --no-binding --out results-one

target/release/reedweave-jb-bench run \
  --config configs/reedweave_jb.toml --threads 1 --no-binding --out results-one
```

### 3. Run all configured sizes

`sweep` reads every `[[cases]]` entry. Large cases may require substantial memory, so check preflight before running the full sweep.

```sh
target/release/reedweave-ub-bench sweep \
  --config configs/reedweave_ub.toml --threads 1 --no-binding --out results-new

target/release/reedweave-jb-bench sweep \
  --config configs/reedweave_jb.toml --threads 1 --no-binding --out results-new
```

### Results and options

- CSV files are written to `<out>/ReedWeave_UB/goldilocks.csv` and `<out>/ReedWeave_JB/goldilocks.csv`.
- Each verified trial records public parameters, thread count, commit/open/verify times in milliseconds, and serialized commitment-plus-proof size in KiB.
- Verify time is a hot-batch average, with 32 verification calls after an untimed verification by default. It is not cold single-request latency.
- **Results are appended. Use a fresh output directory for each campaign** and retain stderr logs to record runtime settings.
- Configs must be loaded explicitly with `--config`. Avoid overriding public parameters when reproducing the configured sweep.
- For CPU/NUMA placement, replace `--no-binding` with both `--cpu-list` and `--numa-node`, using values appropriate for your Linux host.
- Use `--help` for additional options, including `--max-memory-mib` and `--time-limit-seconds`.

## Run comparison benchmarks

The default `plonky3-pcs-bench` build uses code rate `1/4`. The following commands check and run FRI, STIR and WHIR over `log_n=20..28`, with one warmup and five measured trials per case.

```sh
target/release/plonky3-pcs-bench preflight \
  --protocols fri,stir,whir --log-n 20..28 --threads 1

target/release/plonky3-pcs-bench sweep \
  --protocols fri,stir,whir --log-n 20..28 --threads 1 --out results-pcs-new
```

Results are saved to `<out>/{FRI,STIR,WHIR}/goldilocks.csv`. Use `--help` for additional options.

FRI, STIR and WHIR use single-call verification timing rather than ReedWeave's hot-batch average. Keep this distinction in mind when comparing results.
