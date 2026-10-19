# ReedWeave

Rust research implementation of two polynomial commitment schemes over Goldilocks:

- **ReedWeave_UB**: the unique-decoding base construction.
- **ReedWeave_JB**: the DEEP-enhanced construction strictly below the Johnson radius.

This is experimental research software, not an audited or production-ready cryptographic library. Parameter checks do not certify Fiat–Shamir or hash security.

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
| `scripts/` | Query-count calculators and unified measurement/plotting tools |
| `results/` | Measured results, unavailable markers and comparison figures |

## Build and test

Requires **Rust 1.95+**. Run all commands from the repository root. Dependencies are pinned in `Cargo.lock`, so no local Plonky3 checkout is needed.

```sh
cargo build --release --locked \
  -p reedweave-ub-bench -p reedweave-jb-bench -p plonky3-pcs-bench

cargo test --workspace --locked
```

Scripts require **Python 3.11+**. Plotting and script regression checks also require **Matplotlib**. These checks use disposable outputs, not large benchmark runs:

```sh
python3 scripts/plot_results.py self-test
```

## Run ReedWeave benchmarks

The supplied [UB config](configs/reedweave_ub.toml) and [JB config](configs/reedweave_jb.toml) cover `log_d=20..34` at code rate `1/4`, targeting a 100-bit IOP budget. Each case uses one warmup and five measured trials.

The examples below use one thread and `--no-binding` to disable machine-specific CPU/NUMA binding. Supported thread counts are **1 and 32**. For 32-thread measurements, replace `--threads 1` with `--threads 32` on a suitable machine.

### 1. Check parameters and available resources

Preflight checks the configured sweep without generating proofs or writing measurements. Its memory admission uses conservative estimates; the unified workflow below supports bounded actual allocation attempts instead.

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

`sweep` reads every `[[cases]]` entry. Large cases may exceed available memory. Use the unified workflow for process-level memory limits, failure markers and stopping after an actual memory failure.

```sh
target/release/reedweave-ub-bench sweep \
  --config configs/reedweave_ub.toml --threads 1 --no-binding --out results-new

target/release/reedweave-jb-bench sweep \
  --config configs/reedweave_jb.toml --threads 1 --no-binding --out results-new
```

**Direct benchmarks append results; use a fresh output directory.** ReedWeave verification uses a 32-call hot-batch average. Use `--help` for resource and placement options; bypassing estimates with `--allow-memory-overcommit` does not impose an OS memory limit.

## Run comparison benchmarks

The default `plonky3-pcs-bench` build uses code rate `1/4`. These direct-backend examples select `log_n=20..28`, with one warmup and five measured trials per case:

```sh
target/release/plonky3-pcs-bench preflight \
  --protocols fri,stir,whir --log-n 20..28 --threads 1

target/release/plonky3-pcs-bench sweep \
  --protocols fri,stir,whir --log-n 20..28 --threads 1 --out results-pcs-new
```

FRI, STIR and WHIR use single-call verification timing, unlike ReedWeave's hot-batch average.

### Complete comparison

`scripts/plot_results.py benchmark` manages the standard **20..34** range for all eight PCS series, rates `1/2` and `1/4`, and both thread counts. Brakedown retains its native SdigCode3 rate, approximately `1/1.521`, recorded from actual integer dimensions.

The full workflow requires Linux, `/usr/bin/time`, `taskset`, matching BaseFold benchmarks in `~/gkr-backend`, and Shockwave/Ligero and Brakedown benchmarks in `~/lcpc`. Use `--basefold` / `--lcpc` to override these paths. Builds use cached dependencies (`--offline`), nightly-2025-08-18 for BaseFold and nightly for LCPC; install the dependencies and toolchains beforehand.

```sh
python3 scripts/plot_results.py benchmark plan --campaign results/run-new
python3 scripts/plot_results.py benchmark build --campaign results/run-new
python3 scripts/plot_results.py benchmark run --campaign results/run-new --finalize
```

Existing cases are reused; only missing cases run. Use `--min-log` / `--max-log` for a subrange, or `--rerun` on `plan` for a fresh result set without modifying bundled data.

Attempts use CPU sets 0 or 0–31, cross-NUMA memory and a **480 GiB process-level virtual-address-space limit** by default; choose `--memory-limit-gib` for the host. Native domain/security checks remain enforced, and actual memory failures stop larger cases in the same series. `--finalize` validates and publishes results, then regenerates figures.

## Plot results

Plot the standard **20..34** range, omitting unavailable points:

```sh
python3 scripts/plot_results.py --rate 1/2
python3 scripts/plot_results.py --rate 1/4
```

Figures overwrite `results/figures/goldilocks/`. Use `--out` for another directory and `--help` for more options.
