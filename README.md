# BrakeFRI

Standalone Rust coefficient-input BrakeFRI PCS with both field profiles, Blake3 hashing, shared Merkle multiproofs, bounded codecs, and a measured Rust CLI. The retained [BrakeFRI results](results/BrakeFRI/) use the current `m=64` geometry and 128-coefficient terminal polynomial, with one discarded warmup and five measured trials per configuration. New runs default to `results/`.

The production API accepts exactly `2^log_n` coefficients in ascending monomial order, for `log_n=14..30`. Parameters are fixed at `m=64`, blowup `2` (rate `1/2`), and `244` replacement-sampled queries. Folding stops at 128 coefficients after `t=log_n-13` rounds. The verifier reconstructs the 256 terminal evaluations and their Merkle root, checks the terminal evaluation claim, and uses those values for query endpoints. The minimum size ensures at least one fold as required by the protocol.

Both field profiles satisfy the paper's 100-bit **interactive** bound throughout this range; the worst case at `n=2^30` is about **100.589 bits**. See [the exact parameter analysis](docs/terminal-polynomial-security.md). This bound excludes hash collision and Fiat–Shamir compilation losses. Proofs and transcript identifiers now use [wire format v2](docs/wire-format.md).

Hashing uses Plonky3's `p3-blake3` (`Blake3`), compiled with its `neon` feature for the aarch64 intrinsics path. Leaf hashing reserves the complete preimage capacity, including its 11-byte header; transcript hashing reserves capacity using the input iterator's length hint. Both submit the assembled bytes through `hash_slice`, which delegates to `hash_iter_slices`. Internal nodes use a fixed 65-byte stack buffer. Leaf hashing parallelism comes from the Merkle tree construction's Rayon batches.

## Plonky3 FRI and STIR PCS benchmarks

The independent [`plonky3-pcs-bench`](crates/plonky3-pcs-bench/README.md) binary benchmarks upstream FRI and STIR PCS implementations for `2^20..2^30` coefficients, using Goldilocks cubic and F128 quadratic challenge fields, initial rate `1/2`, and zero PoW. It provides `run`, `preflight`, and `sweep` commands, with threads `[1, 32]`, one warmup and five measured repetitions. See the [parameters, usage and measurement details](crates/plonky3-pcs-bench/README.md).

## Build and check

Use Rust 1.95 or newer. Dependencies resolve from crates.io and the public Plonky3 Git repository. All `p3-*` crates use the compatible revision in `Cargo.toml` and `Cargo.lock`; the F128 adapter uses Winterfell `winter-math` arithmetic. No local upstream checkout is required.

```sh
cargo build --release -p brakefri-bench --locked
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Use the same parallel-enabled release binary for every thread setting. The benchmark accepts `threads` values of 1 or 32; the selected value controls the initialized local Rayon pool for commit, prove, and verify. Upstream DFT and Merkle construction share that pool through `install`. Independent oracle authentication uses coarse jobs when the other scalar trees contain at least 256 opened leaves. This cutoff is a work heuristic, not a measured crossover. Transcript operations, Horner evaluation, combinations, folds, layout/copy passes, query derivation, multiproof assembly, serialization, and local fold checks stay sequential. The library never initializes a global pool.

## Commands

Run commands from the repository root, or provide an explicit config path. `run` uses the configured repetitions, not necessarily one trial.

```sh
target/release/brakefri-bench --help
target/release/brakefri-bench run --help
target/release/brakefri-bench preflight --help
target/release/brakefri-bench sweep --help

# Quick verified API case; override the repetition policy explicitly.
target/release/brakefri-bench run \
  --field goldilocks-quadratic --log-n 14 --threads 1 \
  --repetitions 1 --out results/quick

# A configured case: five measured trials at log_n=20.
target/release/brakefri-bench run \
  --field goldilocks-quadratic --log-n 20 --threads 1

target/release/brakefri-bench run \
  --field f128-base --log-n 24 --threads 32

# Exact checks and allocation estimates; no proof data or numeric CSV is produced.
target/release/brakefri-bench preflight \
  --fields goldilocks-quadratic,f128-base \
  --log-n 20..30 --threads 1,32

# A Blake3 series. Use a fresh --out directory for a new series.
target/release/brakefri-bench sweep \
  --fields goldilocks-quadratic,f128-base \
  --log-n 20..30 --threads 1,32 \
  --config configs/brakefri.toml --out /tmp/brakefri-blake3-series
```

`run` requires one field, size, and thread count of 1 or 32. The default sweep uses both fields, sizes 20–30, and threads `[1, 32]`: 44 configurations, 44 discarded warmups, and 220 measured trials. `sweep` and `preflight` accept lists and an inclusive size range, or use the corresponding config defaults. Iteration order is fields, increasing sizes, then threads, preserving list order. Unknown fields, unsupported sizes, thread counts other than 1 or 32, incompatible protocol settings, unknown TOML keys, and zero repetitions are rejected. Hashing is fixed to Blake3.

CLI `--out`, `--seed`, `--repetitions`, `--max-memory-mib`, and `--time-limit-seconds` override the respective benchmark settings. Matrix CLI lists and `--log-n` override config selection. Output paths are relative to the working directory. The complete config is checked even when CLI values override benchmark selection. The benchmark config uses a single `repetitions = 5` setting for every size, including API checks at sizes 14–19. CLI `--repetitions` overrides that setting.

## Fixtures, timing, and bytes

Fixtures use the documented `SplitMix64-v1` generator with default seed `20260906`, canonical little-endian rejection sampling, and separate coefficient/point streams. This noncryptographic generator never supplies Fiat–Shamir challenges. For a given field, size, and seed, coefficients are identical across trials and thread counts. Successive repetitions select fresh points after commitment. Separate command invocations reproduce the same point sequence. No trial nonce enters the transcript.

Each configuration first executes one complete warmup through commit, prove, serialization, and encoded verification. Its timings and proof size are discarded, and it produces no CSV row; successful completion is logged as `WARMUP VERIFIED`. A failed warmup aborts the case. The warmup uses the same polynomial and first evaluation point as the formal trials, then resets the point stream so measured inputs remain reproducible. Its PCS instance and proof data are released before formal repetitions.

The warmup and every measured repetition construct fresh public PCS configuration and consume a freshly generated coefficient vector. Commit retains that vector and its tree-owned encoding; prove borrows the immutable state. All opening temporaries drop synchronously before the next repetition. The pool is initialized outside timers and reused across the case. Each configuration runs in a fresh child process; its repetitions commit, prove, then verify in that same process and pool. Verification consumes the newly encoded proof immediately after proving, while prover state remains alive. There is no explicit CPU/NUMA affinity. Lazy DFT twiddle construction is charged to each commit.

- `commit_time`: ready coefficients through padded encoding, DFT, tree construction, returned state/root, and raw commitment encoding.
- `prove_time`: retained state and newly supplied point through claims, combinations, folds, trees, multiproofs, and evaluation-proof encoding.
- `verify_time`: actual bytes through bounded decoding, expected-root matching, typed verification, and all fold checks.

Times are elapsed seconds. Fixture generation, point selection, process startup, public configuration/pool creation, and output writes are outside timers. `proof_size` is the checked sum of the two actual verified buffers: **32 raw initial-root bytes once, plus the evaluation-proof bytes**. Public `z`, `y`, configuration, and transcript context are excluded. A numeric row is appended only after successful verification of those same bytes against the expected commitment and public claim.

## Results and resources

Raw BrakeFRI trials append to `<out>/BrakeFRI/goldilocks.csv` or `<out>/BrakeFRI/f128.csv`. FRI/STIR use `<out>/FRI/<base_field>.csv` and `<out>/STIR/<base_field>.csv`, with compact columns `log_n,rho,threads,commit_time,prove_time,verify_time,proof_size`. Every CSV has exactly this header:

```csv
log_n,m,k,rho,threads,commit_time,prove_time,verify_time,proof_size
```

Existing headers must match exactly; incomplete final rows are rejected. Repetitions remain separate rows. Use a separate output directory for independent or concurrent series; simultaneous writers to one series are unsupported. The two retained CSVs under `results/BrakeFRI/` each contain 110 rows, covering 44 configurations and 220 trials in total. The [four figures](results/figures/) show both field profiles with 1 and 32 threads. These measurements use `m=64`, rate `1/2`, 244 queries, and a 128-coefficient terminal polynomial. All 44 configurations completed one discarded warmup and five verified measured trials.

For new-format BrakeFRI series under `results/BrakeFRI/`, validate with `python3 scripts/plot_results.py --protocols brakefri --validate-only`, then generate its figures with `python3 scripts/plot_results.py --protocols brakefri` (requires Matplotlib 3.10 or newer). To overlay BrakeFRI, FRI and STIR, run `python3 scripts/plot_results.py`; it reads BrakeFRI from `--results` (default `results`) and FRI/STIR from `--plonky3-results` (default `results`). Use `--protocols fri,stir` for a two-protocol comparison. Comparison figures default to `results/figures/<base_field>/threads_<count>.png`; `--out` overrides the figure root. Each image has four metric panels with protocol colors and a legend showing only protocol names. Points are medians of five measured trials (`--repetitions` overrides this count). Only `2^20..2^28` is plotted; rows for `2^29` and `2^30` are ignored. By default, each base field uses thread counts shared by all selected protocols. Use `--threads 32` (or `--threads 1,32`) to require explicit counts for every protocol. Included configurations must cover the complete plotted range; incomplete data is rejected. Times use milliseconds and proof size uses KiB. Vertical axes use base-2 scales with bounds shared across protocols and threads for each base field and metric.

The retained BrakeFRI CSVs have been moved to `results/BrakeFRI/goldilocks.csv` and `results/BrakeFRI/f128.csv` without changing their contents. The plotting script requires the new paths; legacy CSVs under `results/blake3/` are no longer read. Compact FRI/STIR CSVs omit seed, revision and repetition IDs, so campaign compatibility must be ensured by the caller; only row counts, coverage and the remaining values can be validated.

Benchmark runs save only the result CSV files. Case starts, verified trials, resource estimates, and failures are printed to stderr; no `run.log` or `metadata/` files are created.

Preflight checks exact integer soundness inequalities and reports retained coefficients, the initial matrix, all retained tree digests, and scratch estimates. Scratch conservatively includes a full matrix normalization buffer, twiddles, challenge/fold buffers, simultaneous typed/wire/decoded proofs, and worker stacks; the estimate adds 25% allocation overhead plus 32 MiB. These are capacity estimates, not measured RSS. Available resources include CPU parallelism and Linux `MemAvailable`, restricted by readable cgroup v1/v2 memory headroom and ancestor limits. Other platforms report unknown memory and require an explicit `--max-memory-mib` budget.

Admission uses the smaller of a configured `max_memory_mib` and 80% of detected available memory. The memory option is an **estimate-based admission cap**, not an operating-system RSS limit. Requested CPU oversubscription is permitted and visible in preflight. `run` and `sweep` isolate each case in a child process and wait for it before starting another. Optional `time_limit_seconds` is a wall limit for the whole child case, including setup, fixtures, the warmup, and all measured repetitions; the parent polls every 20 ms, kills and reaps an expired child. OS termination and other child failures return a nonzero status. Completed verified rows remain; unfinished trials are reported as unmeasured on stderr. Sweeps continue with later cases and exit nonzero if any case failed. No missing measurement is extrapolated or replaced by zeros.

## Workspace API

`brakefri-core` exports validated `BrakeParams`, `BrakeFri<P>`, immutable `ProverData`, typed proof messages, explicit commitment/evaluation codecs, and `verify_encoded` for expected-root matching and byte accounting. `brakefri-primitives` supplies field profiles, Blake3 role-separated hashing, natural-order DFT, checked MMCS, and the byte transcript. `p3-f128-adapter` wraps Winterfell F128 with current Plonky3 traits. `brakefri-runtime` owns the local execution budget. `brakefri-bench` supplies configuration, resource preflight, sequential case scheduling, and measured CSV output.
