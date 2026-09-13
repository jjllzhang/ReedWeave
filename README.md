# ReedWeave

Crate names, CLI commands, and protocol identifiers consistently use the ReedWeave name.

Rust coefficient-input ReedWeave PCS over Goldilocks, with challenge extension degrees **1, 2, 3, 5**, Blake3 hashing, shared Merkle multiproofs, bounded codecs, and benchmark tools. See [ReedWeave.md](ReedWeave.md) for the protocol and soundness derivation; [WHIR.md](WHIR.md) is the reference paper, not the WHIR benchmark manual.

## Parameters and security

Every ReedWeave invocation requires complete public parameters, via CLI flags or an explicitly loaded TOML file:

`(base_field, extension_degree, log_d, m, blowup, terminal_coefficients, num_queries)`.

The input contains at most `d = 2^log_d` ascending monomial coefficients and is padded internally. Derived geometry is `k=d/m`, `N=blowup*k`, and `t=log2(k/terminal_coefficients)`. At least one binary fold is required. The base FFT domain is limited to `2^32`, independently of extension degree. F128 is not supported.

**The Rust API validates geometry, not security.** The independent [Python calculator](scripts/reedweave_queries.py) checks the unique-decoding IOP bound; it does not certify Fiat–Shamir/hash security or knowledge soundness and does not automatically change benchmark parameters.

## Build and test

Use Rust 1.95+, Python 3.11+, and Matplotlib 3.10+ for plotting. Plonky3 revisions are pinned in `Cargo.toml` and `Cargo.lock`; no local upstream checkout is needed.

```sh
cargo build --release -p reedweave-bench -p plonky3-pcs-bench --locked
cargo test --workspace --locked
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/tests
```

For coverage, targeted commands, and optional formatting/lint checks, see [TESTING.md](TESTING.md). Tests use small fixtures and disposable outputs, not production benchmark sweeps.

## ReedWeave benchmark

[configs/reedweave.toml](configs/reedweave.toml) contains nine tuned cases for `log_d=20..28`, Goldilocks, `blowup=2`, `terminal_coefficients=256`, and a 100-bit IOP target. Parameters minimize expected protocol communication with multiproof sharing under that terminal-size constraint. They do not necessarily minimize runtime.

| log_d | extension_degree | m | num_queries |
|---:|---:|---:|---:|
| 20–21 | 2 | 32 | 241 |
| 22–25 | 2 | 64 | 242 |
| 26 | 2 | 64 | 244 |
| 27–28 | 3 | 64 | 241 |

```sh
# Geometry and resource admission only; no proof allocation or CSV writes.
target/release/reedweave-bench preflight --config configs/reedweave.toml --threads 32

# Production run: nine cases, one discarded warmup + five trials per case.
# Use a fresh output root to avoid appending to an existing campaign.
target/release/reedweave-bench sweep --config configs/reedweave.toml --threads 32 --out results-new

# One case: run reads [pp], not [[cases]].
target/release/reedweave-bench run --config configs/reedweave.toml --threads 32 --out results-one
```

No config is loaded implicitly. `sweep` and `preflight` use the complete `[[cases]]`; `run` uses `[pp]` (the `log_d=20` case). CLI public-parameter flags override every selected case, so do not override them when reproducing the tuned campaign. The config retains thread choices `[1,32]`; `--threads 32` selects only the measurements currently stored in the repository. Use `--help` for lists/ranges and runtime options.

Each case runs in a separate child process and local Rayon pool; supported benchmark thread counts are 1 and 32. There is no explicit CPU/NUMA affinity. Fixture generation uses deterministic `SplitMix64-v1`, seed `20260906`, with separate coefficient/point streams; Fiat–Shamir challenges do not use this generator. Each measured repetition commits afresh and opens at the next point. Warmup resets the point stream before measurements.

Preflight estimates memory, including retained state, temporary buffers, 25% overhead and 32 MiB. Admission uses the smaller of `--max-memory-mib` and 80% of detected available memory. This is not an OS RSS cap. `--time-limit-seconds` bounds the whole child, including setup and warmup. Failed cases return nonzero; only completed verified trials produce rows. Sweeps continue to later cases after a failure.

## Query count and theoretical communication

```sh
# Reads only [pp]; ignores num_queries and [[cases]].
python3 scripts/reedweave_queries.py --config configs/reedweave.toml --security-bits 100 --json

# Omitted extension degree: minimize feasible e first, then Q.
python3 scripts/reedweave_queries.py --base-field goldilocks --log-d 20 \
  --m 64 --blowup 2 --terminal-coefficients 128 --security-bits 100
```

With `rho=1/blowup`, `k_t=terminal_coefficients`, and `A_t=blowup*(d-k_t)+m-1+t`, the calculator finds the minimum integer `Q>=1` satisfying

```text
((1+rho)/2)^Q + A_t/q^e <= 2^-security_bits
```

It uses exact integer comparisons and the actual Goldilocks order `q=2^64-2^32+1`. If `q^e <= A_t*2^security_bits`, no finite query count suffices. An omitted degree is selected from `{1,2,3,5}`; an explicit degree is never upgraded. Minimizing feasible `e` is not the same as minimizing proof size. Query positions are sampled with replacement, so `Q` can exceed `N`.

Default output is `Q` on stdout and selected-degree/size information on stderr; `--json` emits a structured report. The Python APIs are `minimum_queries`, `select_parameters`, and `theoretical_proof_size`. Custom `--q` and explicit degrees outside runtime support are mathematical inputs only; field construction is the caller's responsibility.

The calculator's size model uses **independent paths, without multiproof or leaf deduplication**. For `n=log2(N)`, its base elements, extension elements, and hash counts are:

```text
B = m*(1+2*Q)
E = 2*t+k_t+2*Q*(t-1)
H = 1+t+2*Q*(t*n-t*(t-1)/2)
bytes = 8*B + 8*e*E + 32*H
```

This counts prover-to-verifier communication, including the initial commitment once, but excludes verifier messages, query indices, terminal evaluation tables and serialization framing. It is not the actual wire size. The tuned config was selected using a separate multiproof expectation calculation; the calculator does not perform that optimization.

## Timing and result files

Current ReedWeave, FRI, STIR and WHIR runners use **`timing_model=core-v1`**:

- **Commit:** encoding/FFT, Merkle construction and native commitment work; stops before serialization.
- **Open:** complete typed proof generation, including transcript, folds and multiproofs; stops before serialization.
- **Verify:** full typed verification of the wire-round-trip decoded proof.

Serialization, decoding, canonical encoding checks and transport consistency checks still run, outside timers. Fixture generation, pool/process setup and CSV writes are also outside timers. RS encoding and lazy DFT work remain timed. ReedWeave's `verify_encoded` API retains end-to-end checks.

`proof_size_KiB` is the actual serialized commitment-plus-proof length, not the independent-path estimate. ReedWeave includes its initial 32-byte root once, plus the evaluation proof including version/context framing. Times are milliseconds; KiB is bytes/1024. Each verified trial is a separate row, rounded to three decimals.

**Runner output and curated plotting input use the same relative layout; use a fresh output root for new campaigns:**

| Purpose | Path |
|---|---|
| ReedWeave runner output | `<out>/ReedWeave/goldilocks.csv` |
| Curated ReedWeave plotting input | `results/ReedWeave/goldilocks.csv` |
| Other protocol CSVs | `<out>/<protocol>/goldilocks.csv` |
| Comparison figure | `results/figures/goldilocks/threads_32.png` |

The curated ReedWeave file contains the latest 45 measured rows: nine configured sizes, five trials each, 32 threads, terminal size 256, core-v1 timing. It records complete public parameters without a `protocol_version` column:

```csv
base_field,extension_degree,log_d,m,blowup,terminal_coefficients,num_queries,threads,commit_time_ms,open_time_ms,verify_time_ms,proof_size_KiB
```

Runners **append** to compatible CSVs. Use a fresh output directory, validate all cases, then explicitly replace the curated input when publishing a new local campaign. Do not concatenate different timing models. CSVs do not record timing provenance, seeds, revisions or trial IDs; capture stderr logs when those records are needed. Other protocols' existing measurements were not re-run with the latest ReedWeave campaign, so their timing compatibility is not established by the figure.

## Comparison protocols and plotting

`plonky3-pcs-bench` benchmarks upstream FRI/STIR over Goldilocks with cubic challenges, initial rate `1/2` and zero PoW (`log_n=20..30`). Its native multilinear WHIR profile uses hypercube evaluations (`log_n=20..28`), cubic challenges, rate `1/2`, zero PoW and a whole-protocol 100-bit algebraic budget under JohnsonBound. WHIR's native proof includes the opening value. See the executable [FRI/STIR parameters and audit](crates/plonky3-pcs-bench/src/params.rs) and [WHIR parameters and audit](crates/plonky3-pcs-bench/src/whir_params.rs).

```sh
target/release/plonky3-pcs-bench preflight --protocols fri,stir,whir --threads 32
python3 scripts/plot_results.py --threads 32 --validate-only
python3 scripts/plot_results.py --threads 32
```

The plotter reads `<results>/<protocol>/goldilocks.csv` and discovers ReedWeave, FRI, STIR, WHIR, BaseFold, Shockwave and Brakedown. ReedWeave requires the full public-parameter schema: legacy headers are rejected. Protocol version is not inferred from CSV contents. Parameters may vary **between sizes**, but must agree within each size across trials and thread counts. No two parameter choices at the same size are averaged together.

Default sizes are `20..28`; `--log-d`/`--log-sizes` selects others. `--protocols` restricts protocols, `--results` selects an input root, `--plonky3-results` overrides only FRI/STIR/WHIR inputs, and `--out` selects the figure root. Missing explicitly selected data or incomplete trial coverage is an error. Means use five rows per point, except Shockwave and Brakedown, which each supply a single row; `--repetitions` overrides this. Zero timings use linear axes; positive-only metrics use base-2 log axes. Input semantics, security assumptions and PoW may differ across protocols: these are native-configuration comparisons, not identical-task security benchmarks.

## Workspace layout

- `reedweave-core`: public parameters, typed PCS, immutable prover state, codecs and verification.
- `reedweave-primitives`: Goldilocks profiles, canonical hashing, DFT, MMCS and transcript.
- `reedweave-runtime`: local execution budget and Rayon pool.
- `reedweave-bench`: configuration, resource admission, isolated scheduling and CSV output.
- `plonky3-pcs-bench`: independent FRI/STIR/WHIR benchmarks and parameter audits.

ReedWeave binds complete public parameters and encoding conventions into the transcript. `ReedWeave<P>` requires validated parameters matching the chosen field profile; untrusted bytes cannot choose the profile or statement. Historical implementation plans under `docs/` are archival, not current usage instructions; that directory remains ignored by Git.
