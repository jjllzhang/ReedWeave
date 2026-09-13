# ReedWeave

**ReedWeave_UB** is the unique-decoding base construction in Section 3 of the paper.
**ReedWeave_JB** is reserved for the future Johnson-radius construction in Section 4;
it is not implemented yet. Shared primitives and runtime keep the ReedWeave family name.

Naming: Rust `ReedWeaveUb`, `UbParams`, `UbProof`; crates/CLI `reedweave-ub-core`
and `reedweave-ub-bench`; plotting selector `reedweave_ub`; results directory `ReedWeave_UB`.
The old unqualified implementation names are no longer supported.

Rust coefficient-input ReedWeave_UB PCS over Goldilocks, with challenge extension degrees **1, 2, 3, 5**, Blake3 hashing, shared Merkle multiproofs, bounded codecs, and benchmark tools. See [ReedWeave.md](ReedWeave.md) for the protocol and soundness derivation.

## Parameters and security

Every ReedWeave_UB invocation requires complete public parameters, via CLI flags or an explicitly loaded TOML file:

`(base_field, extension_degree, log_d, m, blowup, terminal_coefficients, num_queries)`.

The input contains at most `d = 2^log_d` ascending monomial coefficients and is padded internally. Derived geometry is `k=d/m`, `N=blowup*k`, and `t=log2(k/terminal_coefficients)`. Require `k>=4` and a power-of-two `2<=terminal_coefficients<=k/2`, so `1<=t<log2(k)`. The base FFT domain is limited to `2^32`, independently of extension degree. F128 is not supported.

**The Rust API validates geometry, not security.** The independent [Python calculator](scripts/reedweave_ub_queries.py) checks the unique-decoding IOP bound; it does not certify Fiat–Shamir/hash security or knowledge soundness and does not automatically change benchmark parameters.

## Protocol and API

`ReedWeaveUb::commit` retains reusable prover data; `prove`/`verify` implement evaluation
proofs. `open_base(commitment, coefficients, word, execution)` checks a full decoded
opening: root equality and **joint column distance** `2*errors < N-k+1`, not exact-codeword
equality. `ProverData::coefficients()` and `encoded_word()` expose borrowed full-opening
inputs. The natural-order word is an `N`-by-`m` matrix; each stored row is one oracle column.

Proofs carry `t` evaluation-message pairs and only `t-1` intermediate oracle roots.
There is no terminal root or terminal tree: verification evaluates the terminal
polynomial directly at query points. The transcript label is
`ReedWeave_UB-Section3-Multiproof`. The encoding starts with the complete context digest,
with no version byte; obsolete encodings are rejected. UB and future JB must use
separate transcript domains.

## Build and test

Use Rust 1.95+, Python 3.11+, and Matplotlib 3.10+ for plotting. Plonky3 revisions are pinned in `Cargo.toml` and `Cargo.lock`; no local upstream checkout is needed.

```sh
cargo build --release -p reedweave-ub-bench -p plonky3-pcs-bench --locked
cargo test --workspace --locked
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/tests
```

Targeted checks: `cargo test -p reedweave-ub-core -p reedweave-primitives -p reedweave-ub-bench --locked`.
Tests use small fixtures and disposable outputs, not production benchmark sweeps.

## ReedWeave_UB benchmark

[configs/reedweave_ub.toml](configs/reedweave_ub.toml) contains nine tuned cases for `log_d=20..28`, Goldilocks, `blowup=2`, `terminal_coefficients=256`, and a 100-bit IOP target. Parameters minimize expected protocol communication with multiproof sharing under that terminal-size constraint. They do not necessarily minimize runtime.

| log_d | extension_degree | m | num_queries |
|---:|---:|---:|---:|
| 20–21 | 2 | 32 | 241 |
| 22–25 | 2 | 64 | 242 |
| 26 | 2 | 64 | 244 |
| 27–28 | 3 | 64 | 241 |

```sh
# Geometry and resource admission only; no proof allocation or CSV writes.
target/release/reedweave-ub-bench preflight --config configs/reedweave_ub.toml --threads 32

# Production run: nine cases, one discarded warmup + five trials per case.
# Use a fresh output root to avoid appending to an existing campaign.
target/release/reedweave-ub-bench sweep --config configs/reedweave_ub.toml --threads 32 --out results-new

# One case: run reads [pp], not [[cases]].
target/release/reedweave-ub-bench run --config configs/reedweave_ub.toml --threads 32 --out results-one
```

No config is loaded implicitly. `sweep` and `preflight` use the complete `[[cases]]`; `run` uses `[pp]` (the `log_d=20` case). CLI public-parameter flags override every selected case, so do not override them when reproducing the tuned campaign. The config retains thread choices `[1,32]`; `--threads 32` selects only the measurements currently stored in the repository. Use `--help` for lists/ranges and runtime options.

Each case runs in a separate child process and local Rayon pool; supported benchmark thread counts are 1 and 32. There is no explicit CPU/NUMA affinity. Fixture generation uses deterministic `SplitMix64-v1`, seed `20260906`, with separate coefficient/point streams; Fiat–Shamir challenges do not use this generator. Each measured repetition commits afresh and opens at the next point. Warmup resets the point stream before measurements.

Preflight estimates memory, including retained state, temporary buffers, 25% overhead and 32 MiB. Admission uses the smaller of `--max-memory-mib` and 80% of detected available memory. This is not an OS RSS cap. `--time-limit-seconds` bounds the whole child, including setup and warmup. Failed cases return nonzero; only completed verified trials produce rows. Sweeps continue to later cases after a failure.

## Query count and theoretical communication

```sh
# Reads only [pp]; ignores num_queries and [[cases]].
python3 scripts/reedweave_ub_queries.py --config configs/reedweave_ub.toml --security-bits 100 --json

# Omitted extension degree: minimize feasible e first, then Q.
python3 scripts/reedweave_ub_queries.py --base-field goldilocks --log-d 20 \
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
H = t+2*Q*(t*n-t*(t-1)/2)
bytes = 8*B + 8*e*E + 32*H
```

This counts prover-to-verifier communication, including the initial commitment once, but excludes verifier messages, query indices, terminal evaluation tables and serialization framing. It is not the actual wire size. The tuned config was selected using a separate multiproof expectation calculation; the calculator does not perform that optimization.

## Timing and result files

Current ReedWeave_UB, FRI, STIR and WHIR runners use **`timing_model=core-v1`**:

- **Commit:** encoding/FFT, Merkle construction and native commitment work; stops before serialization.
- **Open:** complete typed proof generation, including transcript, folds and multiproofs; stops before serialization.
- **Verify:** full typed verification of the wire-round-trip decoded proof.

Serialization, decoding, canonical encoding checks and transport consistency checks still run, outside timers. Fixture generation, pool/process setup and CSV writes are also outside timers. RS encoding and lazy DFT work remain timed. ReedWeave_UB's `verify_encoded` API retains end-to-end checks.

`proof_size_KiB` is the actual serialized commitment-plus-proof length, not the independent-path estimate. ReedWeave_UB includes its initial 32-byte root once, plus the evaluation proof including context framing. Times are milliseconds; KiB is bytes/1024. Each verified trial is a separate row, rounded to three decimals.

**Runner output and curated plotting input use the same relative layout; use a fresh output root for new campaigns:**

| Purpose | Path |
|---|---|
| ReedWeave_UB runner output | `<out>/ReedWeave_UB/goldilocks.csv` |
| Curated ReedWeave_UB plotting input | `results/ReedWeave_UB/goldilocks.csv` |
| Other protocol CSVs | `<out>/<protocol>/goldilocks.csv` |
| Comparison figure | `results/figures/goldilocks/threads_32.png` |

`results/ReedWeave_UB/goldilocks.csv` contains a fresh run of the corrected implementation,
without the redundant terminal tree. All 45 measured trials and nine discarded warmups
passed verification. The comparison PNG has been regenerated using these results;
other protocols' CSVs were retained unchanged. Build/source fingerprints, run settings,
and verification logs are recorded in [benchmark.log](results/ReedWeave_UB/benchmark.log).

The file covers nine sizes, five trials each, 32 threads, terminal size 256,
and core-v1 timing. It records complete public parameters without a `protocol_version` column:

```csv
base_field,extension_degree,log_d,m,blowup,terminal_coefficients,num_queries,threads,commit_time_ms,open_time_ms,verify_time_ms,proof_size_KiB
```

Runners **append** to compatible CSVs. Use a fresh output directory, validate all cases, then explicitly replace the curated input when publishing a new local campaign. Do not concatenate different timing models. CSVs do not record timing provenance, seeds, revisions or trial IDs; capture stderr logs when those records are needed. Other protocols' existing measurements were not re-run with the latest ReedWeave_UB campaign, so their timing compatibility is not established by the figure.

## Comparison protocols and plotting

`plonky3-pcs-bench` benchmarks upstream FRI/STIR over Goldilocks with cubic challenges, initial rate `1/2` and zero PoW (`log_n=20..30`). Its native multilinear WHIR profile uses hypercube evaluations (`log_n=20..28`), cubic challenges, rate `1/2`, zero PoW and a whole-protocol 100-bit algebraic budget under JohnsonBound. WHIR's native proof includes the opening value. See the executable [FRI/STIR parameters and audit](crates/plonky3-pcs-bench/src/params.rs) and [WHIR parameters and audit](crates/plonky3-pcs-bench/src/whir_params.rs).

```sh
target/release/plonky3-pcs-bench preflight --protocols fri,stir,whir --threads 32
python3 scripts/plot_results.py --threads 32 --validate-only
python3 scripts/plot_results.py --threads 32
```

The plotter reads `<results>/<protocol>/goldilocks.csv` and discovers ReedWeave_UB, FRI, STIR, WHIR, BaseFold, Shockwave and Brakedown. ReedWeave_UB requires the full public-parameter schema: legacy headers are rejected. Protocol version is not inferred from CSV contents. Parameters may vary **between sizes**, but must agree within each size across trials and thread counts. No two parameter choices at the same size are averaged together.

Default sizes are `20..28`; `--log-d`/`--log-sizes` selects others. `--protocols` restricts protocols, `--results` selects an input root, `--plonky3-results` overrides only FRI/STIR/WHIR inputs, and `--out` selects the figure root. Missing explicitly selected data or incomplete trial coverage is an error. Means use five rows per point, except Shockwave and Brakedown, which each supply a single row; `--repetitions` overrides this. Zero timings use linear axes; positive-only metrics use base-2 log axes. Input semantics, security assumptions and PoW may differ across protocols: these are native-configuration comparisons, not identical-task security benchmarks.

## Workspace layout

- `reedweave-ub-core`: public parameters, typed PCS, immutable prover state, codecs and verification.
- `reedweave-primitives`: Goldilocks profiles, canonical hashing, DFT, MMCS and transcript.
- `reedweave-runtime`: local execution budget and Rayon pool.
- `reedweave-ub-bench`: configuration, resource admission, isolated scheduling and CSV output.
- `plonky3-pcs-bench`: independent FRI/STIR/WHIR benchmarks and parameter audits.

ReedWeave_UB binds complete public parameters and encoding conventions into the transcript. `ReedWeaveUb<P>` requires validated parameters matching the chosen field profile; untrusted bytes cannot choose the profile or statement. Historical implementation plans under `docs/` are archival, not current usage instructions; that directory remains ignored by Git.
