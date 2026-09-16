# ReedWeave

## Anonymous research artifact

This repository contains the research implementation and evaluation tools for ReedWeave polynomial commitment schemes.

The artifact includes two constructions, benchmark configurations, query-count calculators, measured results, and plotting scripts. Protocol and dependency names are retained to make the implementation reproducible.
This is experimental research software, not an audited or production-ready cryptographic library. Functional tests and parameter calculations do not constitute a security certification.


## Implemented constructions

**ReedWeave_UB** implements the unique-decoding base construction.
**ReedWeave_JB** implements the DEEP-enhanced construction strictly below the
Johnson radius. They have independent commitments, codecs and
transcript domains; shared primitives and runtime keep the ReedWeave family name.

| Variant | Rust | Crates/CLI | Plot selector | Results directory |
|---|---|---|---|---|
| UB | `ReedWeaveUb`, `UbParams`, `UbProof` | `reedweave-ub-core`, `reedweave-ub-bench` | `reedweave_ub` | `ReedWeave_UB` |
| JB | `ReedWeaveJb`, `JbParams`, `JbProof` | `reedweave-jb-core`, `reedweave-jb-bench` | `reedweave_jb` | `ReedWeave_JB` |


Rust coefficient-input PCSs over Goldilocks, with challenge extension degrees **1, 2, 3, 5**, Blake3 hashing, shared Merkle multiproofs, bounded codecs, and benchmark tools. Protocol behavior, parameters, and security limitations are described below.

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
`ReedWeave_UB-Multiproof`. The encoding starts with the complete context digest,
with no version byte; obsolete encodings are rejected. UB and JB use
separate transcript domains.

## Build and test

Use Rust 1.95+, Python 3.11+, and Matplotlib 3.10+ for plotting. Plonky3 revisions are pinned in `Cargo.toml` and `Cargo.lock`; no local upstream checkout is needed.

```sh
cargo build --release -p reedweave-ub-bench -p reedweave-jb-bench -p plonky3-pcs-bench --locked
cargo test --workspace --locked
```

Targeted checks: `cargo test -p reedweave-ub-core -p reedweave-jb-core -p reedweave-primitives -p reedweave-ub-bench -p reedweave-jb-bench --locked`.
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

No config is loaded implicitly. `sweep` and `preflight` use the complete `[[cases]]`; `run` uses `[pp]` (the `log_d=20` case). CLI public-parameter flags override every selected case, so do not override them when reproducing the tuned campaign. The config retains thread choices `[1,32]`; `--threads 32` selects only the 32-thread cases. Bundled results include both single-thread and 32-thread measurements. Use `--help` for lists/ranges and runtime options.

Each case runs in a separate child process and local Rayon pool; supported benchmark thread counts are 1 and 32. The supplied ReedWeave configs bind CPUs `0-31` and memory to NUMA node `0` on the experiment host; adapt both settings on other machines. Fixture generation uses deterministic `SplitMix64-v1`, seed `20260906`, with separate coefficient/point streams; Fiat–Shamir challenges do not use this generator. Each measured repetition commits afresh and opens at the next point. Warmup resets the point stream before measurements.

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

## ReedWeave_JB

### Parameters, protocol and security scope

JB uses the same geometry and field profiles as UB, plus required public
`agreement_numerator` and `agreement_denominator`. Their reduced rational value
is `a=1-delta`, with **`sqrt(rho)<a<1`**. The strict comparison is checked with
integers; no floating-point radius enters the verifier. For example, `a=18/25`
at `blowup=2` gives `delta=0.28`, strictly below `1-sqrt(1/2)`.

`ReedWeaveJb::commit` first fixes the initial Merkle root, then derives
`zeta` uniformly from the challenge extension minus the base FFT domain, and
computes `c_i=f_i(zeta)`. A `JbCommitment<P>` carries a context digest, root,
`zeta`, and `m` extension-valued `deep_values`; it is **not a 32-byte root**.
The immutable state can be reused at different base-field target points.
`prove`/`verify` maintain the target and DEEP evaluation claims through the same
folding challenges, with four extension-valued messages per round, `t-1`
intermediate roots, and no terminal tree. Encoding and initial leaves remain
base-valued; increasing extension degree does not enlarge the base FFT domain.

`open_deep` checks root equality, all DEEP component evaluations, and strict
**joint column distance** `errors*denominator < N*(denominator-numerator)`.
`validate_commitment` checks shape, context and challenge replay, not knowledge
of an opening. Parameter-aware commitment/proof codecs reject malformed lengths
before allocation and enforce canonical encodings. `verify_encoded` compares
the full caller-expected commitment and intended `(z,y)`, not only the root.

**Security limitation:** the calculator bounds interactive IOP errors only. This implementation
uses separately domain-separated Fiat–Shamir commit/evaluation transcripts;
Merkle/Fiat–Shamir compilation losses, grinding, and ROM/QROM guarantees are not
certified by the calculator or functional tests. No executable general list
decoder/extractor, zero knowledge, or multipoint batching is provided.

### Query calculator and configurations

[The JB calculator](scripts/reedweave_jb_queries.py) follows the UB CLI convention:
Q alone on stdout, metadata on stderr, or a structured `--json` report. It reads
only `[pp]` from TOML, ignores its old `num_queries` and `[[cases]]`, and applies
CLI overrides. Without an explicit extension degree, it selects the smallest
feasible degree from `{1,2,3,5}`; explicit degrees are never silently upgraded.

```sh
python3 scripts/reedweave_jb_queries.py --base-field goldilocks --log-d 20 \
  --m 32 --blowup 2 --terminal-coefficients 256 \
  --agreement 18/25 --security-bits 100 --json

python3 scripts/reedweave_jb_queries.py --config configs/reedweave_jb.toml \
  --security-bits 100 --json
```

For `B=floor(1/(a^2-rho))` and `qK=q0^e`, it certifies the minimum `Q>=1` for
one commitment plus one evaluation under the conservative IOP union bound:

```text
binom(B,2)*(k-1)/(qK-N)
+ err(C0,m,delta) + sum_{j=0}^{t-1} err(C_(j+1),2,delta)
+ B*(m-1+t)/qK + a^Q <= 2^-security_bits
```

The MCA errors use the applicable unique-decoding or Johnson-radius bound **at every layer**, including
`C_t`; the Johnson branch uses `(k_j-1)/N_j` and its local slack. Exact rational
square-root intervals certify both Q and Q-1. An exhausted algebraic budget is
reported as unprovable with this bound, not as an attack or a reason to increase Q.
For the first command above, `e=3,Q=212,B=54`; forcing `e=2` cannot certify 100 bits.
Repeated evaluations require a corresponding total budget, not an unlimited
reuse of a single-opening security estimate.

Communication reports include the full protocol commitment once and distinguish
independent paths from the expected antipodal-pair multiproof size. With the
same e/Q/geometry, JB adds `(m+1+2t)*8e` protocol bytes over UB. Context/framing
and public `(z,y)` are excluded from these estimates; benchmark proof size is
the actual serialized commitment-plus-proof length.

[configs/reedweave_jb.toml](configs/reedweave_jb.toml) supplies nine 100-bit IOP
cases for `log_d=20..28`, with `terminal_coefficients=256`.
The TOML comments record the finite candidate grid, objective and reproduction
command. Detailed error/certificate reports are generated on demand with
`--search --json`; no generated audit JSON is stored in the repository or required
at runtime. These are selected theoretical parameters, **not globally optimal
configurations or performance measurements**.
Use the calculator's `--help` for bounded grid search and explicit selection
objectives; minimizing feasible e is different from minimizing expected bytes.

### Benchmarking

```sh
# Geometry/resource admission only; no proof allocation or result writes.
target/release/reedweave-jb-bench preflight --config configs/reedweave_jb.toml --threads 32

# A new campaign, never appended to historical UB measurements.
target/release/reedweave-jb-bench sweep --config configs/reedweave_jb.toml \
  --threads 32 --out results-jb-new
```

`run` reads `[pp]`; `sweep`/`preflight` read complete `[[cases]]`. Admission,
worker isolation and `core-hot-verify` timing follow UB. Commit time includes DEEP challenge
generation and c evaluation; Open includes both evaluation chains; typed Verify
includes commitment challenge replay. Canonical wire round-trip stays outside
timers. Output is `<out>/ReedWeave_JB/goldilocks.csv`, with both agreement fields
in addition to the complete UB-style public parameters. A curated JB campaign
is bundled as `results/ReedWeave_JB/goldilocks.csv` (nine sizes, five trials per
size for each rate/thread combination); the plotter validates it like the UB file. Use fresh output roots for
new campaigns and retain the chosen parameters and execution logs. A generated
JSON report may optionally accompany your campaign outputs.

## Timing and result files

Current ReedWeave_UB and ReedWeave_JB runners use **`timing_model=core-hot-verify`**:

- **Commit:** encoding/FFT, Merkle construction and native commitment work; stops before serialization.
- **Open:** complete typed proof generation, including transcript, folds and multiproofs; stops before serialization.
- **Verify:** one untimed full verification of the decoded proof, followed by a single timed batch of `verify_repetitions` complete verifications of that **same proof** (default 32). The CSV records batch elapsed time divided by the count. Every call performs all checks, and any failure aborts the trial. This measures hot amortized cost, **not cold single-request latency**.

FRI, STIR and WHIR retain their existing single-call verification measurements; they have not been changed to this hot-batch model.

Serialization, decoding, canonical encoding checks and transport consistency checks still run, outside timers. Fixture generation, pool/process setup and CSV writes are also outside timers. RS encoding and lazy DFT work remain timed. ReedWeave_UB's `verify_encoded` API retains end-to-end checks.

`proof_size_KiB` is the actual serialized commitment-plus-proof length, not the independent-path estimate. ReedWeave_UB includes its initial 32-byte root once, plus the evaluation proof including context framing; ReedWeave_JB measures its full serialized DEEP commitment plus evaluation proof. Times are milliseconds; KiB is bytes/1024. Each verified trial is a separate row, rounded to three decimals.

**Runner output and curated plotting input use the same relative layout; use a fresh output root for new campaigns:**

| Purpose | Path |
|---|---|
| ReedWeave_UB runner output | `<out>/ReedWeave_UB/goldilocks.csv` |
| ReedWeave_JB runner output | `<out>/ReedWeave_JB/goldilocks.csv` |
| Curated ReedWeave_UB plotting input | `results/ReedWeave_UB/goldilocks.csv` |
| Curated ReedWeave_JB plotting input | `results/ReedWeave_JB/goldilocks.csv` |
| Other protocol CSVs | `<out>/<protocol>/goldilocks.csv` |
| Comparison figures | `results/figures/goldilocks/threads_<count>_rate_<num>_<den>.png` |

`results/ReedWeave_UB/goldilocks.csv` and `results/ReedWeave_JB/goldilocks.csv`
each contain 180 rows: nine sizes (`log_d=20..28`), five verified trials per
size, rates `1/2` and `1/4`, and thread counts 1 and 32. Terminal size is 256.
The supplied configs specify CPUs 0-31, NUMA memory
node 0, seed 20260906, and 32 timed verifications after an untimed verification.
Comparison figures use the protocol CSVs at the selected rate and thread count;
they do not establish identical timing methodology across protocols.

Each file records complete public parameters without a `protocol_version` column;
the JB file inserts `agreement_numerator,agreement_denominator` after `num_queries`.
The UB header is:

```csv
base_field,extension_degree,log_d,m,blowup,terminal_coefficients,num_queries,threads,commit_time_ms,open_time_ms,verify_time_ms,proof_size_KiB
```

Runners **append** to compatible CSVs. Use a fresh output directory, validate all cases, then explicitly replace the curated input when publishing a new local campaign. Do not concatenate different timing models. CSV rows do not record timing provenance, seeds, revisions or trial IDs; retain stderr logs (which record measurement settings and seed) and source provenance. The comparison protocols' existing measurements were not re-run with the ReedWeave_UB/JB campaigns, so their timing compatibility is not established by the figure.

### Placement and new ReedWeave campaigns

Both CLI and `[benchmark]` accept `cpu_list`, `numa_node`, and `verify_repetitions`
(CLI: `--cpu-list`, `--numa-node`, `--verify-repetitions`). CPU and memory binding
must be supplied together. `--no-binding` explicitly overrides config placement
and inherits the launch environment; without a config, placement is inherited.
The default verification batch size is 32 even without a config.

Binding uses Linux CPU affinity plus `MPOL_BIND` **inside the isolated worker,
before creating the Rayon pool or allocating polynomial data**. CPUs must be
allowed, belong to the selected memory node, and number at least the worker
thread count. This restricts a CPU set; it does not pin each worker to a distinct
physical core. No global NUMA/kernel settings are modified. Unsupported systems
or binding failures return an error, never silently fall back. Preflight checks
topology/allowed sets without changing placement; actual syscall permissions are
checked by the worker. Memory admission estimates are not a reservation of RAM
on the selected node.

```sh
# Supplied configs select CPUs 0-31 / node 0 and a 32-call hot verification batch.
target/release/reedweave-ub-bench sweep --config configs/reedweave_ub.toml --threads 32 --out results-bound
target/release/reedweave-jb-bench sweep --config configs/reedweave_jb.toml --threads 32 --out results-bound
```

Benchmarks write **only `goldilocks.csv`** in each protocol's output directory.
Timing semantics, verification batch size/warmup, seed, and placement are printed
to stderr; no `goldilocks.benchmark.txt` is created or consulted. Existing sidecars
are left untouched. The CSV schema and existing CSV validation are unchanged,
but timing settings are no longer checked when appending: use a fresh output root
when changing measurement settings and retain stderr logs yourself.
The bundled ReedWeave results/figure now include the bound hot-batch campaign
described above; do not mix it with historical single-call measurements. Changing
`verify_repetitions` to 1 still includes a per-proof untimed warmup and does not
restore cold-latency semantics.

## Comparison protocols and plotting

`plonky3-pcs-bench` defaults to the initial rate `1/4` profile. Building the same current source with `--no-default-features --features rate-half` selects the audited `1/2` profile (FRI: 244 rather than 151 queries); no historical checkout is needed. The remaining description in this paragraph refers to the default quarter-rate build. It benchmarks upstream FRI/STIR over Goldilocks with cubic challenges and zero PoW (`log_n=20..30`): FRI uses 151 queries, binary folds and 128 terminal coefficients; STIR uses four-way folds and automatically derived JohnsonBound parameters. Its native multilinear WHIR profile uses hypercube evaluations (`log_n=20..28`), cubic challenges, rate `1/4`, zero PoW, four-way folds and a whole-protocol 100-bit algebraic budget under JohnsonBound. All three profiles must pass the whole-protocol >=100-bit audit before measurement. Results append to the existing protocol CSVs with `rho=1/4`; select a single rate before plotting mixed-rate files. `--allow-memory-overcommit` explicitly bypasses the available-memory estimate (an OS OOM kill is possible); an explicit `--max-memory-mib` cap is still enforced. The 32-thread `log_n=20..28` experiment appends five measured rows per case after one discarded warmup; logs and original CSV snapshots are in `results/logs/pcs-rate-1_4-threads32/`. WHIR's native proof includes the opening value. See the executable [FRI/STIR parameters and audit](crates/plonky3-pcs-bench/src/params.rs) and [WHIR parameters and audit](crates/plonky3-pcs-bench/src/whir_params.rs).

```sh
target/release/plonky3-pcs-bench preflight --protocols fri,stir,whir --threads 32
python3 scripts/plot_results.py --threads 32 --validate-only
python3 scripts/plot_results.py --threads 32
# Quarter-rate comparison, with Brakedown's supplied native-rate reference:
python3 scripts/plot_results.py --threads 32 --rate 1/4 \
  --protocols fri,stir,whir,basefold,shockwave,brakedown
```

### Reproduce the bundled single-thread figures

From the repository root, using the current curated CSV files:

```sh
python3 scripts/plot_results.py --threads 1 --rate 1/2 --validate-only
python3 scripts/plot_results.py --threads 1 --rate 1/4 --validate-only
python3 scripts/plot_results.py --threads 1 --rate 1/2
python3 scripts/plot_results.py --threads 1 --rate 1/4
```

These commands compare all eight available protocols over sizes `2^20..2^28`
and write `results/figures/goldilocks/threads_1_rate_1_2.png` and
`results/figures/goldilocks/threads_1_rate_1_4.png`. They do not run benchmarks or
modify the input CSVs. Brakedown retains its native rate in both comparisons.

### Rate-specific single-thread PCS campaigns

```sh
# Each entry point builds only its selected rate from the current working tree.
./scripts/run_pcs_single_thread_rate_1_2.py
./scripts/run_pcs_single_thread_rate_1_4.py
# Build and preflight only: no proofs, benchmark measurements or CSV appends.
./scripts/run_pcs_single_thread_rate_1_2.py --prepare-only
./scripts/run_pcs_single_thread_rate_1_4.py --prepare-only
```

Each script runs FRI, STIR and WHIR at its selected rate sequentially with no
inter-case cooldowns. Common validation/build/append logic lives in
`scripts/pcs_single_thread_common.py`; the former combined entry point has been
replaced by these two scripts. Each group uses `log_n=20..28`, one
local Rayon worker, one discarded warmup, five measured repetitions, seed
`20260906`, a whole-protocol 100-bit algebraic target and zero PoW. Placement is
inherited. The selected binary is built before measurement and copied to a stable
path under `results/logs/pcs-single-rate-1_2-*/bin/` or
`results/logs/pcs-single-rate-1_4-*/bin/`; logs, original CSV snapshots and a
manifest are saved alongside them. The working tree's sources are not replaced.

Each verified trial immediately appends to `results/{FRI,STIR,WHIR}/goldilocks.csv`
with the correct `rho`; three complete new groups produce 135 rows per script
(45 per protocol). `--out DIR`
selects another result root. On reruns, a group with exactly five rows at every
selected size is skipped; partial/duplicate groups are refused before building
so they cannot be silently mixed. Inspect partial results manually or choose a
fresh output root. A failed group retains completed rows and later groups are
still attempted, with a nonzero final exit status. Quarter-rate runs explicitly
use `--allow-memory-overcommit`; this bypasses conservative admission, not actual
RAM limits, and an OS OOM kill remains possible. Both scripts share a local lock
to prevent concurrent instances writing the same output root; do not run other
benchmark writers against that root concurrently.

The plotter reads `<results>/<protocol>/goldilocks.csv` and discovers ReedWeave_UB, ReedWeave_JB, FRI, STIR, WHIR, BaseFold, Shockwave and Brakedown. UB and JB require their complete public-parameter schemas; JB additionally validates its rational agreement. Legacy headers are rejected. Protocol version is not inferred from CSV contents. Parameters may vary **between sizes**, but must agree within each size across trials and thread counts. No two parameter choices at the same size are averaged together.

`--rate` selects the initial code rate (default `1/2`) before grouping trials or checking per-size public-parameter identity; UB/JB use `1/blowup`, other protocols use `rho`. Brakedown always uses its supplied native-rate rows and is labeled accordingly. Explicitly select protocols with data at the requested rate; absent coverage is an error. Output names include the canonical rate, e.g. `results/figures/goldilocks/threads_32_rate_1_4.png`, so different-rate figures do not overwrite one another.

Default sizes are `20..28`; `--log-d`/`--log-sizes` selects others. `--protocols` restricts protocols, `--results` selects an input root, `--plonky3-results` overrides only FRI/STIR/WHIR inputs, and `--out` selects the figure root. Missing explicitly selected data or incomplete trial coverage is an error. Means use five rows per point, except Shockwave and Brakedown, which each supply a single row; `--repetitions` overrides this. Zero timings use linear axes; positive-only metrics use base-2 log axes. Input semantics, security assumptions and PoW may differ across protocols: these are native-configuration comparisons, not identical-task security benchmarks.

## Workspace layout

- `reedweave-ub-core`: UB public parameters, typed PCS, immutable prover state, codecs and verification.
- `reedweave-jb-core`: independent DEEP commitment, dual-chain PCS, rational radius and bounded codecs.
- `reedweave-primitives`: Goldilocks profiles, canonical hashing, DFT, MMCS and transcript.
- `reedweave-runtime`: local execution budget and Rayon pool.
- `reedweave-ub-bench` / `reedweave-jb-bench`: variant-specific configuration, resource admission, isolated scheduling and CSV output.
- `plonky3-pcs-bench`: independent FRI/STIR/WHIR benchmarks and parameter audits.

Both variants bind complete public parameters and encoding conventions into their independent transcripts. `ReedWeaveUb<P>` and `ReedWeaveJb<P>` require validated parameters matching the chosen field profile; untrusted bytes cannot choose the profile or statement. This README and the production scripts are the current usage instructions.
