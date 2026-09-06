# M6 measured series

Completed **330 of 330 cases and 1,110 of 1,110 requested verified trials** on 2026-09-06. The single Rust sweep exited successfully. There were **no failed, resource-limited, skipped, incomplete, or rerun cases**. All six raw CSVs contain 185 trials covering 55 configurations each. Earlier small implementation checks remain separate in `m5-validation/`.

## Reproduction and build

The measured source revision is `fd1b8c5b5e97a3652e02cc7e393606ff95dea33f` (committed M1–M5). No Rust, dependency, configuration, or release-binary changes occurred during this series. The working tree was clean before preparation. The release binary was built from that revision with:

```sh
cargo build --release -p brakefri-bench --locked

target/release/brakefri-bench preflight \
  --fields goldilocks-quadratic,f128-base \
  --hashes keccak256,sha256,blake3 --log-n 20..30 --threads 1,2,4,8,16 \
  --config configs/brakefri.toml

target/release/brakefri-bench sweep \
  --fields goldilocks-quadratic,f128-base \
  --hashes keccak256,sha256,blake3 --log-n 20..30 --threads 1,2,4,8,16 \
  --config configs/brakefri.toml --out results/
```

The sweep ran in tmux, from **10:26:08 to 13:49:08 UTC** (3 hours 23 minutes of process wall time, including untimed setup and teardown). Scheduling followed fields, hashes, increasing sizes, then threads. Each of the 330 cases ran in a fresh child, with no concurrent benchmark cases. No optional time or memory cap was supplied. Resource admission retained the existing 80% available-memory policy.

Compiler: Rust `1.95.0 (59807616e 2026-04-14)`, LLVM 22.1.2, target `x86_64-unknown-linux-gnu`, release optimization level 3, default Cargo release options, no `RUSTFLAGS` or encoded Rust flags. The same parallel-enabled binary served all thread settings. Plonky3 remains at `9d496524560f3c699473906c6f50fca7cf343730` through the unchanged lockfile.

SHA-256 identities:

- Release executable: `bcf1c9d061e32bc0ae070f02325d07d1ab84cab142de176f5c8ab865686abcbb`.
- `Cargo.lock`: `d5682f3300979c148dea7d3b4b9db130426e6da8bc49e61bee239262ad2ea3b7`.
- `configs/brakefri.toml`: `23dc46e05ffdbbdba73422354875136fce6d4844a8ebc5acb82dede2b3687932`.

## Configuration and machine

Both profiles (`goldilocks-quadratic`, `f128-base`), all three hashes (`keccak256`, `sha256`, `blake3`), every `log_n=20..30` inclusive, and threads `1,2,4,8,16` were measured. Each configuration has five repetitions for sizes 20–24, three for 25–27, and one for 28–30. Protocol parameters are m=1024, blowup=2, rho=0.5, Q=244.

Fixtures use `SplitMix64-v1`, seed `20260906`, canonical little-endian rejection sampling, and separate coefficient/point streams. Each repetition regenerates the same coefficients; successive repetitions consume successive points after commitment. Field, size, and seed determine the fixtures across hashes and thread settings. There were no warmups or untimed DFT-cache preparations. No invocations were restarted, so no repetition deduplication or point-sequence adjustment was necessary.

The machine reported one AMD EPYC 9754 socket, 128 physical cores / 256 logical CPUs, four NUMA nodes, and about 503 GiB RAM with no swap. Initial available memory was about 491 GiB. All 330 preflight admissions passed; the largest estimated allocation peak, F128 at size 30 with 16 threads, was 108,270,695,192 bytes (about 100.84 GiB). This is the engine's conservative capacity estimate, **not measured peak RSS**. Readable cgroup ancestors reported unlimited memory, with zero OOM events in the recorded snapshots. CPU affinity allowed 0–255; no taskset, NUMA binding, or governor change was applied. Frequency boost was enabled. This was an ordinary host run without exclusive CPU reservation. Formatting, focused tests, and Clippy ran during the first approximately one second of the series and may have affected its earliest timings; those successful rows are retained without replacement.

## Results and verification

Raw files are `<hash>/goldilocks_quadratic.csv` and `<hash>/f128_base.csv`, with exactly:

```csv
log_n,m,k,rho,threads,commit_time,prove_time,verify_time,proof_size
```

Times are measured seconds. Every row follows actual coefficient commitment, proof generation, encoding, decoding, expected-commitment matching, and verification. `proof_size` counts the actual 32-byte initial commitment plus the actual evaluation-proof buffer verified in that trial. Public claims and transcript context are excluded. Serialization is included in commit/prove time and decoding in verify time. No estimated or extrapolated values appear in these CSVs.

For illustration, the following are the **single measured trials** at `log_n=30`, threads=16, copied from the raw files. They are not medians or predictions.

| Hash | Profile | Commit (s) | Prove (s) | Verify (s) | Proof bytes |
|---|---|---:|---:|---:|---:|
| keccak256 | goldilocks-quadratic | 22.830041201 | 19.683745821 | 0.044260417 | 5,200,039 |
| keccak256 | f128-base | 57.281697624 | 70.531269453 | 0.073976728 | 9,202,471 |
| sha256 | goldilocks-quadratic | 24.101912499 | 20.333342698 | 0.032091548 | 5,204,359 |
| sha256 | f128-base | 45.859804860 | 62.279564938 | 0.051100488 | 9,206,087 |
| blake3 | goldilocks-quadratic | 20.414685009 | 16.297940598 | 0.031589208 | 5,182,920 |
| blake3 | f128-base | 46.755317106 | 64.828880658 | 0.056554935 | 9,203,399 |

After the sweep, an independent CSV/log audit checked all headers, field/hash paths, fixed geometry, all 330 parameter groups, exact repetition counts, finite strictly positive measured times, and integer proof sizes greater than 32. Every row matched its ordered `VERIFIED` log entry and actual byte length. Each case had exactly one `START` and `DONE`; proof-size sequences agreed across thread settings. All 330 case metadata records had the same compiler/options identity and lockfile contents. The config and executable hashes still matched preparation. No missing trials or blockers remain.

Evidence outside numeric CSVs:

- [`run.log`](run.log): all resource checks, case starts, verified repetitions, and completions.
- [`metadata/m6-audit.txt`](metadata/m6-audit.txt): independent final count and consistency checks.
- [`metadata/m6-config.toml`](metadata/m6-config.toml): unchanged series configuration.
- [`metadata/m6-environment.txt`](metadata/m6-environment.txt): source revision, compiler, hardware, resources, and identities.
- [`metadata/m6-preflight.txt`](metadata/m6-preflight.txt): all 330 preflight cases.
- `metadata/m6-cgroup-start.txt` and `metadata/m6-cgroup-end.txt`: real cgroup resource snapshots.
- [`metadata/m6-parallel-features.txt`](metadata/m6-parallel-features.txt): enabled upstream parallel feature graph.
- `metadata/<timestamp>-<pid>.txt` and matching `.lock`: immutable metadata and compiled lockfile per child case.
- [`metadata/m6-checks.txt`](metadata/m6-checks.txt): build, formatting, relevant tests, and Clippy output.
- [`metadata/m6-sha256sums.txt`](metadata/m6-sha256sums.txt): raw CSV and run-log identities.

M6 changed measurements and documentation only. Five existing benchmark tests passed with `cargo test -p brakefri-bench --locked`; formatting and workspace Clippy with warnings denied also passed. The previously reviewed full correctness suite was not rerun, and no redundant performance tests were added. Session and temporary monitoring files remain under `.git/m6/`.
