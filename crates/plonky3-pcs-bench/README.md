# Plonky3 FRI / STIR PCS benchmarks

This binary measures upstream `TwoAdicFriPcs` and `TwoAdicStirPcs` at the workspace's pinned Plonky3 revision. It accepts one polynomial in ascending coefficient order, commits it, opens one extension-field point, serializes the commitment and proof, and verifies their decoded representations.

## Fixed protocol parameters

| Parameter | FRI | STIR |
|---|---|---|
| Coefficient counts | `2^20..2^30`, inclusive | `2^20..2^30`, inclusive |
| Initial rate | `1/2` | `1/2`; improves each round |
| Coefficient fields | Goldilocks, F128 | Goldilocks, F128 |
| Challenge fields | Goldilocks cubic, F128 quadratic | Goldilocks cubic, F128 quadratic |
| Security target | 100 algebraic bits | 100 algebraic bits |
| Analysis | Unique decoding, conservative finite-size opening correction | JohnsonBound |
| Folding factor | 2 | 4, including first round |
| Terminal coefficients | 128, matching BrakeFRI | 1 for even `log_n`, 2 for odd `log_n` |
| Queries | 244 | Derived for each round by upstream |
| PoW | 0 for both phases | 0 throughout |
| Hash | Blake3, 32-byte digests | Blake3, 32-byte digests |
| Input shape | One polynomial, one point | One polynomial, one point |

The runtime checks the complete algebraic error budget in `src/params.rs` before admitting a case. The optional [scalar audit script](../../scripts/audit_plonky3_pcs_security.py) independently calculates the FRI/STIR schedules and error budgets without building or running a PCS. It is not a runtime dependency. Its FRI calculation uses exact rational arithmetic with the actual field order; runtime admission uses a conservative field-size lower bound, so reported bit bounds need not be identical. Its STIR final error sums also use a conservative field-size lower bound. Run `python3 scripts/audit_plonky3_pcs_security.py --json` to inspect every round; the script exits nonzero if a checked configuration fails the target. Both the concrete runtime parameters and the current BrakeFRI terminal size must match the audited configuration. Hash collision and Fiat–Shamir compilation losses are outside this algebraic target.

The new F128 quadratic field uses `u²=3`; its extension arithmetic, Frobenius, inverse and Serde come from Plonky3's generic binomial extension. The adapter supplies the nonresidue, multiplicative generator `8+u`, and compatible two-adic roots through order `2^41`.

## Commands

Run from the repository root.

```sh
cargo build --release -p plonky3-pcs-bench --locked

# Parameter derivation and estimated resource admission only; no proof allocation.
target/release/plonky3-pcs-bench preflight

# One configuration: one complete discarded warmup and five measured trials.
target/release/plonky3-pcs-bench run \
  --protocol fri --field goldilocks --log-n 20 --threads 1

target/release/plonky3-pcs-bench run \
  --protocol stir --field f128 --log-n 20 --threads 32

# Full matrix, using defaults: both protocols, both fields, log_n=20..30,
# threads=1,32; 88 configurations, 88 warmups, 440 measured trials.
target/release/plonky3-pcs-bench sweep

# Explicit subset and independent output directory.
target/release/plonky3-pcs-bench sweep \
  --protocols fri,stir --fields goldilocks,f128 \
  --log-n 20..24 --threads 1,32 --out results/plonky3-subset
```

Shared options are `--out` (default `results`), `--seed` (default `20260906`), `--repetitions` (default 5), `--max-memory-mib`, and `--time-limit-seconds`. Warmup count is fixed at one. Resource limits and repetition overrides must be positive. Only thread counts 1 and 32 and sizes 20 through 30 are accepted. Protocol/security settings are fixed in code; changing them requires updating the audit.

`run` launches one child process. `sweep` launches one child per case, sequentially, and continues after failures while returning a nonzero final status if any case failed. The optional time limit covers the entire child, including fixtures, pool setup, warmup and all measured repetitions. Oversized cases are reported as unmeasured, without synthetic timings or proof sizes.

## Fixtures and timing

Coefficient fixtures use the same SplitMix64-v1 generator, canonical rejection sampling and size-dependent seed as BrakeFRI. They are identical across the two PCS protocols, repetitions and thread counts for a given base field and size. Opening points use a separate fixture stream and independently sampled base coordinates. Each is chosen after commitment, rejecting points on the committed LDE coset. Warmup consumes the first point and resets that stream before measured repetitions. Fixtures are noncryptographic and do not supply internal Fiat–Shamir challenges.

Each case creates and initializes one local Rayon pool, used by all phases, including upstream DFT and Merkle operations. Each warmup and repetition constructs fresh PCS and input-DFT instances. These objects, caches and retained prover data are released before the next trial. No global Rayon pool is initialized by this binary. Leaf hashing uses canonical base-field coordinates with distinct input/challenge roles; extension MMCS flattens challenge elements into their base coordinates. Node and transcript hashing have separate roles. The challenger draws uniform field elements by rejection sampling from Plonky3's Blake3 byte challenger, and draws uniform query bits directly from fresh bytes.

- `commit_time`: ready coefficients through conversion to the PCS evaluation-input format, upstream commit, and commitment serialization. Both the input DFT and upstream LDE use fresh caches; their construction is charged to this phase.
- `prove_time`: fresh prover transcript, observation of commitment and public opening point, upstream open, and opening-proof serialization.
- `verify_time`: decoding both buffers, matching the expected commitment, fresh verifier transcript and public-point observation, and upstream verification.

All times are elapsed seconds. Fixture generation, external point selection, public configuration/pool creation, output writes and object destruction after the phase are excluded. Verification uses the trial's PCS instance and freshly decoded proof, while prover state remains alive. As with the existing BrakeFRI benchmark, this is immediate verification following proving, not a separate verifier process.

The public evaluation value comes from the upstream opening result and is supplied to the verifier. The upstream proof binds it through its transcript. A row is appended only after successful verification.

## Results

CSV paths are:

```text
<out>/FRI/goldilocks.csv
<out>/FRI/f128.csv
<out>/STIR/goldilocks.csv
<out>/STIR/f128.csv
```

The CSV records only the key measurements, with one row per verified trial:

```csv
log_n,rho,threads,commit_time,prove_time,verify_time,proof_size
```

`rho` is the initial rate (`0.5`). Protocol and base field are identified by the path; no hash directory or extension-degree suffix is added. Security parameters remain fixed and audited at runtime but are not CSV columns. Retain stderr logs, command options (including seed), and the source revision separately for reproducibility.

`proof_size = commitment_size + opening_proof_size`, in bytes. Both are the actual Postcard-encoded buffers passed through decoding and verification. The commitment root is counted once. Postcard framing is included: a single FRI root encodes to 33 bytes; STIR's one-group wrapper adds one more byte, for 34 bytes. Public `z`, `y` and configuration are excluded. This differs from BrakeFRI's raw 32-byte commitment encoding, although the compact CSV stores only the combined size.

Rows append to existing files only when the header matches and the previous row is complete. Use independent output directories for independent runs; simultaneous writers to the same CSV are unsupported. The shared plotter reads these files and overlays selected protocols in each panel:

```sh
# FRI (blue) and STIR (orange), one four-panel figure per base field/thread count.
python3 scripts/plot_results.py --protocols fri,stir

# Add BrakeFRI (green), reading its CSVs from results/BrakeFRI by default.
python3 scripts/plot_results.py

# Custom input/output locations; validation alone does not generate images.
python3 scripts/plot_results.py --protocols fri,stir \
  --plonky3-results results --out results/figures --validate-only
```

Comparison images default to `<plonky3-results>/figures/goldilocks/threads_<count>.png` and `<plonky3-results>/figures/f128/threads_<count>.png`. Each contains commit, prove, verify and proof-size panels. Medians use five trials unless `--repetitions` specifies another count. Plots include only sizes `2^20..2^28`; rows for `2^29` and `2^30` are ignored. By default, each base field compares only thread counts shared by all selected protocols. Pass `--threads 32` or `--threads 1,32` to require explicit counts; every selected protocol must cover all plotted sizes for those counts. To produce this range, pass `--log-n 20..28` to `sweep` (the benchmark default remains `20..30`). Inputs should come from the same seed and upstream revision for each base field. Compact CSVs do not contain seed/revision or repetition IDs, so the plotter checks row counts and coverage but cannot detect mixed campaigns or replaced duplicate trials. Legacy verbose FRI/STIR CSVs must be converted separately. BrakeFRI files must use `<results>/BrakeFRI/<base_field>.csv`; legacy paths are not supported. Legends show only the protocol names.

## Resource admission

Memory estimates include coefficient/evaluation buffers, retained extension layers, initial and folded Merkle trees, DFT/LDE scratch, worker stacks, allocation overhead and proof buffers. They deliberately allow several concurrent buffers per stage and are conservative estimates rather than measured RSS. Linux admission uses 80% of available memory, restricted by readable cgroup v1/v2 limits and ancestor headroom, and further restricted by `--max-memory-mib` when supplied. On platforms where available memory cannot be detected, supply an explicit admission cap. These checks do not impose a hard RSS limit.

