# Implementation status

## M1: complete

The Cargo workspace contains four implemented crates. All Plonky3 dependencies resolve from public Git revision `9d496524560f3c699473906c6f50fca7cf343730` (compatible upstream 0.7.0 sources); `Cargo.lock` retains the resolved dependency graph. F128 arithmetic delegates to crates.io `winter-math` 0.13. No absolute checkout dependencies are used.

### Architecture

`p3-f128-adapter` wraps Winterfell F128 with a private backend, canonical 16-byte little-endian Serde, checked canonical conversions, reducing integer quotient maps, Plonky3 field traits, and scalar packing. Its roots follow the fixed order-2^40 generator. Goldilocks and its quadratic extension use upstream arithmetic and the fixed order-2^32 root.

`brakefri-primitives::fields` exposes canonical base-coordinate encodings. `hash` supplies generic Keccak-256, SHA-256, and BLAKE3 suites, canonical role-separated leaves, full-hash binary node compression, and the prefix-2 transcript hash. `mmcs::CanonicalMmcs` validates shapes and sorted unique indices before delegating to upstream binary cap-zero single-matrix MMCS, including direct `PrunedMerklePaths` multiproofs. The tree owns its matrix. Base widths are reusable; the PCS caller must enforce width 1024. Challenge leaves have width one. Ordinary path adapters support small-test references.

`dft::NaturalOrderDft` wraps `Radix2DitParallel`, normalizes order-aware output, and transforms extension coefficients through base-coordinate columns using base roots. `padded_coefficient_blocks` constructs one destination matrix with sequential tiled writes and checked geometry.

`transcript::Transcript<P,S>` binds the fixed context and typed events to upstream `HashChallenger<u8, TranscriptHash<S::Hasher>, 32>`. Field sampling rejects noncanonical integers and samples quadratic coordinates separately. Index sampling consumes fresh bytes per sample and preserves repeated queries. `FieldProfile` is closed to the two supported base/challenge pairings. The M2 controller must enforce event order and check scalar identities before sampling; the primitive supplies framing and shape validation, not a PCS state machine.

`brakefri-core::BrakeParams` validates all supported `log_n` 11 through 30, fixed m=1024, B=2, Q=244, and all three exact integer interactive soundness inequalities. Its fields are private; geometry is exposed through accessors.

`brakefri-runtime::ExecutionContext` owns and initializes a positive-size local Rayon pool. The workspace enables upstream parallelism through `p3-maybe-rayon/parallel`. DFT and tree construction install work in this pool; transcript and multiproof assembly stay sequential. M5 will integrate phase timing and coarse independent-tree authentication scheduling.

### Checks

Passed `cargo test --workspace --locked`: 29 tests, including exact bounds for all 40 supported profile/size combinations (and thus the 22 benchmark combinations), every fixed field root against BigUint, F128 wide arithmetic/conversions, canonical decoding, direct base/extension DFT evaluations, known hash answers and exact role preimages, MMCS base/extension roundtrips for all suites, malformed rows/indices/frontiers, ordinary-path interoperability, full-tree empty frontiers, rejection sampling, and complete event framing replay with upstream for both profiles and all suites.

Passed `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets --locked -- -D warnings`. Inspected Cargo feature propagation and confirmed upstream Rayon support is enabled. Reviewed primitive shape checks, ownership, root ordering, coordinate widths, and the separation of context from future proof payloads. No concrete M1 blockers remain.

### Independent M1 review

Reviewed all new Rust sources, integration tests, manifests, and the locked dependency sources against the M1 assignment and plan. Re-ran formatting, all 29 workspace tests, and Clippy with warnings denied successfully. Confirmed the integration tests are discovered by Cargo and `p3-maybe-rayon/parallel` is enabled. No concrete M1 defects or blockers were found; M1 is ready for the parent to commit. No code fixes or additional tests were needed.

The MMCS adapter enforces role, width, dimensions, and sorted unique nonempty indices; upstream enforces exact frontier consumption. Transcript methods enforce event shapes, while the future PCS controller must enforce sequencing and scalar checks. Future core operations must also bind the runtime `BrakeParams` profile to the selected `FieldProfile` and use the fixed initial width 1024. These remain M2/M3 integration obligations.

## M2: complete (independently reviewed; awaiting parent commit)

`brakefri-core` now exports `BrakeFri<P, S>`, `Commitment`, `ProverData<P, S>`, `Opening<P>`, `BrakeProof<P>`, `Round<K>`, `ScalarOpening<K>`, and structured `PcsError`. Construct a configuration with `BrakeFri::<GoldilocksProfile, _>::new(params, Blake3Suite)` (or either supported profile and any of the three suites). Its methods are `commit(coefficients, execution)`, `prove(&state, z, execution)`, and `verify(&commitment, z, y, &proof, execution)`. The verifier receives the caller's intended commitment and claim separately. `validate_shape` also exposes the preliminary public-geometry bounds for typed proofs.

Commit consumes exactly the declared coefficient vector, retains its original allocation, performs one padded natural-order batched DFT, and transfers the encoding into the initial MMCS tree. Private prover state binds the validated parameters, suite identity, coefficients, tree, and root. It can serve multiple subsequent points. No opening-specific state is retained there.

The opening controller computes base-field block claims and reconstruction by powers of `z^k`, samples all 1024 independent challenge-field row weights, and combines coefficients and the retained base rows sequentially. Both round scalars are observed and checked before sampling gamma. Coefficient folds and word folds use separate destination buffers, with an inverse-root recurrence for domain powers. Production proving performs no DFT. Scalar buffers move into their trees, subsequent rounds borrow them, and the virtual initial word is released after its first fold. All temporary trees remain alive through multiproof assembly and drop synchronously on return.

The proof uses the specified message structure, including every next root and the terminal constant/two values. Verification checks prefix shapes, reconstruction, round identities, terminal equality and the canonical two-leaf root before sampling queries. It retains the 244 ordered replacement-sampled starts, derives sorted unique per-tree sets, authenticates each oracle once through the M1 upstream multiproof adapter, combines each unique initial row once, and checks every logical query/round using the actual signed point. Sorted sets serve as bounded binary-search lookups. The initial oracle has one shared matrix opening; scalar openings hold flat value vectors and one frontier each; the terminal oracle has no multiproof. Verification has no coefficients or full encoding and does not impose an exact-codeword relation on adversarial words.

### M2 checks and review

Passed core tests for zero, constant, sparse, and full-degree polynomials at `log_n=11,12,14`, each at zero and a nonzero point, for both profiles and all three suites. Direct polynomial reference checks cover even/odd identities, zero and extension challenges, word/coefficient folds, and both signs at every position. A separate small reference prover uses direct polynomial evaluations at every folded domain point and matches production messages and openings across all six profile/suite pairs. Its transcript independently samples every row coefficient and replays the ordered messages. Deliberately corrupted, correctly authenticated scalar oracles with valid scalar/terminal checks are rejected by the local folds.

Malformed tests cover prefix counts, row widths/counts/order/values, scalar values/openings, roots, terminal data, incorrect claims/points/configurations/suites, and block/scalar changes that preserve their immediate algebraic identity but change the transcript. A `log_n=18` case exercises nonempty frontier nodes, missing/extra/wrong digests, and matches each initial multiproof row to a verified M1 ordinary-path reference. Small cases exercise fully opened trees with empty frontiers and repeated logical queries. The coefficient allocation is retained across commit.

Reviewed the controller against the supplied plan, including buffer ownership, base/challenge separation, event order, signed indices, and typed indexing bounds. No M2 blockers remain. Codecs and measurement APIs have not been added; no benchmark measurements were produced. Passed `cargo fmt --all -- --check`, `cargo test --workspace --locked` (35 tests), `cargo clippy --workspace --all-targets --locked -- -D warnings`, and `git diff --check`. The earlier core-only test run also passed. Cargo.lock retains portable public dependencies; its only change adds the core crate's three newly used workspace dependencies. Planning documents remain ignored and untracked, and all M2 changes are left uncommitted for parent review.

### Independent M2 review

Reviewed every M2 Rust source and test against HEAD, the full plan, the paper, and the M2 assignment. Checked the reused DFT/transcript/MMCS adapters and current upstream multiproof dispatch/frontier validation. The controller enforces the M1 integration obligations: closed profile matching, width 1024, independent row sampling, scalar checks before challenges, terminal checks before queries, exact derived opening counts, and all signed logical fold checks. Private state and validated shapes justify the remaining direct indexing. No concrete M2 defects were found, so no Rust changes or redundant tests were added.

Independently passed `cargo fmt --all -- --check`, `cargo test --workspace --locked` (35 tests, including all six new M2 tests discovered by Cargo), `cargo clippy --workspace --all-targets --locked -- -D warnings`, and `git diff --check`. Confirmed portable locked dependencies and ignored, untracked planning documents. M2 is ready to commit with no concrete blockers. The review report is in `.git/stages/M2-review-report.md`; later milestone work remains below.

## Remaining milestones

- M3: independently audit, complete, and harden per-oracle sharing and adversarial verification. M2 already supplies the usable upstream multiproof path and all logical fold checks; there is no production individual-path or full-oracle fallback.
- M4: bounded protocol-only proof codecs and actual commitment-plus-evaluation byte accounting. F128 coordinate Serde in M1 is not a protocol proof codec.
- M5: benchmark runtime integration, hash/field CLI dispatch, configuration parsing, preflight/sweep, and nine-column CSV output. The benchmark crate is deliberately not created as an empty placeholder. `configs/brakefri.toml` records planned settings but has no parser yet.
- M6: requested successful measurements. No benchmark sweep or measurements have been produced.

The supplied planning documents remain ignored and untracked. Each milestone is implemented in a fresh Pi session, independently reviewed, checked, and committed by the parent orchestrator.
