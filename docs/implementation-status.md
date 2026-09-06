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

## Remaining milestones

- M2: coefficient-input commitment and Section 3 two-scalar algebra/proof/verification controller.
- M3: protocol per-oracle query sets, multiproof assembly/authentication, and all logical fold checks. Primitive multiproof support is already in M1.
- M4: bounded protocol-only proof codecs and actual commitment-plus-evaluation byte accounting. F128 coordinate Serde in M1 is not a protocol proof codec.
- M5: benchmark runtime integration, hash/field CLI dispatch, configuration parsing, preflight/sweep, and nine-column CSV output. The benchmark crate is deliberately not created as an empty placeholder. `configs/brakefri.toml` records planned settings but has no parser yet.
- M6: requested successful measurements. No benchmark sweep or measurements have been produced.

The supplied planning documents remain ignored and untracked. Each milestone is implemented in a fresh Pi session, independently reviewed, checked, and committed by the parent orchestrator.
