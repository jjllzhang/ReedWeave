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

## M2: complete (independently reviewed and committed by parent)

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

## M3: complete (independently reviewed; awaiting parent commit)

Audited the M2 typed protocol and M1 MMCS adapter against plan Sections 8 and 9 and the paper's Section 3 query experiment. The existing protocol already assembled the required multiproofs. M3 hardens that path and adds focused acceptance evidence.

### Architecture and audit

`CanonicalMmcs::verify_multi_batch` now accepts rows implementing `AsRef<[F]>`. Initial matrix rows remain borrowed; scalar authentication passes width-one array views directly over the flat `ScalarOpening::values` buffer. This removes the previous singleton field allocations and field copies in the core verifier. Only the small nested slice containers required by the upstream single-matrix API are allocated. The opening adapter additionally checks upstream's outer query count before unwrapping each single-matrix row and validating its width.

Verified that the ordered 244 starts are sampled with replacement after terminal checks and preserved for the nested query/round loop. Each local set is sorted and deduplicated by index within its own tree, includes both signs, and supplies a bounded binary-search lookup. No indices are proof fields. The initial tree authenticates base rows of width 1024; initial combinations are computed once per unique authenticated row. Scalar proofs contain flat values. There is no committed virtual pi0; every later root occurs once in the rounds. The two terminal values reconstruct their root and have no additional multiproof. Typed prefix, row-width, geometry bounds, and exact derived value counts precede shared authentication. All Q * ell local equalities retain the actual signed point and repeated logical queries.

Inspected upstream `Mmcs` dispatch, `open_batch_pruned`, `walk_pruned_frontier`, and `pruning::restore_paths` at the locked compatible revision. Each queried tree receives exactly one upstream `open_multi_batch` during proving and one `verify_multi_batch` during verification. Upstream checks the exact frontier count, including missing and unused nodes, and shares internal-node authentication. Its temporary path buffers remain upstream implementation details. BrakeFRI neither traverses a second frontier nor expands proofs for verification; ordinary paths are used only as test references. No protocol acceptance defect was found in this audit.

### M3 acceptance checks

Added exhaustive tests of all 255 nonempty subsets of an eight-leaf scalar tree for both profiles and all three hash suites (1,530 subset cases). Borrowed flat scalar openings match independently verified ordinary paths, including the exact four-digest frontier order for indices 1, 2, 5. Each subset exercises wrong values, changed roots, missing/extra rows, wrong widths, swapped rows where applicable, extra boundary nodes, and missing/wrong nodes and index substitution where applicable. Full coverage accepts an empty frontier and rejects extra nodes. Equal-valued leaves remain distinct authenticated positions.

The reference prover now derives its query sets independently by domain enumeration and signed membership. Its comparisons cover both signs and repeated queries across all six profile/suite combinations. Expanded correctly authenticated malicious-oracle fixtures to reject an invalid fold at each intermediate round. A separate direct-evaluation degree-k monomial fixture passes scalar, terminal, authentication, and all earlier fold checks but fails precisely the final local equality, for both profiles. The existing nonempty initial-frontier test now also rejects a valid multiproof for a substituted canonical set at the same root. Typed malformed cases additionally cover scalar reordering/counts, oversized initial widths/counts, extra empty-frontier nodes, and a redundant scalar opening.

Passed `cargo test -p brakefri-core -p brakefri-primitives --locked` during implementation, then final `cargo fmt --all -- --check`, `cargo test --workspace --locked` (37 tests), `cargo clippy --workspace --all-targets --locked -- -D warnings`, and `git diff --check`. Self-reviewed all changed code and new tests against Sections 8 and 9. Cargo.lock and portable dependency sources are retained unchanged. The three planning documents remain ignored and untracked. No M3 blockers remain; changes are uncommitted for the parent. No benchmarks or proof-byte measurements were produced.

### Independent M3 review

Reviewed all M3 changes against HEAD, including the newly added Cargo integration test, the full typed controller, canonical MMCS/hash adapters, transcript controller integration, and upstream multiproof dispatch and frontier consumption at the locked revision. Confirmed borrowed scalar array views preserve canonical hashing without copying field values, exact shape checks protect verifier indexing, and all 244 ordered queries retain every signed fold check. The exhaustive subset test and authenticated intermediate/final bad-fold fixtures run under workspace tests. No concrete defects were found; no Rust fixes or additional tests were necessary.

Independently passed `cargo fmt --all -- --check`, `cargo test --workspace --locked` (37 tests, none ignored), `cargo clippy --workspace --all-targets --locked -- -D warnings`, and `git diff --check`. Cargo.lock and portable dependency sources are unchanged; planning documents and session files remain untracked. M3 is ready to commit with no concrete blockers. The report is `.git/stages/M3-review-report.md`.

## M4: complete (independently reviewed; awaiting parent commit)

`brakefri_core::codec` now exposes `encode_commitment`, `decode_commitment`, `encode_eval_proof::<P>`, and `decode_eval_proof::<P>`, with structured encoding/decoding errors. Commitment bytes are exactly the raw 32-byte root. Local Postcard/Serde wire structures borrow the existing typed proof's field rows and frontier vectors; only small round/opening descriptor vectors are projected. The evaluation encoding contains exactly the specified prover messages, with fixed canonical coordinate arrays, challenge tuples, digest arrays, and real vector framing. It contains no statement, context, header, indices, challenges, or initial root. Exact ordering and accounting are documented in [wire-format.md](wire-format.md).

Every incoming vector uses a parameter-aware `DeserializeSeed`/sequence visitor. Announced lengths are checked before reservation or element visitation; missing Postcard size hints are rejected as well. Prefix and row widths are exact, opened counts are bounded by min(2Q, N_j), and frontier counts are bounded by the checked product of actual bounded opened count and tree depth. Canonical field decoding rejects representatives at least the modulus on the stack. The decoder rejects truncation, trailing bytes, and overlong Postcard length framing (via a bounded canonical re-encoding comparison). That comparison's allocation and serialization belong to verification time. No production unbounded proof/vector deserialization is used.

Typed verification retains its preliminary shape checks through a shared checked geometry/shape validator. Its existing transcript replay derives exact S_j counts, then upstream shared MMCS authentication enforces exact frontier consumption and order. Neither the codec nor measurement helper duplicates the algebraic protocol or Merkle traversal.

`BrakeFri::verify_encoded(expected_commitment, (z, y), commit_bytes, eval_bytes, execution)` decodes the two actual buffers, matches the received root to the expected commitment, invokes typed verification, and returns their checked total byte length only after acceptance. This reusable helper avoids a concatenation copy and is intended to run inside M5's verification timer. Commitment serialization belongs to commit time and evaluation serialization to prove time. No benchmark timings or sweep were produced in M4.

### M4 checks and self-review

Added five tests covering actual byte verification for all six profile/suite pairs, both profiles with nonempty initial/scalar frontiers at log_n=18, and ell=1 empty scalar vectors. Independent ordinary Serde receivers interoperate with both wire profiles. Tests compare the verified buffer total to concatenation length and to the structural payload plus every actual Postcard vector header. They cover expected-root and intended-claim matching, fixed widths at zero/one/modulus-minus-one, noncanonical coordinates in both extension positions, all vector length locations, truncated fields/digests/framing, trailing bytes, overlong varints, profile mismatch, malformed typed rows, missing nodes, and surplus nodes accepted by preliminary bounds but rejected by exact authentication.

Largest-parameter tests exercise every layer's allocation limits, including usize::MAX lengths and oversized lengths with sufficient remaining input to expose Postcard's actual count. The element factory must never be visited on these failures. Reviewed current Postcard sequence size hints and tuple decoding, compatible upstream frontier representation, checked shape arithmetic, bounded nested allocations, and the single existing typed verification path against plan Sections 3.3, 7, 9, 11, and 12. No concrete M4 blockers remain.

Passed `cargo test -p brakefri-core --locked codec -- --nocapture`, `cargo fmt --all -- --check`, `cargo test --workspace --locked` (42 tests), `cargo clippy --workspace --all-targets --locked -- -D warnings`, and `git diff --check`. After refining the sufficient-input length-bound test during review, reran that targeted locked test, formatting, and workspace Clippy successfully. Cargo.lock retains portable dependencies; Postcard 1.1.3 and Serde were already resolved and are now direct core dependencies. Planning documents remain ignored and untracked. All M4 changes are left uncommitted for parent review.

### Independent M4 review

Reviewed every M4 change against HEAD, the full plan and assignment, the paper's protocol and communication rules, the typed verifier, canonical field/MMCS adapters, and the locked Postcard and upstream frontier APIs. Confirmed that every untrusted vector length is checked before reservation or element visitation, nested row allocations are bounded, closed field profiles justify fixed coordinate layouts, and exact transcript-derived counts and frontier consumption remain enforced by typed verification. The re-encoding comparison rejects noncanonical framing and is explicitly charged to decoding. The byte helper verifies the expected commitment and intended claim before returning actual commit-plus-evaluation buffer length.

Independently passed `cargo fmt --all -- --check`, `cargo test --workspace --locked` (42 tests, none ignored, including all five M4 tests), `cargo clippy --workspace --all-targets --locked -- -D warnings`, and `git diff --check`. Confirmed public locked dependencies and ignored, untracked planning documents. No concrete defects were found; no Rust fixes or redundant tests were added. M4 is ready to commit with no concrete blockers. The report is `.git/stages/M4-review-report.md`. No benchmark timings or later-stage work were produced.

## Remaining milestones
- M5: benchmark runtime integration, hash/field CLI dispatch, configuration parsing, preflight/sweep, and nine-column CSV output. The benchmark crate is deliberately not created as an empty placeholder. `configs/brakefri.toml` records planned settings but has no parser yet.
- M6: requested successful measurements. No benchmark sweep or measurements have been produced.

The supplied planning documents remain ignored and untracked. Each milestone is implemented in a fresh Pi session, independently reviewed, checked, and committed by the parent orchestrator.
