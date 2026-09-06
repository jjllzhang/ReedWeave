# BrakeFRI protocol bytes

`brakefri_core::codec` provides `encode_commitment`, `decode_commitment`, `encode_eval_proof::<P>`, and `decode_eval_proof::<P>`. The evaluation codecs take validated `&BrakeParams`; its profile must match `P`. The typed prover and verifier remain the single protocol implementation.

## Exact ordering

The commitment is exactly its raw `[u8; 32]` root. Commitment decoding requires exactly 32 bytes.

The evaluation proof is the following Postcard/Serde structure, serialized in declaration order. Structs, tuples, and fixed arrays have no headers or length prefixes. Every `Vec` has Postcard's unsigned base-128 varint element count, including empty vectors. Every digest is a fixed `[u8; 32]`.

```text
Vec<Base> block_values                         # exactly m
Vec<Round> rounds                              # exactly ell
    Challenge even_value
    Challenge odd_value
    [u8; 32] next_oracle_root
Challenge terminal_constant
[Challenge; 2] terminal_values                 # natural order
InitialOpening initial_opening
    Vec<Vec<Base>> rows                        # sorted S_0 order; each row has m values
    Vec<[u8; 32]> boundary_digests
Vec<ScalarOpening> scalar_openings             # ell - 1, layers 1 through ell - 1
    Vec<Challenge> values                      # sorted S_j order
    Vec<[u8; 32]> boundary_digests
```

Goldilocks base coordinates are `[u8; 8]`, and F128 base coordinates are `[u8; 16]`, each containing the canonical little-endian representative. A Goldilocks challenge is the fixed tuple `([u8; 8], [u8; 8])`, ordered constant then coefficient of u. An F128 challenge is the one-coordinate tuple `([u8; 16],)`. Both challenges occupy exactly 16 bytes. A one-coordinate base tuple and its fixed coordinate array have identical Postcard bytes. The local coordinate adapter always serializes these fixed arrays; it never uses integer compression for field elements.

Each authentication payload is solely the upstream `PrunedMerklePaths::sibling_hashes` vector. Its order is levels from leaves to root, ascending parent within a level, then ascending missing child. It contains no indices, depths, flags, or separate paths. Fully opened trees have an empty digest vector. The terminal tree is read in full and has no additional opening.

There is no evaluation envelope. The initial root, z, y, profile, parameters, suite, protocol label, transcript events, challenges, and query indices are absent from the evaluation proof. Each later root occurs once in its round. Suite and profile selection come from the caller's configuration. The public claim returned by `prove` must be supplied separately to verification as the intended statement.

## Bounded decoding and verification

All variable-length data pass through custom `DeserializeSeed` and sequence visitors. Postcard exposes the announced length through `SeqAccess::size_hint`, or returns no hint when there are fewer remaining bytes than elements. The visitor rejects a missing hint and checks the length before `try_reserve_exact` or element decoding. Unbounded `Vec::deserialize` and unbounded proof `from_bytes` are not used in production.

Prefix vectors must have exactly m or ell entries. Scalar opening count must equal ell - 1. At layer j, let `depth = log2(N_j)` and `u` be the transmitted opened-value count. The decoder requires `1 <= u <= min(2Q, N_j)`, exact row width m for the initial matrix, and at most `u * depth` boundary digests. This is a conservative bound from independent binary paths, not a claim about the exact frontier length. Geometry and boundary multiplication use checked arithmetic. Allocation depends only on validated geometry and bounded counts; it never scales with n coefficients or all N_j tree leaves. Nested rows have independently bounded lengths. Failures of these vector reservations become decode errors.

Coordinates are decoded on the stack and rejected when any representative is at least its base modulus. Truncated tuples, invalid length varints, and trailing bytes are rejected. After bounded parsing, the decoder compares a canonical re-encoding with the input, rejecting overlong Postcard length representations too. This bounded extra serialization pass and temporary byte buffer are part of decoding and must be charged to verification time.

Encoding and typed verification share the preliminary shape validator. Typed callers still receive shape checks even when they bypass byte decoding. After scalar/terminal checks and transcript replay, the verifier requires exact derived `|S_j|` counts. Upstream MMCS checks exact `h_j` consumption and frontier authentication for those same derived indices, rejecting missing and surplus digests. Canonical parsing alone does not establish cryptographic validity.

## Actual byte accounting and timing

`BrakeFri::verify_encoded(expected_commitment, (z, y), commit_bytes, eval_bytes, execution)` decodes both actual buffers, compares the received commitment with the caller's expected root, invokes typed verification, and returns the checked sum of buffer lengths only after success. It does not generate a second proof or implement a second transcript.

```rust,ignore
// Parameters, the local pool, coefficients, and the point are prepared as public
// setup/input selection. Place the following operations in their phase timers.
let (commitment, state) = pcs.commit(coefficients, &execution)?;
let commit_bytes = encode_commitment(&commitment);  // included in commit_time

let opening = pcs.prove(&state, z, &execution)?;
let eval_bytes = encode_eval_proof(pcs.params(), &opening.proof)?; // prove_time

// The caller supplies the intended claim. Here it is the generated trial's claim.
let proof_size = pcs.verify_encoded(
    &commitment, (z, opening.y), &commit_bytes, &eval_bytes, &execution,
)?; // decoding, matching, canonicality, and all verification included in verify_time
```

`proof_size = 32 + eval_bytes.len()` counts one commitment and one evaluation, including every actual vector header. Equivalently, concatenate `commit_bytes || eval_bytes`: the first 32 bytes are the commitment and the remainder is the evaluation proof. The helper avoids that extra concatenation copy. No statement/context bytes or external compression are added. Applications transporting an initially unknown y have separate statement communication, outside this metric.

Tests verify generated byte buffers for both profiles and all three suites, and compare the actual total with the structural payload formula plus every Postcard vector header. Independent ordinary Serde wire structures interoperate with both profiles. These are correctness and accounting checks, not benchmark timing results. M5 supplies the benchmark timers and nine-column output.
