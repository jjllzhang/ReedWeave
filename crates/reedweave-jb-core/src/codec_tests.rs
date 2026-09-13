use super::*;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use reedweave_primitives::{
    fields::{Goldilocks, GoldilocksCubic, GoldilocksQuadratic, GoldilocksQuintic},
    transcript::{
        GoldilocksBaseProfile, GoldilocksCubicProfile, GoldilocksProfile, GoldilocksQuinticProfile,
    },
};

// Independent ordinary Serde receiver describes exactly the protocol wire shape.
// Its unbounded Deserialize is only a test interoperability reference.
#[derive(Debug, Serialize, Deserialize)]
struct ReferenceProof<B, K> {
    context_id: Digest,
    blocks: Vec<B>,
    rounds: Vec<(K, K, K, K)>,
    oracle_roots: Vec<[u8; 32]>,
    terminal: Vec<K>,
    initial: (Vec<Vec<B>>, Vec<[u8; 32]>),
    scalars: Vec<(Vec<K>, Vec<[u8; 32]>)>,
}

type GoldCoordinate = ([u8; 8], [u8; 8]);
type GoldWire = ReferenceProof<[u8; 8], GoldCoordinate>;

#[derive(Debug, Serialize, Deserialize)]
struct ReferenceCommitment<K> {
    context_id: Digest,
    root: Digest,
    zeta: K,
    deep_values: Vec<K>,
}

fn varint_size(n: usize) -> usize {
    postcard::to_allocvec(&n).unwrap().len()
}

// Structural formula plus every real vector header, independent of the encoder.
fn structural_size<P: FieldProfile>(proof: &JbProof<P>) -> usize {
    let ell = proof.rounds.len();
    let u0 = proof.initial_opening.rows.len();
    let h0 = proof.initial_opening.proof.sibling_hashes.len();
    let scalar_values: usize = proof.scalar_openings.iter().map(|o| o.values.len()).sum();
    let nodes: usize = h0
        + proof
            .scalar_openings
            .iter()
            .map(|o| o.proof.sibling_hashes.len())
            .sum::<usize>();
    let m = proof.block_values.len();
    let payload = 32
        + P::Base::BYTE_WIDTH * (m + m * u0)
        + P::Challenge::BYTE_WIDTH * (4 * ell + proof.terminal_coefficients.len() + scalar_values)
        + 32 * (ell - 1 + nodes);
    let framing = varint_size(m)
        + varint_size(ell)
        + varint_size(ell - 1)
        + varint_size(proof.terminal_coefficients.len())
        + varint_size(u0)
        + u0 * varint_size(m)
        + varint_size(h0)
        + varint_size(ell - 1)
        + proof
            .scalar_openings
            .iter()
            .map(|o| varint_size(o.values.len()) + varint_size(o.proof.sibling_hashes.len()))
            .sum::<usize>();
    payload + framing
}

fn fixture<P: FieldProfile>(
    log_d: usize,
) -> (
    ReedWeaveJb<P>,
    ExecutionContext,
    JbCommitment<P>,
    P::Base,
    crate::Opening<P>,
) {
    let params = test_params::<P>(log_d);
    let execution = ExecutionContext::new(1).unwrap();
    let pcs = ReedWeaveJb::<P>::new(params.clone()).unwrap();
    let coefficients = (0..params.d())
        .map(|i| P::Base::from_usize(i * 17 + 3))
        .collect();
    let (commitment, state) = pcs.commit(coefficients, &execution).unwrap();
    let z = P::Base::from_u8(9);
    let opening = pcs.prove(&state, z, &execution).unwrap();
    (pcs, execution, commitment, z, opening)
}

fn roundtrip<P: FieldProfile>(log_d: usize) {
    let (pcs, execution, commitment, z, opening) = fixture::<P>(log_d);
    let commit_bytes = encode_commitment(pcs.params(), &commitment).unwrap();
    assert_eq!(&commit_bytes[..32], &commitment.context_id);
    assert_eq!(&commit_bytes[32..64], &commitment.root);
    assert_eq!(
        decode_commitment::<P>(pcs.params(), &commit_bytes).unwrap(),
        commitment
    );
    assert_eq!(
        commit_bytes.len(),
        64 + (pcs.params().m() + 1) * P::Challenge::BYTE_WIDTH + varint_size(pcs.params().m())
    );
    let bytes = encode_eval_proof(pcs.params(), &opening.proof).unwrap();
    let decoded = decode_eval_proof::<P>(pcs.params(), &bytes).unwrap();
    pcs.verify(&commitment, z, opening.y, &decoded, &execution)
        .unwrap();
    assert_eq!(encode_eval_proof(pcs.params(), &decoded).unwrap(), bytes);
    let total = pcs
        .verify_encoded(
            &commitment,
            (z, opening.y),
            &commit_bytes,
            &bytes,
            &execution,
        )
        .unwrap();
    let transport = [commit_bytes.as_slice(), &bytes].concat();
    assert_eq!(total, transport.len());
    assert_eq!(total, commit_bytes.len() + structural_size(&opening.proof));
    assert_eq!(
        pcs.verify_encoded(
            &commitment,
            (z, opening.y),
            &transport[..commit_bytes.len()],
            &transport[commit_bytes.len()..],
            &execution
        )
        .unwrap(),
        total
    );
    let mut wrong_root = commit_bytes.clone();
    wrong_root[32] ^= 1;
    assert!(matches!(
        pcs.verify_encoded(&commitment, (z, opening.y), &wrong_root, &bytes, &execution),
        Err(VerifyEncodedError::CommitmentMismatch)
    ));
    assert!(
        pcs.verify_encoded(
            &commitment,
            (z, opening.y + P::Base::ONE),
            &commit_bytes,
            &bytes,
            &execution
        )
        .is_err()
    );
    if log_d == 8 {
        assert!(!decoded.initial_opening.proof.sibling_hashes.is_empty());
        assert!(
            decoded
                .scalar_openings
                .iter()
                .any(|o| !o.proof.sibling_hashes.is_empty())
        );
        let mut missing = decoded.clone();
        missing.initial_opening.proof.sibling_hashes.pop();
        let missing_bytes = encode_eval_proof(pcs.params(), &missing).unwrap();
        assert!(
            pcs.verify_encoded(
                &commitment,
                (z, opening.y),
                &commit_bytes,
                &missing_bytes,
                &execution
            )
            .is_err()
        );
    }
}

#[test]
fn actual_bytes_verify_for_every_field_and_size() {
    roundtrip::<GoldilocksProfile>(5);
    roundtrip::<GoldilocksCubicProfile>(5);
    roundtrip::<GoldilocksQuinticProfile>(5);
    roundtrip::<GoldilocksBaseProfile>(5);
    // Nonempty initial and scalar frontiers.
    roundtrip::<GoldilocksProfile>(8);
    roundtrip::<GoldilocksBaseProfile>(8);
    // t=1 has no scalar openings, but still has a vector length of zero.
    roundtrip::<GoldilocksProfile>(4);
    roundtrip::<GoldilocksBaseProfile>(4);
    roundtrip::<GoldilocksCubicProfile>(4);
    roundtrip::<GoldilocksQuinticProfile>(4);
}

#[test]
fn serde_interoperability_and_protocol_only_order() {
    let (pcs, execution, commitment, z, opening) = fixture::<GoldilocksProfile>(5);
    let commit_bytes = encode_commitment(pcs.params(), &commitment).unwrap();
    let wire_commit: ReferenceCommitment<GoldCoordinate> =
        postcard::from_bytes(&commit_bytes).unwrap();
    assert_eq!(wire_commit.context_id, commitment.context_id);
    assert_eq!(wire_commit.root, commitment.root);
    assert_eq!(wire_commit.deep_values.len(), pcs.params().m());
    for (wire_value, value) in std::iter::once((&wire_commit.zeta, &commitment.zeta))
        .chain(wire_commit.deep_values.iter().zip(&commitment.deep_values))
    {
        let coords: &[Goldilocks] = value.as_basis_coefficients_slice();
        assert_eq!(
            *wire_value,
            (
                coords[0].to_canonical_bytes(),
                coords[1].to_canonical_bytes()
            )
        );
    }
    assert_eq!(postcard::to_allocvec(&wire_commit).unwrap(), commit_bytes);
    let bytes = encode_eval_proof(pcs.params(), &opening.proof).unwrap();
    assert_eq!(&bytes[..32], &opening.proof.context_id);
    let wire: GoldWire = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(
        wire.blocks,
        opening
            .proof
            .block_values
            .iter()
            .map(CanonicalField::to_canonical_bytes)
            .collect::<Vec<_>>()
    );
    for (wire_round, round) in wire.rounds.iter().zip(&opening.proof.rounds) {
        for (wire_value, value) in [
            (wire_round.0, round.even_value),
            (wire_round.1, round.odd_value),
            (wire_round.2, round.deep_even_value),
            (wire_round.3, round.deep_odd_value),
        ] {
            let coords: &[Goldilocks] = value.as_basis_coefficients_slice();
            assert_eq!(
                wire_value,
                (
                    coords[0].to_canonical_bytes(),
                    coords[1].to_canonical_bytes()
                )
            );
        }
    }
    assert_eq!(wire.oracle_roots, opening.proof.oracle_roots);
    assert_eq!(
        wire.initial.0.len(),
        opening.proof.initial_opening.rows.len()
    );
    let received = postcard::to_allocvec(&wire).unwrap();
    assert_eq!(received, bytes);
    pcs.verify_encoded(
        &commitment,
        (z, opening.y),
        &encode_commitment(pcs.params(), &commitment).unwrap(),
        &received,
        &execution,
    )
    .unwrap();
}

fn coordinate_width<F: CanonicalField>(values: &[F]) {
    for &value in values {
        let bytes = postcard::to_allocvec(&Coordinate(value)).unwrap();
        assert_eq!(bytes.len(), F::BYTE_WIDTH);
        assert_eq!(bytes, value.to_canonical_bytes().as_ref());
        let decoded: Coordinate<F> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.0, value);
        for end in 0..F::BYTE_WIDTH {
            assert!(postcard::from_bytes::<Coordinate<F>>(&bytes[..end]).is_err());
        }
        for position in (0..F::BYTE_WIDTH).step_by(8) {
            for invalid in [GoldilocksProfile::PROFILE.modulus() as u64, u64::MAX] {
                let mut bad = bytes.clone();
                bad[position..position + 8].copy_from_slice(&invalid.to_le_bytes());
                assert!(postcard::from_bytes::<Coordinate<F>>(&bad).is_err());
            }
        }
    }
}
#[test]
fn canonical_fixed_coordinate_arrays() {
    coordinate_width(&[Goldilocks::ZERO, Goldilocks::ONE, -Goldilocks::ONE]);
    coordinate_width(&[
        GoldilocksCubic::ZERO,
        GoldilocksCubic::ONE,
        GoldilocksCubic::from_basis_coefficients_fn(|i| -Goldilocks::from_usize(i + 1)),
    ]);
    coordinate_width(&[
        GoldilocksQuintic::ZERO,
        GoldilocksQuintic::ONE,
        GoldilocksQuintic::from_basis_coefficients_fn(|i| -Goldilocks::from_usize(i + 1)),
    ]);
    coordinate_width(&[
        GoldilocksQuadratic::ZERO,
        GoldilocksQuadratic::ONE,
        GoldilocksQuadratic::from_basis_coefficients_fn(|i| {
            if i == 0 {
                -Goldilocks::ONE
            } else {
                Goldilocks::from_u8(128)
            }
        }),
    ]);
    for value in [GoldilocksProfile::PROFILE.modulus(), u64::MAX as u128] {
        let bytes = (value as u64).to_le_bytes();
        assert!(postcard::from_bytes::<Coordinate<Goldilocks>>(&bytes).is_err());
        for position in [0, 8] {
            let mut challenge = [0; 16];
            challenge[position..position + 8].copy_from_slice(&bytes);
            assert!(postcard::from_bytes::<Coordinate<GoldilocksQuadratic>>(&challenge).is_err());
        }
    }
}

// Byte offsets from the independently specified field widths and vector framing.
struct Layout {
    at: usize,
    vectors: Vec<(usize, usize, usize)>,
    coordinates: Vec<usize>,
}
impl Layout {
    fn vector(&mut self, count: usize, min: usize, max: usize) {
        self.vectors.push((self.at, min, max));
        self.at += varint_size(count);
    }
    fn fields(&mut self, count: usize, width: usize) {
        // Cover every canonical coordinate of each message, including DEEP rounds.
        for i in 0..count {
            self.coordinates.push(self.at + i * width);
        }
        self.at += count * width;
    }
}
fn layout<P: FieldProfile>(params: &JbParams, proof: &JbProof<P>) -> Layout {
    let mut l = Layout {
        at: 32,
        vectors: Vec::new(),
        coordinates: Vec::new(),
    };
    let m = params.m();
    l.vector(m, m, m);
    l.fields(m, P::Base::COORDINATE_BYTES);
    l.vector(params.rounds(), params.rounds(), params.rounds());
    for _ in &proof.rounds {
        l.fields(
            4 * P::Challenge::COORDINATE_COUNT,
            P::Base::COORDINATE_BYTES,
        );
    }
    l.vector(
        params.rounds() - 1,
        params.rounds() - 1,
        params.rounds() - 1,
    );
    l.at += 32 * (params.rounds() - 1);
    l.vector(
        params.terminal_coefficient_count(),
        params.terminal_coefficient_count(),
        params.terminal_coefficient_count(),
    );
    l.fields(
        params.terminal_coefficient_count() * P::Challenge::COORDINATE_COUNT,
        P::Base::COORDINATE_BYTES,
    );
    let (max, depth) = opening_bounds(params, 0).unwrap();
    l.vector(proof.initial_opening.rows.len(), 1, max);
    for row in &proof.initial_opening.rows {
        l.vector(row.len(), m, m);
        l.fields(row.len(), P::Base::COORDINATE_BYTES);
    }
    l.vector(
        proof.initial_opening.proof.sibling_hashes.len(),
        0,
        proof.initial_opening.rows.len() * depth,
    );
    l.at += proof.initial_opening.proof.sibling_hashes.len() * 32;
    l.vector(
        proof.scalar_openings.len(),
        params.rounds() - 1,
        params.rounds() - 1,
    );
    for (j, o) in proof.scalar_openings.iter().enumerate() {
        let (max, depth) = opening_bounds(params, j + 1).unwrap();
        l.vector(o.values.len(), 1, max);
        l.fields(
            o.values.len() * P::Challenge::COORDINATE_COUNT,
            P::Base::COORDINATE_BYTES,
        );
        l.vector(o.proof.sibling_hashes.len(), 0, o.values.len() * depth);
        l.at += o.proof.sibling_hashes.len() * 32;
    }
    l
}

fn malformed<P: FieldProfile>() {
    let (pcs, execution, commitment, z, opening) = fixture::<P>(5);
    let bytes = encode_eval_proof(pcs.params(), &opening.proof).unwrap();
    let layout = layout(pcs.params(), &opening.proof);
    assert_eq!(layout.at, bytes.len());
    for &(offset, min, max) in &layout.vectors {
        let lengths = [Some(max + 1), Some(usize::MAX), min.checked_sub(1)];
        for len in lengths.into_iter().flatten() {
            let mut bad = bytes[..offset].to_vec();
            bad.extend(postcard::to_allocvec(&len).unwrap());
            // There are deliberately no elements. Rejection must happen on the
            // count, before allocation/element decoding, not via EOF afterward.
            assert!(matches!(
                decode_eval_proof::<P>(pcs.params(), &bad),
                Err(DecodeError::Postcard(postcard::Error::SerdeDeCustom))
            ));
        }
        // Reject overlong and overflowing framing at every nested vector header.
        let last = offset + bytes[offset..].iter().position(|b| b & 0x80 == 0).unwrap();
        let mut overlong = bytes[..=last].to_vec();
        overlong[last] |= 0x80;
        overlong.push(0);
        overlong.extend_from_slice(&bytes[last + 1..]);
        assert!(matches!(
            decode_eval_proof::<P>(pcs.params(), &overlong),
            Err(DecodeError::NonCanonicalFraming)
        ));
        let mut overflow = bytes[..offset].to_vec();
        overflow.extend([0xff; 20]);
        assert!(decode_eval_proof::<P>(pcs.params(), &overflow).is_err());
        for end in [offset.saturating_sub(1), offset, offset + 1] {
            if end < bytes.len() {
                assert!(decode_eval_proof::<P>(pcs.params(), &bytes[..end]).is_err());
            }
        }
    }
    let width = P::Base::COORDINATE_BYTES;
    // Small fixtures permit checking every coordinate of every protocol field.
    let offsets = layout.coordinates.iter().copied();
    for offset in offsets {
        let mut bad = bytes.clone();
        bad[offset..offset + width].copy_from_slice(&P::PROFILE.modulus().to_le_bytes()[..width]);
        assert!(decode_eval_proof::<P>(pcs.params(), &bad).is_err());
        assert!(decode_eval_proof::<P>(pcs.params(), &bytes[..offset + width - 1]).is_err());
    }
    for end in 0..40 {
        assert!(decode_eval_proof::<P>(pcs.params(), &bytes[..end]).is_err());
    }
    assert!(decode_eval_proof::<P>(pcs.params(), &bytes[..bytes.len() - 1]).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        decode_eval_proof::<P>(pcs.params(), &trailing),
        Err(DecodeError::TrailingBytes)
    ));
    for layer in 0..pcs.params().rounds() {
        let mut extra = opening.proof.clone();
        if layer == 0 {
            extra.initial_opening.proof.sibling_hashes.push([0; 32]);
        } else {
            extra.scalar_openings[layer - 1]
                .proof
                .sibling_hashes
                .push([0; 32]);
        }
        // A conservative decoder permits this count, while exact h_j checking
        // after transcript replay must reject the unused frontier node.
        let bad = encode_eval_proof(pcs.params(), &extra).unwrap();
        assert!(decode_eval_proof::<P>(pcs.params(), &bad).is_ok());
        assert!(
            pcs.verify(&commitment, z, opening.y, &extra, &execution)
                .is_err()
        );
        assert!(
            pcs.verify_encoded(
                &commitment,
                (z, opening.y),
                &encode_commitment(pcs.params(), &commitment).unwrap(),
                &bad,
                &execution
            )
            .is_err()
        );
    }
    let mut typed = opening.proof.clone();
    typed.initial_opening.rows[0].clear();
    assert!(encode_eval_proof(pcs.params(), &typed).is_err());
    assert!(
        pcs.verify(&commitment, z, opening.y, &typed, &execution)
            .is_err()
    );
    let mut pp = public_params::<P>(5);
    pp.extension_degree = if pp.extension_degree == 1 { 2 } else { 1 };
    let other = JbParams::new(pp).unwrap();
    assert!(encode_eval_proof(&other, &opening.proof).is_err());
    assert!(decode_eval_proof::<P>(&other, &bytes).is_err());
}

#[test]
fn malformed_bytes_and_typed_frontiers() {
    malformed::<GoldilocksProfile>();
    malformed::<GoldilocksBaseProfile>();
    malformed::<GoldilocksCubicProfile>();
    malformed::<GoldilocksQuinticProfile>();
}

fn authenticated_counts<P: FieldProfile>() {
    let (pcs, execution, commitment, z, opening) = fixture::<P>(8);
    let commit_bytes = encode_commitment(pcs.params(), &commitment).unwrap();
    for layer in 0..pcs.params().rounds() {
        for extra in [false, true] {
            let mut proof = opening.proof.clone();
            if layer == 0 {
                if extra {
                    proof
                        .initial_opening
                        .rows
                        .push(proof.initial_opening.rows[0].clone());
                } else {
                    proof.initial_opening.rows.pop();
                }
            } else {
                let values = &mut proof.scalar_openings[layer - 1].values;
                if extra {
                    values.push(values[0]);
                } else {
                    values.pop();
                }
            }
            assert!(
                pcs.verify(&commitment, z, opening.y, &proof, &execution)
                    .is_err()
            );
            // Shapes inside conservative bounds decode, but their exact queried
            // leaf counts must fail after transcript replay. Over-bound extras
            // are rejected even earlier by encoding/decoding shape checks.
            if let Ok(bytes) = encode_eval_proof(pcs.params(), &proof) {
                assert!(decode_eval_proof::<P>(pcs.params(), &bytes).is_ok());
                assert!(
                    pcs.verify_encoded(
                        &commitment,
                        (z, opening.y),
                        &commit_bytes,
                        &bytes,
                        &execution
                    )
                    .is_err()
                );
            }
        }
    }
}

#[test]
fn transcript_derived_leaf_counts_reject_missing_and_extra_values() {
    authenticated_counts::<GoldilocksBaseProfile>();
    authenticated_counts::<GoldilocksProfile>();
    authenticated_counts::<GoldilocksCubicProfile>();
    authenticated_counts::<GoldilocksQuinticProfile>();
}

#[test]
fn length_bounds_precede_element_visits_at_largest_parameters() {
    for degree in [1, 2, 3, 5] {
        let mut pp = public_params::<GoldilocksProfile>(5);
        pp.extension_degree = degree;
        pp.log_d = 31;
        let params = JbParams::new(pp).unwrap();
        for j in 0..params.rounds() {
            let (values, depth) = opening_bounds(&params, j).unwrap();
            for max in [
                values,
                boundary_bound(values, depth).unwrap(),
                params.m(),
                params.rounds(),
            ] {
                for count in [max + 1, usize::MAX] {
                    let mut bytes = postcard::to_allocvec(&count).unwrap();
                    if count == max + 1 {
                        // Make Postcard expose Some(count), rather than reject
                        // through its insufficient-remaining-bytes size hint.
                        bytes.resize(bytes.len() + count, 0);
                    }
                    let mut decoder = postcard::Deserializer::from_bytes(&bytes);
                    let result = Sequence {
                        min: 0,
                        max,
                        element: |_| -> ValueSeed<Digest> {
                            panic!("oversized length visited an element")
                        },
                    }
                    .deserialize(&mut decoder);
                    assert!(matches!(result, Err(postcard::Error::SerdeDeCustom)));
                }
            }
        }
    }
    assert!(boundary_bound(usize::MAX, 2).is_err());
}

fn public_params<P: FieldProfile>(log_d: usize) -> crate::PublicParams {
    crate::PublicParams {
        base_field: crate::BaseField::Goldilocks,
        extension_degree: P::PROFILE.extension_degree(),
        log_d,
        m: 4,
        blowup: 2,
        terminal_coefficients: 2,
        num_queries: 19,
        agreement_numerator: 18,
        agreement_denominator: 25,
    }
}
fn test_params<P: FieldProfile>(log_d: usize) -> JbParams {
    JbParams::new(public_params::<P>(log_d)).unwrap()
}
