use super::*;
use brakefri_primitives::{
    fields::{F128, Goldilocks, GoldilocksQuadratic},
    hash::{Blake3Suite, KeccakSuite, Sha256Suite},
    transcript::{F128Profile, GoldilocksProfile},
};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};

// Independent ordinary Serde receiver describes exactly the protocol wire shape.
// Its unbounded Deserialize is only a test interoperability reference.
#[derive(Debug, Serialize, Deserialize)]
struct ReferenceProof<B, K> {
    blocks: Vec<B>,
    rounds: Vec<(K, K, [u8; 32])>,
    constant: K,
    terminal: [K; 2],
    initial: (Vec<Vec<B>>, Vec<[u8; 32]>),
    scalars: Vec<(Vec<K>, Vec<[u8; 32]>)>,
}

type GoldWire = ReferenceProof<[u8; 8], ([u8; 8], [u8; 8])>;
type F128Wire = ReferenceProof<[u8; 16], ([u8; 16],)>;

fn varint_size(n: usize) -> usize {
    postcard::to_allocvec(&n).unwrap().len()
}

// Structural formula plus every real vector header, independent of the encoder.
fn structural_size<P: FieldProfile>(proof: &BrakeProof<P>) -> usize {
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
    let payload = P::Base::BYTE_WIDTH * (M + M * u0)
        + 16 * (2 * ell + 3 + scalar_values)
        + 32 * (1 + ell + nodes);
    let framing = varint_size(M)
        + varint_size(ell)
        + varint_size(u0)
        + u0 * varint_size(M)
        + varint_size(h0)
        + varint_size(ell - 1)
        + proof
            .scalar_openings
            .iter()
            .map(|o| varint_size(o.values.len()) + varint_size(o.proof.sibling_hashes.len()))
            .sum::<usize>();
    payload + framing
}

fn fixture<P: FieldProfile, S: HashSuite>(
    log_n: usize,
    suite: S,
) -> (
    BrakeFri<P, S>,
    ExecutionContext,
    Commitment,
    P::Base,
    crate::Opening<P>,
) {
    let params = BrakeParams::new(P::PROFILE, log_n).unwrap();
    let execution = ExecutionContext::new(1).unwrap();
    let pcs = BrakeFri::<P, S>::new(params.clone(), suite).unwrap();
    let coefficients = (0..params.n())
        .map(|i| P::Base::from_usize(i * 17 + 3))
        .collect();
    let (commitment, state) = pcs.commit(coefficients, &execution).unwrap();
    let z = P::Base::from_u8(9);
    let opening = pcs.prove(&state, z, &execution).unwrap();
    (pcs, execution, commitment, z, opening)
}

fn roundtrip<P: FieldProfile, S: HashSuite>(suite: S, log_n: usize) {
    let (pcs, execution, commitment, z, opening) = fixture::<P, S>(log_n, suite);
    let commit_bytes = encode_commitment(&commitment);
    assert_eq!(commit_bytes, commitment.root);
    assert_eq!(decode_commitment(&commit_bytes).unwrap(), commitment);
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
    assert_eq!(total, structural_size(&opening.proof));
    assert_eq!(
        pcs.verify_encoded(
            &commitment,
            (z, opening.y),
            &transport[..32],
            &transport[32..],
            &execution
        )
        .unwrap(),
        total
    );
    let mut wrong_root = commit_bytes;
    wrong_root[0] ^= 1;
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
    if log_n == 18 {
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
fn actual_bytes_verify_for_every_field_and_suite() {
    roundtrip::<GoldilocksProfile, _>(KeccakSuite, 12);
    roundtrip::<GoldilocksProfile, _>(Sha256Suite, 12);
    roundtrip::<GoldilocksProfile, _>(Blake3Suite, 12);
    roundtrip::<F128Profile, _>(KeccakSuite, 12);
    roundtrip::<F128Profile, _>(Sha256Suite, 12);
    roundtrip::<F128Profile, _>(Blake3Suite, 12);
    roundtrip::<GoldilocksProfile, _>(Blake3Suite, 18);
    roundtrip::<F128Profile, _>(Blake3Suite, 18);
    // ell=1 has no scalar openings, but still has a vector length of zero.
    roundtrip::<GoldilocksProfile, _>(Blake3Suite, 11);
    roundtrip::<F128Profile, _>(Blake3Suite, 11);
}

#[test]
fn serde_interoperability_and_protocol_only_order() {
    let (pcs, execution, commitment, z, opening) = fixture::<GoldilocksProfile, _>(12, Blake3Suite);
    let bytes = encode_eval_proof(pcs.params(), &opening.proof).unwrap();
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
        let coords: &[Goldilocks] = round.even_value.as_basis_coefficients_slice();
        assert_eq!(
            wire_round.0,
            (
                coords[0].to_canonical_bytes(),
                coords[1].to_canonical_bytes()
            )
        );
        let coords: &[Goldilocks] = round.odd_value.as_basis_coefficients_slice();
        assert_eq!(
            wire_round.1,
            (
                coords[0].to_canonical_bytes(),
                coords[1].to_canonical_bytes()
            )
        );
        assert_eq!(wire_round.2, round.next_oracle_root);
    }
    assert_eq!(
        wire.initial.0.len(),
        opening.proof.initial_opening.rows.len()
    );
    let received = postcard::to_allocvec(&wire).unwrap();
    assert_eq!(received, bytes);
    pcs.verify_encoded(
        &commitment,
        (z, opening.y),
        &commitment.root,
        &received,
        &execution,
    )
    .unwrap();

    let (pcs, execution, commitment, z, opening) = fixture::<F128Profile, _>(12, Sha256Suite);
    let bytes = encode_eval_proof(pcs.params(), &opening.proof).unwrap();
    let wire: F128Wire = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(
        wire.constant.0,
        opening.proof.terminal_constant.to_canonical_bytes()
    );
    assert_eq!(
        wire.terminal.map(|c| c.0),
        opening
            .proof
            .terminal_values
            .map(|c| c.to_canonical_bytes())
    );
    assert_eq!(
        wire.initial.0,
        opening
            .proof
            .initial_opening
            .rows
            .iter()
            .map(|row| row
                .iter()
                .map(CanonicalField::to_canonical_bytes)
                .collect::<Vec<_>>())
            .collect::<Vec<_>>()
    );
    for (scalar, opening) in wire.scalars.iter().zip(&opening.proof.scalar_openings) {
        assert_eq!(
            scalar.0,
            opening
                .values
                .iter()
                .map(|v| (v.to_canonical_bytes(),))
                .collect::<Vec<_>>()
        );
        assert_eq!(scalar.1, opening.proof.sibling_hashes);
    }
    let received = postcard::to_allocvec(&wire).unwrap();
    assert_eq!(received, bytes);
    pcs.verify_encoded(
        &commitment,
        (z, opening.y),
        &commitment.root,
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
    }
}
#[test]
fn canonical_fixed_coordinate_arrays() {
    coordinate_width(&[Goldilocks::ZERO, Goldilocks::ONE, -Goldilocks::ONE]);
    coordinate_width(&[F128::ZERO, F128::ONE, -F128::ONE]);
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
    for value in [F128::MODULUS, u128::MAX] {
        assert!(postcard::from_bytes::<Coordinate<F128>>(&value.to_le_bytes()).is_err());
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
        // Cover first/last canonical coordinates of each message, including u.
        for i in 0..count {
            self.coordinates.push(self.at + i * width);
        }
        self.at += count * width;
    }
}
fn layout<P: FieldProfile>(params: &BrakeParams, proof: &BrakeProof<P>) -> Layout {
    let mut l = Layout {
        at: 0,
        vectors: Vec::new(),
        coordinates: Vec::new(),
    };
    l.vector(M, M, M);
    l.fields(M, P::Base::COORDINATE_BYTES);
    l.vector(params.rounds(), params.rounds(), params.rounds());
    for _ in &proof.rounds {
        l.fields(
            2 * P::Challenge::COORDINATE_COUNT,
            P::Base::COORDINATE_BYTES,
        );
        l.at += 32;
    }
    l.fields(
        3 * P::Challenge::COORDINATE_COUNT,
        P::Base::COORDINATE_BYTES,
    );
    let (max, depth) = opening_bounds(params, 0).unwrap();
    l.vector(proof.initial_opening.rows.len(), 1, max);
    for row in &proof.initial_opening.rows {
        l.vector(row.len(), M, M);
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
    let (pcs, execution, commitment, z, opening) = fixture::<P, _>(12, Blake3Suite);
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
        for end in [offset.saturating_sub(1), offset, offset + 1] {
            if end < bytes.len() {
                assert!(decode_eval_proof::<P>(pcs.params(), &bytes[..end]).is_err());
            }
        }
    }
    let width = P::Base::COORDINATE_BYTES;
    // Representative samples across every message and each extension coordinate.
    let offsets = layout
        .coordinates
        .iter()
        .step_by(113)
        .copied()
        .chain(layout.coordinates.iter().rev().take(20).copied());
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
    // Same numerical length M with a redundant final varint group.
    let mut overlong = vec![0x80, 0x88, 0x00];
    overlong.extend_from_slice(&bytes[2..]);
    assert!(decode_eval_proof::<P>(pcs.params(), &overlong).is_err());
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
                &commitment.root,
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
    let other = BrakeParams::new(
        if P::PROFILE == crate::Profile::F128Base {
            crate::Profile::GoldilocksQuadratic
        } else {
            crate::Profile::F128Base
        },
        12,
    )
    .unwrap();
    assert!(encode_eval_proof(&other, &opening.proof).is_err());
    assert!(decode_eval_proof::<P>(&other, &bytes).is_err());
}

#[test]
fn malformed_bytes_and_typed_frontiers() {
    malformed::<GoldilocksProfile>();
    malformed::<F128Profile>();
    for count in [0, 1, 31, 33, 64] {
        assert!(decode_commitment(&vec![0; count]).is_err());
    }
}

#[test]
fn length_bounds_precede_element_visits_at_largest_parameters() {
    for profile in [
        crate::Profile::GoldilocksQuadratic,
        crate::Profile::F128Base,
    ] {
        let params = BrakeParams::new(profile, 30).unwrap();
        for j in 0..params.rounds() {
            let (values, depth) = opening_bounds(&params, j).unwrap();
            for max in [
                values,
                boundary_bound(values, depth).unwrap(),
                M,
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
