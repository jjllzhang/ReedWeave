use brakefri_primitives::{
    fields::{CanonicalField, F128, Goldilocks, GoldilocksQuadratic},
    hash::{Digest, LeafKind, NodeHash, TranscriptHash},
    mmcs::CanonicalMmcs,
};
use brakefri_runtime::ExecutionContext;
use p3_blake3::Blake3;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::{Dimensions, dense::RowMajorMatrix};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

fn hex(s: &str) -> Digest {
    assert_eq!(s.len(), 64);
    std::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
}

#[test]
fn blake3_matches_known_vectors_and_role_preimages() {
    assert_eq!(
        Blake3.hash_slice(b""),
        hex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
    );
    assert_eq!(
        Blake3.hash_slice(b"abc"),
        hex("6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85")
    );
    let transcript = TranscriptHash;
    assert_eq!(
        transcript.hash_slice(b"abc"),
        hex("16397a3c72e1b09eb34559edb332c5d7663fa4b59c9fdb6163a66490e4a9a892")
    );
    assert_ne!(transcript.hash_slice(b"abc"), Blake3.hash_slice(b"abc"));
    let inputs = [[0; 32], [1; 32]];
    let node = NodeHash.compress(inputs);
    assert_eq!(
        node,
        hex("9c0959bbfdc28397be447a8f4e58f30b9d8b44c8dff92d02bf14aa4e92758197")
    );
    assert_ne!(
        node,
        Blake3.hash_slice(b"\x01\x00\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")
    );
    assert_ne!(node, NodeHash.compress([inputs[1], inputs[0]]));
}

fn quadratic(a: u64, b: u64) -> GoldilocksQuadratic {
    let coordinates = [Goldilocks::new(a), Goldilocks::new(b)];
    GoldilocksQuadratic::from_basis_coefficients_fn(|i| coordinates[i])
}

#[test]
fn canonical_coordinates_reject_aliases_and_preserve_basis_order() {
    let p = Goldilocks::ORDER_U64;
    // Upstream Goldilocks can retain a noncanonical machine representative.
    assert_eq!(Goldilocks::new(p).to_canonical_bytes(), [0; 8]);
    for value in [0, 1, p - 1] {
        let element = Goldilocks::new(value);
        assert_eq!(
            Goldilocks::from_canonical_bytes(&element.to_canonical_bytes()).unwrap(),
            element
        );
    }
    for value in [p, u64::MAX] {
        assert!(Goldilocks::from_canonical_bytes(&value.to_le_bytes()).is_err());
    }
    let element = quadratic(0x0102030405060708, 0x1112131415161718);
    let expected = [8, 7, 6, 5, 4, 3, 2, 1, 24, 23, 22, 21, 20, 19, 18, 17];
    assert_eq!(element.to_canonical_bytes(), expected);
    assert_eq!(
        GoldilocksQuadratic::from_canonical_bytes(&expected).unwrap(),
        element
    );
    assert_eq!(quadratic(0, 1).square(), quadratic(7, 0));
    for coordinate in 0..2 {
        let mut bad = expected;
        bad[8 * coordinate..8 * (coordinate + 1)].copy_from_slice(&p.to_le_bytes());
        assert!(GoldilocksQuadratic::from_canonical_bytes(&bad).is_err());
    }
    for value in [0, 1, F128::MODULUS - 1] {
        let element = F128::new(value);
        assert_eq!(element.to_canonical_bytes(), value.to_le_bytes());
        assert_eq!(
            <F128 as CanonicalField>::from_canonical_bytes(&element.to_canonical_bytes()).unwrap(),
            element
        );
    }
    for value in [F128::MODULUS, u128::MAX] {
        assert!(<F128 as CanonicalField>::from_canonical_bytes(&value.to_le_bytes()).is_err());
    }
    for length in [0, 7, 9, 15, 17, 32] {
        assert!(Goldilocks::from_canonical_bytes(&vec![0; length]).is_err());
        assert!(GoldilocksQuadratic::from_canonical_bytes(&vec![0; length]).is_err());
        assert!(<F128 as CanonicalField>::from_canonical_bytes(&vec![0; length]).is_err());
    }
}

fn root_vector<F: CanonicalField>(kind: LeafKind, values: Vec<F>, expected: &str) {
    let mmcs = CanonicalMmcs::<F>::new(kind, 1).unwrap();
    let execution = ExecutionContext::new(1).unwrap();
    let (root, state) = mmcs
        .commit(RowMajorMatrix::new_col(values), &execution)
        .unwrap();
    assert_eq!(root, hex(expected));
    let opening = mmcs.open_multi_batch(&[0, 1], &state).unwrap();
    assert!(opening.proof.sibling_hashes.is_empty());
    mmcs.verify_multi_batch(
        &root,
        Dimensions {
            width: 1,
            height: 2,
        },
        &[0, 1],
        &opening.rows,
        &opening.proof,
    )
    .unwrap();
}

#[test]
fn canonical_merkle_roots_match_independent_blake3_vectors() {
    // Fixed vectors computed with the BLAKE3 reference implementation from
    // the protocol's exact byte preimages.
    root_vector(
        LeafKind::Base,
        vec![Goldilocks::new(1), Goldilocks::new(2)],
        "314c764a1a2f4fb27f0cdbced45ba793deaf9f10f7cfc244798e3047988de5ec",
    );
    root_vector(
        LeafKind::Challenge,
        vec![quadratic(1, 2), quadratic(3, 4)],
        "abae38dbf2e2987726687f7e9216a67fbe19de3121f78dad4eb53283a36a7a64",
    );
    root_vector(
        LeafKind::Base,
        vec![F128::new(1), F128::new(2)],
        "d6d7487ad19c98cbeb83722e851aadc166ee71d44fe09fa2e970541135d2877e",
    );
    root_vector(
        LeafKind::Challenge,
        vec![F128::new(1), F128::new(2)],
        "36594bb91b4210bccf0ebc4fbc5c5a70696ae25030bd1eb8eb6a0419c51d3fe1",
    );
}

fn multiproof_cases<F: CanonicalField>(kind: LeafKind, width: usize, values: Vec<F>) {
    let mmcs = CanonicalMmcs::<F>::new(kind, width).unwrap();
    let execution = ExecutionContext::new(2).unwrap();
    let dimensions = Dimensions { width, height: 8 };
    let (root, state) = mmcs
        .commit(RowMajorMatrix::new(values.clone(), width), &execution)
        .unwrap();
    assert_eq!(state.matrix().values, values);
    // Repeated logical queries survive outside the authentication set. Both signs are present.
    let starts = [1, 1, 5, 2];
    let mut indices: Vec<_> = starts.iter().flat_map(|&i| [i, i ^ 4]).collect();
    indices.sort_unstable();
    indices.dedup();
    let opening = mmcs.open_multi_batch(&indices, &state).unwrap();
    mmcs.verify_multi_batch(&root, dimensions, &indices, &opening.rows, &opening.proof)
        .unwrap();
    for &start in &starts {
        for index in [start, start ^ 4] {
            let slot = indices.binary_search(&index).unwrap();
            let (row, path) = mmcs.open_batch(index, &state).unwrap();
            assert_eq!(row, opening.rows[slot]);
            mmcs.verify_batch(&root, dimensions, index, &row, &path)
                .unwrap();
            let mut extra = path.clone();
            extra.push([0; 32]);
            assert!(
                mmcs.verify_batch(&root, dimensions, index, &row, &extra)
                    .is_err()
            );
        }
    }
    let indices = [1, 2, 5];
    let opening = mmcs.open_multi_batch(&indices, &state).unwrap();
    assert_eq!(opening.proof.sibling_hashes.len(), 4); // 9 separate path nodes.
    let verify = |r: &Digest, dims, ids: &[usize], rows: &[Vec<F>], proof: &_| {
        mmcs.verify_multi_batch(r, dims, ids, rows, proof)
    };
    verify(&root, dimensions, &indices, &opening.rows, &opening.proof).unwrap();
    let mut bad_rows = opening.rows.clone();
    bad_rows[0][0] += F::ONE;
    assert!(verify(&root, dimensions, &indices, &bad_rows, &opening.proof).is_err());
    bad_rows = opening.rows.clone();
    bad_rows.swap(0, 1);
    assert!(verify(&root, dimensions, &indices, &bad_rows, &opening.proof).is_err());
    bad_rows = opening.rows.clone();
    bad_rows[0].pop();
    assert!(verify(&root, dimensions, &indices, &bad_rows, &opening.proof).is_err());
    bad_rows = opening.rows.clone();
    bad_rows[0].push(F::ZERO);
    assert!(verify(&root, dimensions, &indices, &bad_rows, &opening.proof).is_err());
    assert!(
        verify(
            &root,
            dimensions,
            &indices,
            &opening.rows[..2],
            &opening.proof
        )
        .is_err()
    );
    let mut bad_root = root;
    bad_root[0] ^= 1;
    assert!(
        verify(
            &bad_root,
            dimensions,
            &indices,
            &opening.rows,
            &opening.proof
        )
        .is_err()
    );
    for ids in [&[0, 2, 5][..], &[1, 2, 8], &[1, 1, 5], &[5, 2, 1], &[]] {
        assert!(verify(&root, dimensions, ids, &opening.rows, &opening.proof).is_err());
    }
    for ids in [&[8][..], &[1, 1], &[2, 1], &[]] {
        assert!(mmcs.open_multi_batch(ids, &state).is_err());
    }
    for height in [0, 1, 3, 7] {
        assert!(
            verify(
                &root,
                Dimensions { width, height },
                &indices,
                &opening.rows,
                &opening.proof
            )
            .is_err()
        );
    }
    assert!(
        verify(
            &root,
            Dimensions {
                width: width + 1,
                height: 8
            },
            &indices,
            &opening.rows,
            &opening.proof
        )
        .is_err()
    );
    let mut proof = opening.proof.clone();
    proof.sibling_hashes.pop();
    assert!(verify(&root, dimensions, &indices, &opening.rows, &proof).is_err());
    proof = opening.proof.clone();
    proof.sibling_hashes.push([0; 32]);
    assert!(verify(&root, dimensions, &indices, &opening.rows, &proof).is_err());
    proof = opening.proof.clone();
    proof.sibling_hashes[0][0] ^= 1;
    assert!(verify(&root, dimensions, &indices, &opening.rows, &proof).is_err());
    proof = opening.proof.clone();
    proof.sibling_hashes.swap(0, 1);
    assert!(verify(&root, dimensions, &indices, &opening.rows, &proof).is_err());
    let all: Vec<_> = (0..8).collect();
    let opening = mmcs.open_multi_batch(&all, &state).unwrap();
    assert!(opening.proof.sibling_hashes.is_empty());
    verify(&root, dimensions, &all, &opening.rows, &opening.proof).unwrap();
}

#[test]
fn base_and_extension_multiproofs_and_malformed_openings() {
    multiproof_cases(LeafKind::Base, 3, (0..24).map(Goldilocks::new).collect());
    multiproof_cases(
        LeafKind::Challenge,
        1,
        (0..8).map(|i| quadratic(i, 100 + i)).collect(),
    );
    multiproof_cases(LeafKind::Base, 3, (0..24).map(F128::new).collect());
    multiproof_cases(LeafKind::Challenge, 1, (0..8).map(F128::new).collect());
}

#[test]
fn reject_wrong_role_and_malformed_commit_shapes() {
    let execution = ExecutionContext::new(1).unwrap();
    let mmcs = CanonicalMmcs::<Goldilocks>::new(LeafKind::Base, 1).unwrap();
    let (root, state) = mmcs
        .commit(
            RowMajorMatrix::new_col(vec![Goldilocks::ONE; 8]),
            &execution,
        )
        .unwrap();
    let opening = mmcs.open_multi_batch(&[1, 2, 5], &state).unwrap();
    let wrong = CanonicalMmcs::<Goldilocks>::new(LeafKind::Base, 2).unwrap();
    assert!(
        wrong
            .verify_multi_batch(
                &root,
                Dimensions {
                    width: 2,
                    height: 8
                },
                &[1, 2, 5],
                &opening.rows,
                &opening.proof
            )
            .is_err()
    );
    assert!(CanonicalMmcs::<Goldilocks>::new(LeafKind::Challenge, 1).is_err());
    assert!(CanonicalMmcs::<GoldilocksQuadratic>::new(LeafKind::Base, 1).is_err());
    assert!(CanonicalMmcs::<F128>::new(LeafKind::Challenge, 2).is_err());
    assert!(CanonicalMmcs::<Goldilocks>::new(LeafKind::Base, 0).is_err());
    for (width, length) in [(0, 0), (0, 4), (1, 0), (1, 1), (1, 3), (2, 3), (2, 8)] {
        // Public fields can be mutated after the constructor's shape assertions.
        let mut matrix = RowMajorMatrix::new_col(vec![Goldilocks::ZERO; length]);
        matrix.width = width;
        assert!(mmcs.commit(matrix, &execution).is_err());
    }
    let base = CanonicalMmcs::<F128>::new(LeafKind::Base, 1).unwrap();
    let challenge = CanonicalMmcs::<F128>::new(LeafKind::Challenge, 1).unwrap();
    let (root, state) = base
        .commit(RowMajorMatrix::new_col(vec![F128::ONE; 2]), &execution)
        .unwrap();
    assert!(challenge.open_multi_batch(&[0, 1], &state).is_err());
    let opening = base.open_multi_batch(&[0, 1], &state).unwrap();
    assert!(
        challenge
            .verify_multi_batch(
                &root,
                Dimensions {
                    width: 1,
                    height: 2
                },
                &[0, 1],
                &opening.rows,
                &opening.proof
            )
            .is_err()
    );
}
