use brakefri_primitives::{
    fields::{CanonicalField, F128, Goldilocks, GoldilocksQuadratic},
    hash::{Blake3Suite, Digest, HashSuite, KeccakSuite, NodeHash, Sha256Suite, TranscriptHash},
    mmcs::{CanonicalMmcs, LeafKind},
};
use brakefri_runtime::ExecutionContext;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::{Dimensions, dense::RowMajorMatrix};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

fn hex(s: &str) -> Digest {
    assert_eq!(s.len(), 64);
    std::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
}

fn known_answers<S: HashSuite>(suite: S, empty: &str, abc: &str) {
    assert_eq!(suite.hasher().hash_slice(b""), hex(empty));
    assert_eq!(suite.hasher().hash_slice(b"abc"), hex(abc));
    let raw = suite.hasher();
    let transcript = TranscriptHash(raw.clone());
    assert_eq!(transcript.hash_slice(b"abc"), raw.hash_slice(b"\x02abc"));
    assert_ne!(transcript.hash_slice(b"abc"), raw.hash_slice(b"abc"));
    let inputs = [[0; 32], [1; 32]];
    let mut bytes = [0; 65];
    bytes[0] = 1;
    bytes[33..].fill(1);
    let node = NodeHash(raw.clone()).compress(inputs);
    assert_eq!(node, raw.hash_slice(&bytes));
    assert_ne!(node, transcript.hash_slice(&bytes[1..]));
    assert_ne!(node, NodeHash(raw).compress([inputs[1], inputs[0]]));
}

#[test]
fn all_hash_backends_match_known_vectors_and_role_preimages() {
    known_answers(
        KeccakSuite,
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
    );
    known_answers(
        Sha256Suite,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    known_answers(
        Blake3Suite,
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
    );
    assert_eq!(
        NodeHash(Sha256Suite.hasher()).compress([[0; 32], [1; 32]]),
        hex("2ad82c3a51e8ed6418cb5bf267c5f9e521b99f7ab4fce657f460a8f1a3e87b2e")
    );
    assert_eq!(
        TranscriptHash(Sha256Suite.hasher()).hash_slice(b"abc"),
        hex("909ac45e439911193205994d09399c29fede977ab212605f29ead5250a812e73")
    );
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
    let mmcs = CanonicalMmcs::<F, _>::new(Sha256Suite, kind, 1).unwrap();
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
fn canonical_merkle_roots_match_independent_sha256_vectors() {
    // Fixed vectors computed with Python hashlib from the plan's exact byte preimages.
    root_vector(
        LeafKind::Base,
        vec![Goldilocks::new(1), Goldilocks::new(2)],
        "86d84946fde40646fd39e82b78266848c5ee2f89b98822054b10dc6cd0b3372a",
    );
    root_vector(
        LeafKind::Challenge,
        vec![quadratic(1, 2), quadratic(3, 4)],
        "0ca48e915a5495a4d429a4cb5efd9fa003cae0173c6de112fae16da05890a63d",
    );
    root_vector(
        LeafKind::Base,
        vec![F128::new(1), F128::new(2)],
        "cabb6fcaba236863a90cd05ca1d0ab3ef0bec7b83a89cada085699048e386352",
    );
    root_vector(
        LeafKind::Challenge,
        vec![F128::new(1), F128::new(2)],
        "a651684f820dddab30f614b6075819af1eb79db49035277cdd4a91a1e80ad226",
    );
}

fn multiproof_cases<F: CanonicalField, S: HashSuite>(
    suite: S,
    kind: LeafKind,
    width: usize,
    values: Vec<F>,
) {
    let mmcs = CanonicalMmcs::<F, _>::new(suite, kind, width).unwrap();
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

fn suite_cases<S: HashSuite>(suite: S) {
    multiproof_cases(
        suite.clone(),
        LeafKind::Base,
        3,
        (0..24).map(Goldilocks::new).collect(),
    );
    multiproof_cases(
        suite.clone(),
        LeafKind::Challenge,
        1,
        (0..8).map(|i| quadratic(i, 100 + i)).collect(),
    );
    multiproof_cases(
        suite.clone(),
        LeafKind::Base,
        3,
        (0..24).map(F128::new).collect(),
    );
    multiproof_cases(
        suite,
        LeafKind::Challenge,
        1,
        (0..8).map(F128::new).collect(),
    );
}

#[test]
fn base_and_extension_multiproofs_and_malformed_openings() {
    suite_cases(KeccakSuite);
    suite_cases(Sha256Suite);
    suite_cases(Blake3Suite);
}

#[test]
fn reject_wrong_suite_role_and_malformed_commit_shapes() {
    let execution = ExecutionContext::new(1).unwrap();
    let mmcs = CanonicalMmcs::<Goldilocks, _>::new(KeccakSuite, LeafKind::Base, 1).unwrap();
    let (root, state) = mmcs
        .commit(
            RowMajorMatrix::new_col(vec![Goldilocks::ONE; 8]),
            &execution,
        )
        .unwrap();
    let opening = mmcs.open_multi_batch(&[1, 2, 5], &state).unwrap();
    let wrong = CanonicalMmcs::<Goldilocks, _>::new(Sha256Suite, LeafKind::Base, 1).unwrap();
    assert!(
        wrong
            .verify_multi_batch(
                &root,
                Dimensions {
                    width: 1,
                    height: 8
                },
                &[1, 2, 5],
                &opening.rows,
                &opening.proof
            )
            .is_err()
    );
    assert!(CanonicalMmcs::<Goldilocks, _>::new(KeccakSuite, LeafKind::Challenge, 1).is_err());
    assert!(CanonicalMmcs::<GoldilocksQuadratic, _>::new(KeccakSuite, LeafKind::Base, 1).is_err());
    assert!(CanonicalMmcs::<F128, _>::new(KeccakSuite, LeafKind::Challenge, 2).is_err());
    assert!(CanonicalMmcs::<Goldilocks, _>::new(KeccakSuite, LeafKind::Base, 0).is_err());
    for (width, length) in [(0, 0), (0, 4), (1, 0), (1, 1), (1, 3), (2, 3), (2, 8)] {
        // Public fields can be mutated after the constructor's shape assertions.
        let mut matrix = RowMajorMatrix::new_col(vec![Goldilocks::ZERO; length]);
        matrix.width = width;
        assert!(mmcs.commit(matrix, &execution).is_err());
    }
    let base = CanonicalMmcs::<F128, _>::new(KeccakSuite, LeafKind::Base, 1).unwrap();
    let challenge = CanonicalMmcs::<F128, _>::new(KeccakSuite, LeafKind::Challenge, 1).unwrap();
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
