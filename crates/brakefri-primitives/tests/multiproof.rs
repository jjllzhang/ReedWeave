//! Exhaustive small-tree frontier checks through borrowed flat scalar openings.
use brakefri_primitives::{
    fields::{CanonicalField, F128, GoldilocksQuadratic},
    hash::{Blake3Suite, HashSuite, KeccakSuite, Sha256Suite},
    mmcs::{CanonicalMmcs, LeafKind},
};
use brakefri_runtime::ExecutionContext;
use p3_matrix::{Dimensions, dense::RowMajorMatrix};

fn all_subsets<F: CanonicalField, S: HashSuite>(suite: S) {
    let execution = ExecutionContext::new(1).unwrap();
    let mmcs = CanonicalMmcs::<F, _>::new(suite, LeafKind::Challenge, 1).unwrap();
    let dimensions = Dimensions {
        width: 1,
        height: 8,
    };
    let values: Vec<_> = (1..=8).map(F::from_usize).collect();
    let (root, state) = mmcs
        .commit(RowMajorMatrix::new_col(values.clone()), &execution)
        .unwrap();
    // Independently authenticate ordinary paths before using their sibling digests
    // as a reference for the shared frontier's prescribed order.
    let paths: Vec<_> = (0..8)
        .map(|index| {
            let (row, path) = mmcs.open_batch(index, &state).unwrap();
            assert_eq!(row, [values[index]]);
            mmcs.verify_batch(&root, dimensions, index, &row, &path)
                .unwrap();
            path
        })
        .collect();
    let example = mmcs.open_multi_batch(&[1, 2, 5], &state).unwrap();
    assert_eq!(
        example.proof.sibling_hashes,
        [paths[1][0], paths[2][0], paths[5][0], paths[5][1]]
    );

    for mask in 1u16..256 {
        let indices: Vec<_> = (0..8).filter(|i| mask & (1 << i) != 0).collect();
        let opening = mmcs.open_multi_batch(&indices, &state).unwrap();
        let flat: Vec<_> = indices.iter().map(|&i| values[i]).collect();
        assert_eq!(
            opening.rows,
            flat.iter().map(|&v| vec![v]).collect::<Vec<_>>()
        );
        let (rows, _) = flat.as_chunks::<1>();
        let verify = |ids: &[usize], rows: &[[F; 1]], proof: &_| {
            mmcs.verify_multi_batch(&root, dimensions, ids, rows, proof)
        };
        verify(&indices, rows, &opening.proof).unwrap();
        let mut extra = opening.proof.clone();
        extra.sibling_hashes.push([0; 32]);
        assert!(verify(&indices, rows, &extra).is_err());
        if mask == 255 {
            assert!(opening.proof.sibling_hashes.is_empty());
        } else {
            assert!(!opening.proof.sibling_hashes.is_empty());
            let mut missing = opening.proof.clone();
            missing.sibling_hashes.pop();
            assert!(verify(&indices, rows, &missing).is_err());
            let mut wrong = opening.proof.clone();
            wrong.sibling_hashes[0][0] ^= 1;
            assert!(verify(&indices, rows, &wrong).is_err());
            // Keep the count and canonical ordering, but replace one authenticated
            // position with a different leaf. No index is supplied by a wire proof.
            let substitute = (0..8).find(|i| !indices.contains(i)).unwrap();
            let mut ids = indices.clone();
            ids[0] = substitute;
            ids.sort_unstable();
            assert!(verify(&ids, rows, &opening.proof).is_err());
        }
        let mut wrong = rows.to_vec();
        wrong[0][0] += F::ONE;
        assert!(verify(&indices, &wrong, &opening.proof).is_err());
        if rows.len() > 1 {
            wrong.copy_from_slice(rows);
            wrong.swap(0, rows.len() - 1);
            assert!(verify(&indices, &wrong, &opening.proof).is_err());
        }
        assert!(verify(&indices, &rows[..rows.len() - 1], &opening.proof).is_err());
        let mut extra_row = rows.to_vec();
        extra_row.push([F::ZERO]);
        assert!(verify(&indices, &extra_row, &opening.proof).is_err());
        let wrong_width: Vec<_> = flat.iter().map(|&v| [v, v]).collect();
        assert!(
            mmcs.verify_multi_batch(&root, dimensions, &indices, &wrong_width, &opening.proof)
                .is_err()
        );
        let mut changed_root = root;
        changed_root[0] ^= 1;
        assert!(
            mmcs.verify_multi_batch(&changed_root, dimensions, &indices, rows, &opening.proof)
                .is_err()
        );
    }

    // Equal values still occupy distinct leaves: opening all of them needs eight
    // values and no boundary nodes; value-based deduplication must be rejected.
    let (root, state) = mmcs
        .commit(RowMajorMatrix::new_col(vec![F::ZERO; 8]), &execution)
        .unwrap();
    let indices: Vec<_> = (0..8).collect();
    let opening = mmcs.open_multi_batch(&indices, &state).unwrap();
    assert_eq!(opening.rows.len(), 8);
    assert!(opening.proof.sibling_hashes.is_empty());
    mmcs.verify_multi_batch(&root, dimensions, &indices, &opening.rows, &opening.proof)
        .unwrap();
    assert!(
        mmcs.verify_multi_batch(&root, dimensions, &indices, &[[F::ZERO]], &opening.proof)
            .is_err()
    );
}

#[test]
fn every_small_scalar_frontier_matches_paths_and_rejects_malformed_openings() {
    all_subsets::<GoldilocksQuadratic, _>(KeccakSuite);
    all_subsets::<F128, _>(KeccakSuite);
    all_subsets::<GoldilocksQuadratic, _>(Sha256Suite);
    all_subsets::<F128, _>(Sha256Suite);
    all_subsets::<GoldilocksQuadratic, _>(Blake3Suite);
    all_subsets::<F128, _>(Blake3Suite);
}
