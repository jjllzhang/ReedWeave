use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use reedweave_primitives::{
    fields::Goldilocks as F,
    mmcs::{CanonicalMmcs, LeafKind},
    transcript::GoldilocksBaseProfile,
};
use reedweave_runtime::ExecutionContext;
use reedweave_ub_core::{BaseField, Commitment, PcsError, PublicParams, ReedWeaveUb, UbParams};

#[test]
fn full_opening_checks_root_degree_shape_and_joint_column_distance() {
    let execution = ExecutionContext::new(1).unwrap();
    let params = UbParams::new(PublicParams {
        base_field: BaseField::Goldilocks,
        extension_degree: 1,
        log_d: 3,
        m: 2,
        blowup: 2,
        terminal_coefficients: 2,
        num_queries: 1,
    })
    .unwrap();
    let pcs = ReedWeaveUb::<GoldilocksBaseProfile>::new(params.clone()).unwrap();
    let (commitment, state) = pcs.commit(vec![F::TWO], &execution).unwrap();
    pcs.open_base(
        &commitment,
        state.coefficients(),
        state.encoded_word(),
        &execution,
    )
    .unwrap();
    pcs.open_base(&commitment, &[F::TWO], state.encoded_word(), &execution)
        .unwrap();
    let mmcs = CanonicalMmcs::new(LeafKind::Base, params.m()).unwrap();
    let root_of = |word: RowMajorMatrix<F>| Commitment {
        root: mmcs.commit(word, &execution).unwrap().0,
    };
    // N=8, k=4: strict distance bound is E < 2.5, so E=2 passes, E=3 fails.
    // Corrupt both components at each position: count columns, not field entries.
    for errors in 0..=3 {
        let mut word = state.encoded_word().clone();
        for column in 0..errors {
            for row in 0..params.m() {
                word.values[column * params.m() + row] += F::ONE;
            }
        }
        let root = root_of(word.clone());
        let result = pcs.open_base(&root, state.coefficients(), &word, &execution);
        if errors <= 2 {
            result.unwrap();
        } else {
            assert!(matches!(result, Err(PcsError::OpeningDistance)));
        }
        if errors > 0 {
            assert!(matches!(
                pcs.open_base(&commitment, state.coefficients(), &word, &execution),
                Err(PcsError::OpeningRoot)
            ));
        }
    }
    // Each component has only two errors, but their union contains four columns.
    let mut disjoint = state.encoded_word().clone();
    for (column, row) in [(0, 0), (1, 0), (2, 1), (3, 1)] {
        disjoint.values[column * params.m() + row] += F::ONE;
    }
    assert!(matches!(
        pcs.open_base(
            &root_of(disjoint.clone()),
            state.coefficients(),
            &disjoint,
            &execution
        ),
        Err(PcsError::OpeningDistance)
    ));
    assert!(matches!(
        pcs.open_base(
            &commitment,
            &vec![F::ZERO; params.d() + 1],
            state.encoded_word(),
            &execution
        ),
        Err(PcsError::CoefficientCount { .. })
    ));
    assert!(
        pcs.open_base(&commitment, &[F::ONE], state.encoded_word(), &execution)
            .is_err()
    );
    for mutation in 0..3 {
        let mut word = state.encoded_word().clone();
        match mutation {
            0 => word.width = 0,
            1 => word.width = 1,
            _ => {
                word.values.pop();
            }
        }
        assert!(matches!(
            pcs.open_base(&commitment, &[F::TWO], &word, &execution),
            Err(PcsError::Shape(_))
        ));
    }
}
