use brakefri_primitives::dft::{DftError, NaturalOrderDft, padded_coefficient_blocks};
use brakefri_runtime::ExecutionContext;
use p3_f128_adapter::F128;
use p3_field::{
    BasedVectorSpace, ExtensionField, PrimeCharacteristicRing, TwoAdicField,
    extension::BinomialExtensionField,
};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;

type GoldilocksExt = BinomialExtensionField<Goldilocks, 2>;

fn check_evaluations<F, E>(root: F, input: &RowMajorMatrix<E>, output: &RowMajorMatrix<E>)
where
    F: TwoAdicField,
    E: ExtensionField<F>,
{
    assert_eq!(output.width, input.width);
    assert_eq!(output.values.len(), input.values.len());
    for t in 0..input.values.len() / input.width {
        let x = E::from(root.exp_u64(t as u64));
        for i in 0..input.width {
            let expected = input
                .values
                .chunks_exact(input.width)
                .rev()
                .fold(E::ZERO, |acc, row| acc * x + row[i]);
            assert_eq!(
                output.values[t * input.width + i],
                expected,
                "row {t}, column {i}"
            );
        }
    }
}

fn base_cases<F: TwoAdicField + Ord>(fixed_root: F, two_adicity: usize) {
    let execution = ExecutionContext::new(3).unwrap();
    let dft = NaturalOrderDft::<F>::default();
    for log_height in 0..=7 {
        let height = 1 << log_height;
        let width = 5;
        // Zero, constant, X, highest-degree monomial, and dense polynomial.
        let mut input = RowMajorMatrix::new(vec![F::ZERO; height * width], width);
        input.values[1] = F::from_u64(19);
        input.values[(height - 1) * width + 3] = F::from_u64(23);
        input.values[usize::from(height > 1) * width + 2] = F::ONE;
        for a in 0..height {
            input.values[a * width + 4] = F::from_u64((a * a + 7 * a + 11) as u64);
        }
        let root = fixed_root.exp_power_of_2(two_adicity - log_height);
        let output = dft.dft_batch(input.clone(), &execution).unwrap();
        check_evaluations(root, &input, &output);
    }
}

#[test]
fn goldilocks_base_fixed_root_evaluations() {
    base_cases(Goldilocks::from_u64(0x185629dcda58878c), 32);
}

#[test]
fn f128_fixed_root_evaluations() {
    base_cases(F128::from_u128(23953097886125630542083529559205016746), 40);
}

#[test]
fn quadratic_coefficients_use_goldilocks_roots() {
    let execution = ExecutionContext::new(2).unwrap();
    let dft = NaturalOrderDft::<Goldilocks>::default();
    for log_height in 0..=6 {
        let height = 1 << log_height;
        let input = RowMajorMatrix::new(
            (0..height * 3)
                .map(|j| {
                    GoldilocksExt::from_basis_coefficients_slice(&[
                        Goldilocks::from_u64((j * j + 1) as u64),
                        Goldilocks::from_u64((3 * j + 7) as u64),
                    ])
                    .unwrap()
                })
                .collect(),
            3,
        );
        let root = Goldilocks::from_u64(0x185629dcda58878c).exp_power_of_2(32 - log_height);
        let output = dft.dft_extension_batch(input.clone(), &execution).unwrap();
        check_evaluations(root, &input, &output);
    }
}

#[test]
fn block_layout_crosses_tile_boundaries_and_encodes_each_block() {
    let (blocks, k, height) = (35, 37, 128);
    let coefficients: Vec<_> = (0..blocks * k)
        .map(|j| Goldilocks::from_u64((j + 1) as u64))
        .collect();
    let padded = padded_coefficient_blocks(&coefficients, blocks, k, height).unwrap();
    for a in 0..height {
        for i in 0..blocks {
            assert_eq!(
                padded.values[a * blocks + i],
                if a < k {
                    coefficients[i * k + a]
                } else {
                    Goldilocks::ZERO
                }
            );
        }
    }
    let output = NaturalOrderDft::<Goldilocks>::default()
        .dft_batch(padded, &ExecutionContext::new(1).unwrap())
        .unwrap();
    let root = Goldilocks::from_u64(0x185629dcda58878c).exp_power_of_2(25);
    for t in 0..height {
        let x = root.exp_u64(t as u64);
        for (i, block) in coefficients.chunks_exact(k).enumerate() {
            let expected = block
                .iter()
                .rev()
                .fold(Goldilocks::ZERO, |acc, &c| acc * x + c);
            assert_eq!(output.values[t * blocks + i], expected);
        }
    }
}

#[test]
fn malformed_matrices_return_errors_before_upstream() {
    let dft = NaturalOrderDft::<Goldilocks>::default();
    let execution = ExecutionContext::new(1).unwrap();
    for (len, width, error) in [
        (0, 0, DftError::ZeroWidth),
        (4, 0, DftError::ZeroWidth),
        (0, 2, DftError::InvalidHeight { height: 0 }),
        (5, 2, DftError::IncompleteRow { len: 5, width: 2 }),
        (6, 2, DftError::InvalidHeight { height: 3 }),
    ] {
        // Public fields allow malformed matrices even though the upstream constructor asserts.
        let mut input = RowMajorMatrix::new_col(vec![Goldilocks::ZERO; len]);
        input.width = width;
        assert_eq!(dft.dft_batch(input, &execution).unwrap_err(), error);
        let mut input = RowMajorMatrix::new_col(vec![GoldilocksExt::ZERO; len]);
        input.width = width;
        assert_eq!(
            dft.dft_extension_batch(input, &execution).unwrap_err(),
            error
        );
    }
}

#[test]
fn invalid_block_shapes_and_overflow_are_rejected_before_allocation() {
    let build = |blocks, k, height| {
        padded_coefficient_blocks::<Goldilocks>(&[], blocks, k, height).unwrap_err()
    };
    assert_eq!(build(0, 1, 2), DftError::ZeroWidth);
    for height in [0, 3, 6] {
        assert_eq!(build(1, 1, height), DftError::InvalidHeight { height });
    }
    for k in [0, 9] {
        assert_eq!(
            build(1, k, 8),
            DftError::InvalidBlockCapacity {
                block_capacity: k,
                height: 8
            }
        );
    }
    assert_eq!(
        build(2, 4, 8),
        DftError::CoefficientCount {
            expected: 8,
            actual: 0
        }
    );
    assert_eq!(
        padded_coefficient_blocks(&[Goldilocks::ONE; 9], 2, 4, 8).unwrap_err(),
        DftError::CoefficientCount {
            expected: 8,
            actual: 9
        }
    );
    assert_eq!(build(usize::MAX, 2, 2), DftError::SizeOverflow);
    assert_eq!(build(usize::MAX / 2, 1, 2), DftError::SizeOverflow);
    if usize::BITS > 33 {
        assert_eq!(
            build(1, 1, 1usize << 33),
            DftError::UnsupportedDomain {
                log_height: 33,
                two_adicity: 32
            }
        );
    }
}
