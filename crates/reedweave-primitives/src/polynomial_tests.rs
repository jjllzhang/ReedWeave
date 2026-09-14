use super::*;
use crate::{
    fields::Goldilocks,
    transcript::{
        FieldProfile, GoldilocksBaseProfile, GoldilocksCubicProfile, GoldilocksQuadraticProfile,
        GoldilocksQuinticProfile,
    },
};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};

#[test]
fn interleaved_evaluations_match_direct_powers_across_scheduling_boundaries() {
    let executions: Vec<_> = [1, 2, 4]
        .into_iter()
        .map(|threads| ExecutionContext::new(threads).unwrap())
        .collect();
    let n = MIN_PARALLEL_ELEMENTS;
    let coefficients: Vec<_> = (0..2 * n)
        .map(|i| Goldilocks::from_usize(i * i + 7))
        .collect();
    for width in [1, 4, 64] {
        for len in [0, 1, width - 1, width, width + 1, n - 1, n, n + 1, 2 * n] {
            for point in [Goldilocks::ZERO, Goldilocks::ONE, Goldilocks::from_u8(3)] {
                let mut expected = vec![Goldilocks::ZERO; width];
                let mut power = Goldilocks::ONE;
                for row in coefficients[..len].chunks(width) {
                    for (value, &coefficient) in expected.iter_mut().zip(row) {
                        *value += power * coefficient;
                    }
                    power *= point;
                }
                for execution in &executions {
                    assert_eq!(
                        evaluate_interleaved(&coefficients[..len], width, point, execution),
                        expected,
                        "width={width}, len={len}, threads={}",
                        execution.threads()
                    );
                }
            }
        }
    }
}

#[test]
fn row_combinations_preserve_serial_dot_products_all_profiles_and_thread_counts() {
    fn check<P: FieldProfile>(executions: &[ExecutionContext]) {
        let n = MIN_PARALLEL_ELEMENTS;
        let values: Vec<_> = (0..2 * n).map(|i| P::Base::from_usize(i * i + 7)).collect();
        // Includes m=1 (many independent rows), and a single wide row that
        // should not schedule parallel work even above the element threshold.
        for width in [1, 4, 64, n] {
            let weights: Vec<_> = (0..width)
                .map(|i| {
                    P::Challenge::from_basis_coefficients_fn(|j| P::Base::from_usize(i + 3 * j + 2))
                })
                .collect();
            for len in [0, width, n - width, n, n + width, 2 * n] {
                let expected: Vec<_> = values[..len]
                    .chunks_exact(width)
                    .map(|row| {
                        row.iter()
                            .zip(&weights)
                            .fold(P::Challenge::ZERO, |sum, (&value, &weight)| {
                                sum + weight * value
                            })
                    })
                    .collect();
                for execution in executions {
                    assert_eq!(
                        combine_rows(&values[..len], &weights, execution),
                        expected,
                        "width={width}, len={len}, threads={}",
                        execution.threads()
                    );
                    assert_eq!(
                        combine_rows(&values[..len], &vec![P::Challenge::ZERO; width], execution),
                        vec![P::Challenge::ZERO; len / width]
                    );
                }
            }
        }
    }
    let executions: Vec<_> = [1, 2, 4]
        .into_iter()
        .map(|threads| ExecutionContext::new(threads).unwrap())
        .collect();
    check::<GoldilocksBaseProfile>(&executions);
    check::<GoldilocksQuadraticProfile>(&executions);
    check::<GoldilocksCubicProfile>(&executions);
    check::<GoldilocksQuinticProfile>(&executions);
}

#[test]
#[should_panic(expected = "component width must be positive")]
fn evaluation_rejects_zero_width() {
    evaluate_interleaved::<Goldilocks>(&[], 0, Goldilocks::ONE, &ExecutionContext::new(1).unwrap());
}

#[test]
#[should_panic(expected = "row width must be positive")]
fn combinations_reject_empty_weights() {
    combine_rows::<Goldilocks, Goldilocks>(&[], &[], &ExecutionContext::new(1).unwrap());
}

#[test]
#[should_panic(expected = "incomplete row")]
fn combinations_reject_incomplete_rows() {
    combine_rows(
        &[Goldilocks::ONE],
        &[Goldilocks::ONE; 2],
        &ExecutionContext::new(1).unwrap(),
    );
}
