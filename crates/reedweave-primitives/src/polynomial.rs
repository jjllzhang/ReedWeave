//! Ordered polynomial evaluation and row combinations shared by UB and JB provers.
use p3_field::{ExtensionField, Field};
use p3_maybe_rayon::prelude::*;
use reedweave_runtime::ExecutionContext;

// Count total input field elements, not coefficients per component or output rows.
// This is a scheduling heuristic, not a measured hardware-independent crossover.
const MIN_PARALLEL_ELEMENTS: usize = 1 << 14;

/// Evaluate all interleaved component polynomials at the same base-field point.
/// Component `i` has ascending coefficients `coefficients[a * width + i]`.
/// Short inputs, including incomplete final rows, are implicitly zero-padded.
/// Parallel collection preserves component order and uses only the supplied pool.
///
/// # Panics
/// Panics if `width` is zero.
pub fn evaluate_interleaved<F: Field>(
    coefficients: &[F],
    width: usize,
    point: F,
    execution: &ExecutionContext,
) -> Vec<F> {
    assert!(width > 0, "component width must be positive");
    let evaluate = |i| {
        coefficients
            .iter()
            .skip(i)
            .step_by(width)
            .rev()
            .fold(F::ZERO, |value, &coefficient| value * point + coefficient)
    };
    if width > 1 && coefficients.len() >= MIN_PARALLEL_ELEMENTS && execution.threads() > 1 {
        execution.install(|| (0..width).into_par_iter().map(evaluate).collect())
    } else {
        (0..width).map(evaluate).collect()
    }
}

/// Combine each complete base-field row with extension-field weights.
/// The width is `weights.len()`. Rows are independent, but the inner dot product
/// keeps its serial order. Indexed collection retains row order without lifting
/// or copying the input matrix; only the output vector is allocated.
///
/// # Panics
/// Panics if the weights are empty or the input has an incomplete row.
pub fn combine_rows<F: Field, E: ExtensionField<F>>(
    values: &[F],
    weights: &[E],
    execution: &ExecutionContext,
) -> Vec<E> {
    let width = weights.len();
    assert!(width > 0, "row width must be positive");
    assert!(values.len().is_multiple_of(width), "incomplete row");
    let combine = |row: &[F]| {
        row.iter()
            .zip(weights)
            .map(|(&value, &weight)| weight * value)
            .sum()
    };
    if values.len() > width && values.len() >= MIN_PARALLEL_ELEMENTS && execution.threads() > 1 {
        execution.install(|| values.par_chunks_exact(width).map(combine).collect())
    } else {
        values.chunks_exact(width).map(combine).collect()
    }
}

#[cfg(test)]
#[path = "polynomial_tests.rs"]
mod tests;
