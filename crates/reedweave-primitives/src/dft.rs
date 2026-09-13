//! Coefficient-column DFTs on naturally ordered base-field subgroups.
//!
//! Row `t` of every result is evaluation at `F::two_adic_generator(log_n)^t`.
//! Extension coefficients use that same base root, via upstream coordinate DFTs.

use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{ExtensionField, TwoAdicField};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use reedweave_runtime::ExecutionContext;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum DftError {
    #[error("matrix width must be positive")]
    ZeroWidth,
    #[error("value count {len} is not divisible by width {width}")]
    IncompleteRow { len: usize, width: usize },
    #[error("domain height {height} must be a nonzero power of two")]
    InvalidHeight { height: usize },
    #[error("domain logarithm {log_height} exceeds base-field two-adicity {two_adicity}")]
    UnsupportedDomain {
        log_height: usize,
        two_adicity: usize,
    },
    #[error("block capacity {block_capacity} must be positive and at most domain height {height}")]
    InvalidBlockCapacity {
        block_capacity: usize,
        height: usize,
    },
    #[error("expected {expected} coefficients, received {actual}")]
    CoefficientCount { expected: usize, actual: usize },
    #[error("matrix size exceeds addressable storage")]
    SizeOverflow,
    #[error("could not allocate the padded coefficient matrix")]
    AllocationFailed,
}

fn check_height<F: TwoAdicField>(height: usize) -> Result<(), DftError> {
    if !height.is_power_of_two() {
        return Err(DftError::InvalidHeight { height });
    }
    let log_height = height.trailing_zeros() as usize;
    if log_height > F::TWO_ADICITY {
        return Err(DftError::UnsupportedDomain {
            log_height,
            two_adicity: F::TWO_ADICITY,
        });
    }
    Ok(())
}

fn check_storage<T>(len: usize) -> Result<(), DftError> {
    if len
        .checked_mul(size_of::<T>())
        .is_none_or(|bytes| bytes > isize::MAX as usize)
    {
        return Err(DftError::SizeOverflow);
    }
    Ok(())
}

fn check_matrix<F: TwoAdicField, T>(matrix: &RowMajorMatrix<T>) -> Result<usize, DftError> {
    if matrix.width == 0 {
        return Err(DftError::ZeroWidth);
    }
    if !matrix.values.len().is_multiple_of(matrix.width) {
        return Err(DftError::IncompleteRow {
            len: matrix.values.len(),
            width: matrix.width,
        });
    }
    let height = matrix.values.len() / matrix.width;
    check_height::<F>(height)?;
    Ok(height)
}

/// Reusable upstream twiddle caches; all transform work uses the supplied local pool.
#[derive(Clone, Debug, Default)]
pub struct NaturalOrderDft<F> {
    inner: Radix2DitParallel<F>,
}

impl<F: TwoAdicField + Ord> NaturalOrderDft<F> {
    /// Consume a row-major matrix whose columns contain ascending coefficients.
    /// Padding, if needed, must already be present. Shapes are checked before upstream calls.
    pub fn dft_batch(
        &self,
        coefficients: RowMajorMatrix<F>,
        execution: &ExecutionContext,
    ) -> Result<RowMajorMatrix<F>, DftError> {
        let height = check_matrix::<F, _>(&coefficients)?;
        if height == 1 {
            return Ok(coefficients);
        }
        Ok(execution.install(|| self.inner.dft_batch(coefficients).to_row_major_matrix()))
    }

    /// Transform extension coefficients over the subgroup in `F`, not an extension root.
    /// Upstream flattens basis coordinates into columns and restores them after the DFT.
    pub fn dft_extension_batch<E: ExtensionField<F>>(
        &self,
        coefficients: RowMajorMatrix<E>,
        execution: &ExecutionContext,
    ) -> Result<RowMajorMatrix<E>, DftError> {
        let height = check_matrix::<F, _>(&coefficients)?;
        let base_len = coefficients
            .values
            .len()
            .checked_mul(E::DIMENSION)
            .ok_or(DftError::SizeOverflow)?;
        coefficients
            .width
            .checked_mul(E::DIMENSION)
            .ok_or(DftError::SizeOverflow)?;
        check_storage::<F>(base_len)?;
        if height == 1 {
            return Ok(coefficients);
        }
        Ok(execution.install(|| self.inner.dft_algebra_batch(coefficients)))
    }
}

/// Build the padded `height × blocks` coefficient matrix for coefficient-input commitment.
///
/// Input `coefficients[blocks * a + i]` becomes output `[a, i]`;
/// rows `block_capacity..height` are zero. The input is borrowed for retention by M2.
/// This primitive permits small test geometries; protocol parameter checks belong to core.
/// Layout writes are sequential, with one destination allocation.
pub fn padded_coefficient_blocks<F: TwoAdicField>(
    coefficients: &[F],
    blocks: usize,
    block_capacity: usize,
    height: usize,
) -> Result<RowMajorMatrix<F>, DftError> {
    if blocks == 0 {
        return Err(DftError::ZeroWidth);
    }
    check_height::<F>(height)?;
    if block_capacity == 0 || block_capacity > height {
        return Err(DftError::InvalidBlockCapacity {
            block_capacity,
            height,
        });
    }
    let expected = blocks
        .checked_mul(block_capacity)
        .ok_or(DftError::SizeOverflow)?;
    let len = blocks.checked_mul(height).ok_or(DftError::SizeOverflow)?;
    check_storage::<F>(len)?;
    if coefficients.len() > expected {
        return Err(DftError::CoefficientCount {
            expected,
            actual: coefficients.len(),
        });
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(len)
        .map_err(|_| DftError::AllocationFailed)?;
    values.resize(len, F::ZERO);
    values[..coefficients.len()].copy_from_slice(coefficients);
    Ok(RowMajorMatrix::new(values, blocks))
}
