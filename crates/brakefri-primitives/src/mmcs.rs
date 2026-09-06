//! Checked single-matrix binary, cap-zero adapters to upstream Merkle MMCS.

use std::marker::PhantomData;

use brakefri_runtime::ExecutionContext;
use p3_commit::{BatchOpeningRef, Mmcs};
use p3_matrix::{Dimensions, Matrix, dense::RowMajorMatrix};
use p3_merkle_tree::{MerkleTree, MerkleTreeError, MerkleTreeMmcs};
use p3_symmetric::MerkleCap;
use thiserror::Error;

use crate::fields::CanonicalField;
pub use crate::hash::LeafKind;
use crate::hash::{CanonicalLeafHash, Digest, HashSuite, NodeHash};

pub type MultiProof = p3_merkle_tree::PrunedMerklePaths<u8, 32>;
pub type SingleProof = Vec<Digest>;
type Tree<F> = MerkleTree<F, u8, RowMajorMatrix<F>, 2, 32>;
type Upstream<F, S> = MerkleTreeMmcs<
    F,
    u8,
    CanonicalLeafHash<F, <S as HashSuite>::Hasher>,
    NodeHash<<S as HashSuite>::Hasher>,
    2,
    32,
>;

#[derive(Debug, Error)]
pub enum MmcsError {
    #[error("unsupported field or leaf role")]
    InvalidRole,
    #[error("matrix must have positive width and power-of-two height at least two")]
    InvalidDimensions,
    #[error("matrix dimensions overflow")]
    SizeOverflow,
    #[error("opening width or row count does not match the expected dimensions")]
    WrongShape,
    #[error("indices must be nonempty, strictly increasing, and below the tree height")]
    InvalidIndices,
    #[error("prover state belongs to a different suite or leaf configuration")]
    StateMismatch,
    #[error("upstream returned an invalid single-matrix shape")]
    UpstreamShape,
    #[error("Merkle authentication failed: {0}")]
    Authentication(#[from] MerkleTreeError),
}

/// Owns the only retained matrix. Tree internals cannot be mutated by callers.
pub struct MatrixProverData<F: CanonicalField, S: HashSuite> {
    tree: Tree<F>,
    upstream: Upstream<F, S>,
    suite_id: &'static str,
    kind: LeafKind,
}

impl<F: CanonicalField, S: HashSuite> MatrixProverData<F, S> {
    pub fn matrix(&self) -> &RowMajorMatrix<F> {
        self.upstream.get_matrices(&self.tree)[0]
    }
}

#[derive(Clone, Debug)]
pub struct MatrixOpening<F> {
    pub rows: Vec<Vec<F>>,
    pub proof: MultiProof,
}

/// The width and leaf role are trusted configuration, never proof-selected.
#[derive(Clone)]
pub struct CanonicalMmcs<F: CanonicalField, S: HashSuite> {
    upstream: Upstream<F, S>,
    width: usize,
    kind: LeafKind,
}

impl<F: CanonicalField, S: HashSuite> CanonicalMmcs<F, S> {
    pub fn new(suite: S, kind: LeafKind, width: usize) -> Result<Self, MmcsError> {
        let valid_role = matches!(
            (
                F::PROFILE_ID,
                F::COORDINATE_COUNT,
                F::COORDINATE_BYTES,
                kind
            ),
            (1, 1, 8, LeafKind::Base) | (2, 1, 16, _) | (1, 2, 8, LeafKind::Challenge)
        );
        if !valid_role {
            return Err(MmcsError::InvalidRole);
        }
        if width == 0 || (kind == LeafKind::Challenge && width != 1) {
            return Err(MmcsError::InvalidDimensions);
        }
        let coordinate_count = width
            .checked_mul(F::COORDINATE_COUNT)
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(MmcsError::SizeOverflow)?;
        width
            .checked_mul(F::BYTE_WIDTH)
            .ok_or(MmcsError::SizeOverflow)?;
        let leaf = CanonicalLeafHash {
            hasher: suite.hasher(),
            kind,
            coordinate_count,
            marker: PhantomData,
        };
        Ok(Self {
            upstream: MerkleTreeMmcs::new(leaf, NodeHash(suite.hasher()), 0),
            width,
            kind,
        })
    }

    fn dimensions(&self, dimensions: Dimensions) -> Result<(), MmcsError> {
        if dimensions.height < 2 || !dimensions.height.is_power_of_two() || dimensions.width == 0 {
            return Err(MmcsError::InvalidDimensions);
        }
        if dimensions.width != self.width {
            return Err(MmcsError::WrongShape);
        }
        dimensions
            .width
            .checked_mul(dimensions.height)
            .ok_or(MmcsError::SizeOverflow)?;
        Ok(())
    }

    fn state(&self, state: &MatrixProverData<F, S>) -> Result<(), MmcsError> {
        if state.suite_id != S::ID || state.kind != self.kind || state.matrix().width != self.width
        {
            return Err(MmcsError::StateMismatch);
        }
        Ok(())
    }

    pub fn commit(
        &self,
        matrix: RowMajorMatrix<F>,
        execution: &ExecutionContext,
    ) -> Result<(Digest, MatrixProverData<F, S>), MmcsError> {
        // Inspect raw fields first: Matrix::height divides by width.
        if matrix.width == 0 || !matrix.values.len().is_multiple_of(matrix.width) {
            return Err(MmcsError::InvalidDimensions);
        }
        self.dimensions(matrix.dimensions())?;
        let (cap, tree) = execution.install(|| self.upstream.commit_matrix(matrix));
        if cap.num_roots() != 1 || self.upstream.get_matrices(&tree).len() != 1 {
            return Err(MmcsError::UpstreamShape);
        }
        Ok((
            cap[0],
            MatrixProverData {
                tree,
                upstream: self.upstream.clone(),
                suite_id: S::ID,
                kind: self.kind,
            },
        ))
    }

    /// Uses upstream's compact opening interface directly; no local path traversal.
    pub fn open_multi_batch(
        &self,
        indices: &[usize],
        state: &MatrixProverData<F, S>,
    ) -> Result<MatrixOpening<F>, MmcsError> {
        self.state(state)?;
        check_indices(indices, state.matrix().height())?;
        let (values, proof) = self.upstream.open_multi_batch(indices, &state.tree);
        if values.len() != indices.len() {
            return Err(MmcsError::UpstreamShape);
        }
        let rows = values
            .into_iter()
            .map(|mut matrices| {
                if matrices.len() != 1 {
                    return Err(MmcsError::UpstreamShape);
                }
                let row = matrices.pop().ok_or(MmcsError::UpstreamShape)?;
                if row.len() != self.width {
                    return Err(MmcsError::UpstreamShape);
                }
                Ok(row)
            })
            .collect::<Result<_, _>>()?;
        Ok(MatrixOpening { rows, proof })
    }

    /// Borrows owned rows, slices, or fixed arrays (including views of flat scalar values).
    /// Upstream checks exact frontier consumption and authenticates the shared tree once.
    pub fn verify_multi_batch<R: AsRef<[F]>>(
        &self,
        root: &Digest,
        dimensions: Dimensions,
        indices: &[usize],
        rows: &[R],
        proof: &MultiProof,
    ) -> Result<(), MmcsError> {
        self.dimensions(dimensions)?;
        check_indices(indices, dimensions.height)?;
        if rows.len() != indices.len() || rows.iter().any(|row| row.as_ref().len() != self.width) {
            return Err(MmcsError::WrongShape);
        }
        // Borrow field rows; only the upstream query/matrix shape needs small allocations.
        let values: Vec<_> = rows.iter().map(|row| vec![row.as_ref()]).collect();
        self.upstream.verify_multi_batch(
            &MerkleCap::new(vec![*root]),
            &[dimensions],
            indices,
            &values,
            proof,
        )?;
        Ok(())
    }

    /// Checked ordinary paths, useful as a small-instance multiproof reference.
    pub fn open_batch(
        &self,
        index: usize,
        state: &MatrixProverData<F, S>,
    ) -> Result<(Vec<F>, SingleProof), MmcsError> {
        self.state(state)?;
        check_indices(&[index], state.matrix().height())?;
        let mut opening = self.upstream.open_batch(index, &state.tree);
        if opening.opened_values.len() != 1 {
            return Err(MmcsError::UpstreamShape);
        }
        let row = opening
            .opened_values
            .pop()
            .ok_or(MmcsError::UpstreamShape)?;
        Ok((row, opening.opening_proof))
    }

    pub fn verify_batch(
        &self,
        root: &Digest,
        dimensions: Dimensions,
        index: usize,
        row: &[F],
        proof: &SingleProof,
    ) -> Result<(), MmcsError> {
        self.dimensions(dimensions)?;
        check_indices(&[index], dimensions.height)?;
        if row.len() != self.width {
            return Err(MmcsError::WrongShape);
        }
        let rows = vec![row.to_vec()];
        self.upstream.verify_batch(
            &MerkleCap::new(vec![*root]),
            &[dimensions],
            index,
            BatchOpeningRef::new(&rows, proof),
        )?;
        Ok(())
    }
}

fn check_indices(indices: &[usize], height: usize) -> Result<(), MmcsError> {
    if indices.is_empty()
        || indices.last().is_some_and(|&index| index >= height)
        || indices.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(MmcsError::InvalidIndices);
    }
    Ok(())
}
