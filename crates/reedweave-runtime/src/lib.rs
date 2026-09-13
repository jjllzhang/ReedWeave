//! Local execution budget shared by upstream DFT, Merkle construction, and authentication.
use rayon::{ThreadPool, ThreadPoolBuilder, prelude::*};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("thread count must be positive")]
    ZeroThreads,
    #[error("could not build local thread pool: {0}")]
    Pool(#[from] rayon::ThreadPoolBuildError),
}

pub struct ExecutionContext {
    pool: ThreadPool,
}

impl ExecutionContext {
    pub fn new(threads: usize) -> Result<Self, ExecutionError> {
        if threads == 0 {
            return Err(ExecutionError::ZeroThreads);
        }
        let pool = ThreadPoolBuilder::new().num_threads(threads).build()?;
        // Initialize the pool before callers start operation timers.
        pool.broadcast(|_| ());
        Ok(Self { pool })
    }

    pub fn threads(&self) -> usize {
        self.pool.current_num_threads()
    }

    pub fn install<R: Send>(&self, operation: impl FnOnce() -> R + Send) -> R {
        self.pool.install(operation)
    }

    /// Authenticate independent trees within the same budget as DFT and tree construction.
    /// The caller decides whether its authentication workload warrants coarse jobs.
    /// Both paths install the pool so any nested upstream parallelism shares this budget.
    /// No jobs outlive this call, including when an authentication fails.
    pub fn try_for_each_tree<E: Send>(
        &self,
        tree_count: usize,
        worthwhile: bool,
        authenticate: impl Fn(usize) -> Result<(), E> + Send + Sync,
    ) -> Result<(), E> {
        self.install(|| {
            if worthwhile && tree_count > 1 && self.threads() > 1 {
                (0..tree_count).into_par_iter().try_for_each(authenticate)
            } else {
                (0..tree_count).try_for_each(authenticate)
            }
        })
    }
}
