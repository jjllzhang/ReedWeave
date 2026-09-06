//! Local execution budget shared by upstream DFT and Merkle construction.
use rayon::{ThreadPool, ThreadPoolBuilder};
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
}
