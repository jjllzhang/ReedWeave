//! Standalone coefficient-input BrakeFRI. Geometry validation is not a security estimate.
pub mod codec;
mod pcs;
pub use brakefri_primitives::profile::{BaseField, Profile};
use brakefri_primitives::transcript::TranscriptContext;
pub use pcs::{
    BrakeFri, BrakeProof, Commitment, Opening, PcsError, ProverData, Round, ScalarOpening,
};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicParams {
    pub base_field: BaseField,
    pub extension_degree: usize,
    pub log_d: usize,
    pub m: usize,
    pub blowup: usize,
    pub terminal_coefficients: usize,
    pub num_queries: usize,
}

/// Immutable, checked public geometry; no soundness checking is performed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrakeParams {
    pp: PublicParams,
    d: usize,
    domain_size: usize,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ParameterError {
    #[error("unsupported extension degree")]
    UnsupportedExtension,
    #[error("invalid protocol geometry")]
    Geometry,
    #[error("encoding domain exceeds Goldilocks two-adicity")]
    UnsupportedDomain,
    #[error("parameter arithmetic or addressable storage overflow")]
    SizeOverflow,
}

impl BrakeParams {
    pub fn new(pp: PublicParams) -> Result<Self, ParameterError> {
        use ParameterError::*;
        if !matches!(pp.extension_degree, 1 | 2 | 3 | 5) {
            return Err(UnsupportedExtension);
        }
        let shift = u32::try_from(pp.log_d).map_err(|_| SizeOverflow)?;
        let d = 1usize.checked_shl(shift).ok_or(SizeOverflow)?;
        if pp.m == 0 || !d.is_multiple_of(pp.m) || pp.num_queries == 0 {
            return Err(Geometry);
        }
        let k = d / pp.m;
        if k < 2
            || !k.is_power_of_two()
            || pp.blowup < 2
            || !pp.blowup.is_power_of_two()
            || !pp.terminal_coefficients.is_power_of_two()
            || pp.terminal_coefficients > k / 2
        {
            return Err(Geometry);
        }
        let domain_size = pp.blowup.checked_mul(k).ok_or(SizeOverflow)?;
        if domain_size.ilog2() > 32 {
            return Err(UnsupportedDomain);
        }
        let mul = |a: usize, b: usize| {
            a.checked_mul(b)
                .filter(|&v| v <= isize::MAX as usize)
                .ok_or(SizeOverflow)
        };
        let matrix = mul(pp.blowup, d)?;
        mul(matrix, 8)?;
        let width = mul(8, pp.extension_degree)?;
        mul(domain_size, width)?;
        mul(pp.m, width)?
            .checked_add(32)
            .filter(|&v| v <= isize::MAX as usize)
            .ok_or(SizeOverflow)?;
        let nodes = mul(domain_size, 2)?.checked_sub(1).ok_or(SizeOverflow)?;
        mul(nodes, 32)?;
        let queries = mul(pp.num_queries, 2)?;
        let rounds = (k / pp.terminal_coefficients).ilog2() as usize;
        mul(mul(queries, rounds)?, size_of::<usize>())?;
        let openings = queries.min(domain_size);
        let row_bytes = mul(pp.m, 8)?
            .checked_add(size_of::<Vec<u8>>())
            .ok_or(SizeOverflow)?;
        // Conservative bounds include vector framing/headers, not only field payloads.
        let initial_bytes = mul(openings, row_bytes)?;
        let prefix_bytes = mul(pp.m, 8)?
            .checked_add(mul(rounds, 2 * width + 32)?)
            .and_then(|v| v.checked_add(mul(pp.terminal_coefficients, width).ok()?))
            .ok_or(SizeOverflow)?;
        let framing_bytes = mul(openings, 10)?
            .checked_add(mul(rounds, 4 * size_of::<Vec<u8>>() + 40)?)
            .and_then(|v| v.checked_add(128))
            .ok_or(SizeOverflow)?;
        let auth_bytes = mul(
            mul(mul(openings, domain_size.ilog2() as usize)?, rounds)?,
            32,
        )?;
        let scalar_bytes = mul(mul(openings, rounds)?, width)?;
        initial_bytes
            .checked_add(auth_bytes)
            .and_then(|v| v.checked_add(scalar_bytes))
            .and_then(|v| v.checked_add(prefix_bytes))
            .and_then(|v| v.checked_add(framing_bytes))
            .filter(|&v| v <= isize::MAX as usize)
            .ok_or(SizeOverflow)?;
        Ok(Self { pp, d, domain_size })
    }
    pub fn base_field(&self) -> BaseField {
        self.pp.base_field
    }
    pub fn extension_degree(&self) -> usize {
        self.pp.extension_degree
    }
    pub fn log_d(&self) -> usize {
        self.pp.log_d
    }
    pub fn d(&self) -> usize {
        self.d
    }
    pub fn m(&self) -> usize {
        self.pp.m
    }
    pub fn blowup(&self) -> usize {
        self.pp.blowup
    }
    pub fn num_queries(&self) -> usize {
        self.pp.num_queries
    }
    pub fn k(&self) -> usize {
        self.d / self.m()
    }
    pub fn domain_size(&self) -> usize {
        self.domain_size
    }
    pub fn log_domain_size(&self) -> usize {
        self.domain_size.ilog2() as usize
    }
    pub fn rounds(&self) -> usize {
        (self.k() / self.terminal_coefficient_count()).ilog2() as usize
    }
    pub fn terminal_coefficient_count(&self) -> usize {
        self.pp.terminal_coefficients
    }
    pub fn terminal_domain_size(&self) -> usize {
        self.blowup() * self.terminal_coefficient_count()
    }
    pub fn layer_size(&self, j: usize) -> Option<usize> {
        (j <= self.rounds()).then(|| self.domain_size >> j)
    }
    pub fn profile(&self) -> Profile {
        Profile::from_degree(self.extension_degree()).expect("validated degree")
    }
    pub fn transcript_context(&self) -> TranscriptContext {
        TranscriptContext {
            base_field: self.base_field(),
            extension_degree: self.extension_degree(),
            log_d: self.log_d(),
            m: self.m(),
            blowup: self.blowup(),
            terminal_coefficients: self.terminal_coefficient_count(),
            num_queries: self.num_queries(),
        }
    }
}
