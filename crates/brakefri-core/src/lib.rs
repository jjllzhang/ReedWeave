//! BrakeFRI public parameters. Coefficient PCS operations follow in M2.
pub use brakefri_primitives::profile::Profile;
use num_bigint::BigUint;
use thiserror::Error;

pub const M: usize = 1024;
pub const B: usize = 2;
pub const Q: usize = 244;

/// Validated geometry and exact interactive soundness parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrakeParams {
    profile: Profile,
    log_n: usize,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ParameterError {
    #[error("log_n must be in 11..=30")]
    UnsupportedSize,
    #[error("m, blowup, and num_queries must be 1024, 2, and 244")]
    FixedParameters,
    #[error("parameters fail exact 100-bit interactive soundness checks")]
    Soundness,
}

impl BrakeParams {
    pub fn new(profile: Profile, log_n: usize) -> Result<Self, ParameterError> {
        Self::with_fixed_values(profile, log_n, M, B, Q)
    }

    pub fn with_fixed_values(
        profile: Profile,
        log_n: usize,
        m: usize,
        blowup: usize,
        queries: usize,
    ) -> Result<Self, ParameterError> {
        if !(11..=30).contains(&log_n) {
            return Err(ParameterError::UnsupportedSize);
        }
        if (m, blowup, queries) != (M, B, Q) {
            return Err(ParameterError::FixedParameters);
        }
        let params = Self { profile, log_n };
        let q = BigUint::from(profile.challenge_order());
        let a = BigUint::from(params.algebraic_numerator());
        let three_q = BigUint::from(3u8).pow(Q as u32);
        let four_q = BigUint::from(4u8).pow(Q as u32);
        if (&a << 101usize) > q
            || (&three_q << 101usize) > four_q
            || ((&three_q * &q + &a * &four_q) << 100usize) > &four_q * &q
        {
            return Err(ParameterError::Soundness);
        }
        Ok(params)
    }

    pub fn from_coefficient_count(profile: Profile, n: usize) -> Result<Self, ParameterError> {
        if !n.is_power_of_two() {
            return Err(ParameterError::UnsupportedSize);
        }
        Self::new(profile, n.ilog2() as usize)
    }
    pub const fn profile(&self) -> Profile {
        self.profile
    }
    pub const fn log_n(&self) -> usize {
        self.log_n
    }
    pub const fn n(&self) -> usize {
        1usize << self.log_n
    }
    pub const fn m(&self) -> usize {
        M
    }
    pub const fn blowup(&self) -> usize {
        B
    }
    pub const fn num_queries(&self) -> usize {
        Q
    }
    pub const fn rounds(&self) -> usize {
        self.log_n - 10
    }
    pub const fn k(&self) -> usize {
        1usize << self.rounds()
    }
    pub const fn domain_size(&self) -> usize {
        B * self.k()
    }
    pub const fn log_domain_size(&self) -> usize {
        self.rounds() + 1
    }
    pub const fn algebraic_numerator(&self) -> usize {
        4 * self.k() + self.rounds() - 1
    }
    pub fn layer_size(&self, round: usize) -> Option<usize> {
        (round <= self.rounds()).then(|| self.domain_size() >> round)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_supported_exact_bounds_and_geometry() {
        assert_eq!(
            Profile::GoldilocksQuadratic.challenge_order(),
            340282366762482138490186164457219031041
        );
        assert_eq!(
            Profile::F128Base.challenge_order(),
            340282366920938463463374557953744961537
        );
        for profile in [Profile::GoldilocksQuadratic, Profile::F128Base] {
            for d in 11..=30 {
                let p = BrakeParams::new(profile, d).unwrap();
                assert_eq!(p.m() * p.domain_size(), 2 * p.n());
                assert_eq!(p.layer_size(p.rounds()), Some(2));
                assert_eq!(p.layer_size(p.rounds() + 1), None);
                assert!(p.log_domain_size() <= profile.two_adicity());
                assert_eq!(p.num_queries(), 244);
                // Independent unsimplified numerator from the theorem.
                assert_eq!(
                    p.algebraic_numerator(),
                    2 * p.domain_size() - (p.domain_size() >> p.rounds()) + p.rounds() + 1
                );
            }
            assert_eq!(
                BrakeParams::new(profile, 30).unwrap().algebraic_numerator(),
                (1 << 22) + 19
            );
        }
    }
    #[test]
    fn invalid_configuration() {
        let profile = Profile::F128Base;
        for d in [0, 10, 31, usize::MAX] {
            assert!(BrakeParams::new(profile, d).is_err());
        }
        for n in [0, 1, 2047, 2049, usize::MAX] {
            assert!(BrakeParams::from_coefficient_count(profile, n).is_err());
        }
        for (m, b, q) in [(1, 2, 244), (1024, 4, 244), (1024, 2, 243)] {
            assert_eq!(
                BrakeParams::with_fixed_values(profile, 20, m, b, q),
                Err(ParameterError::FixedParameters)
            );
        }
        assert!("unknown".parse::<Profile>().is_err());
    }
}
