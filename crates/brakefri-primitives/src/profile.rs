//! Closed field profiles, including their fixed domain conventions.
use thiserror::Error;

pub const GOLDILOCKS_MODULUS: u128 = 18446744069414584321;
pub const F128_MODULUS: u128 = 340282366920938463463374557953744961537;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    GoldilocksQuadratic,
    F128Base,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("unsupported field profile")]
pub struct ProfileError;

impl Profile {
    pub const fn id(self) -> u8 {
        match self {
            Self::GoldilocksQuadratic => 1,
            Self::F128Base => 2,
        }
    }
    pub const fn modulus(self) -> u128 {
        match self {
            Self::GoldilocksQuadratic => GOLDILOCKS_MODULUS,
            Self::F128Base => F128_MODULUS,
        }
    }
    pub const fn challenge_order(self) -> u128 {
        match self {
            Self::GoldilocksQuadratic => GOLDILOCKS_MODULUS * GOLDILOCKS_MODULUS,
            Self::F128Base => F128_MODULUS,
        }
    }
    pub const fn two_adicity(self) -> usize {
        match self {
            Self::GoldilocksQuadratic => 32,
            Self::F128Base => 40,
        }
    }
    pub const fn base_bytes(self) -> usize {
        match self {
            Self::GoldilocksQuadratic => 8,
            Self::F128Base => 16,
        }
    }
}

impl core::str::FromStr for Profile {
    type Err = ProfileError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "goldilocks-quadratic" => Ok(Self::GoldilocksQuadratic),
            "f128-base" => Ok(Self::F128Base),
            _ => Err(ProfileError),
        }
    }
}
