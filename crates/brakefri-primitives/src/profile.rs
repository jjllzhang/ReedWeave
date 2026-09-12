//! Closed Goldilocks representations. All encoding domains use the base field.
use thiserror::Error;
pub const GOLDILOCKS_MODULUS: u128 = 18446744069414584321;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BaseField {
    Goldilocks,
}
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("unsupported Goldilocks field representation")]
pub struct ProfileError;
impl core::str::FromStr for BaseField {
    type Err = ProfileError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "goldilocks" => Ok(Self::Goldilocks),
            _ => Err(ProfileError),
        }
    }
}
impl core::fmt::Display for BaseField {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("goldilocks")
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    GoldilocksBase,
    GoldilocksQuadratic,
    GoldilocksCubic,
    GoldilocksQuintic,
}
impl Profile {
    pub const fn from_degree(e: usize) -> Option<Self> {
        match e {
            1 => Some(Self::GoldilocksBase),
            2 => Some(Self::GoldilocksQuadratic),
            3 => Some(Self::GoldilocksCubic),
            5 => Some(Self::GoldilocksQuintic),
            _ => None,
        }
    }
    pub const fn extension_degree(self) -> usize {
        match self {
            Self::GoldilocksBase => 1,
            Self::GoldilocksQuadratic => 2,
            Self::GoldilocksCubic => 3,
            Self::GoldilocksQuintic => 5,
        }
    }
    pub const fn id(self) -> u8 {
        self.extension_degree() as u8
    }
    pub const fn representation(self) -> &'static [u8] {
        match self {
            Self::GoldilocksBase => b"goldilocks",
            Self::GoldilocksQuadratic => b"goldilocks:x^2-7",
            Self::GoldilocksCubic => b"goldilocks:x^3-x-1",
            Self::GoldilocksQuintic => b"goldilocks:x^5-3",
        }
    }
    pub const fn modulus(self) -> u128 {
        GOLDILOCKS_MODULUS
    }
    pub const fn two_adicity(self) -> usize {
        32
    }
    pub const fn base_bytes(self) -> usize {
        8
    }
}
