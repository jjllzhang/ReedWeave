//! Canonical coordinates shared by the transcript, Merkle leaves, and proof codecs.

pub use p3_f128_adapter::F128;
use p3_field::{BasedVectorSpace, Field, PackedValue, PrimeField64};
pub use p3_goldilocks::Goldilocks;
use thiserror::Error;

pub type GoldilocksQuadratic = p3_field::extension::BinomialExtensionField<Goldilocks, 2>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CanonicalEncodingError {
    #[error("expected {expected} field bytes, got {actual}")]
    WrongLength { expected: usize, actual: usize },
    #[error("field coordinate is not a canonical representative")]
    NonCanonical,
}

/// Fixed little-endian base coordinates, in constant-then-u order for the quadratic.
/// Decoding rejects representatives at least the modulus; it never reduces them.
pub trait CanonicalField: Field + PackedValue<Value = Self> {
    type Bytes: AsRef<[u8]> + IntoIterator<Item = u8>;
    const PROFILE_ID: u8;
    const COORDINATE_COUNT: usize;
    const COORDINATE_BYTES: usize;
    const BYTE_WIDTH: usize = Self::COORDINATE_COUNT * Self::COORDINATE_BYTES;

    fn to_canonical_bytes(&self) -> Self::Bytes;
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CanonicalEncodingError>;
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], CanonicalEncodingError> {
    bytes
        .try_into()
        .map_err(|_| CanonicalEncodingError::WrongLength {
            expected: N,
            actual: bytes.len(),
        })
}

impl CanonicalField for Goldilocks {
    type Bytes = [u8; 8];
    const PROFILE_ID: u8 = 1;
    const COORDINATE_COUNT: usize = 1;
    const COORDINATE_BYTES: usize = 8;

    fn to_canonical_bytes(&self) -> Self::Bytes {
        self.as_canonical_u64().to_le_bytes()
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CanonicalEncodingError> {
        let value = u64::from_le_bytes(fixed(bytes)?);
        if value >= Self::ORDER_U64 {
            return Err(CanonicalEncodingError::NonCanonical);
        }
        Ok(Self::new(value))
    }
}

impl CanonicalField for GoldilocksQuadratic {
    type Bytes = [u8; 16];
    const PROFILE_ID: u8 = 1;
    const COORDINATE_COUNT: usize = 2;
    const COORDINATE_BYTES: usize = 8;

    fn to_canonical_bytes(&self) -> Self::Bytes {
        let coordinates: &[Goldilocks] = self.as_basis_coefficients_slice();
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&coordinates[0].to_canonical_bytes());
        bytes[8..].copy_from_slice(&coordinates[1].to_canonical_bytes());
        bytes
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CanonicalEncodingError> {
        let bytes = fixed::<16>(bytes)?;
        let coordinates = [
            Goldilocks::from_canonical_bytes(&bytes[..8])?,
            Goldilocks::from_canonical_bytes(&bytes[8..])?,
        ];
        Ok(Self::from_basis_coefficients_fn(|i| coordinates[i]))
    }
}

impl CanonicalField for F128 {
    type Bytes = [u8; 16];
    const PROFILE_ID: u8 = 2;
    const COORDINATE_COUNT: usize = 1;
    const COORDINATE_BYTES: usize = 16;

    fn to_canonical_bytes(&self) -> Self::Bytes {
        self.to_le_bytes()
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CanonicalEncodingError> {
        F128::from_le_bytes(fixed(bytes)?).map_err(|_| CanonicalEncodingError::NonCanonical)
    }
}
