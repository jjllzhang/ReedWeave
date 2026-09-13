//! Canonical coordinates shared by the transcript, Merkle leaves, and proof codecs.

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

macro_rules! extension_encoding {
    ($field:ty, $degree:expr, $bytes:expr) => {
        impl CanonicalField for $field {
            type Bytes = [u8; $bytes];
            const PROFILE_ID: u8 = 1;
            const COORDINATE_COUNT: usize = $degree;
            const COORDINATE_BYTES: usize = 8;
            fn to_canonical_bytes(&self) -> Self::Bytes {
                let coordinates: &[Goldilocks] = self.as_basis_coefficients_slice();
                let mut bytes = [0; $bytes];
                for (chunk, coordinate) in bytes.chunks_exact_mut(8).zip(coordinates) {
                    chunk.copy_from_slice(&coordinate.to_canonical_bytes());
                }
                bytes
            }
            fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CanonicalEncodingError> {
                let bytes = fixed::<$bytes>(bytes)?;
                let mut coordinates = [Goldilocks::new(0); $degree];
                for (coordinate, chunk) in coordinates.iter_mut().zip(bytes.chunks_exact(8)) {
                    *coordinate = Goldilocks::from_canonical_bytes(chunk)?;
                }
                Ok(Self::from_basis_coefficients_fn(|i| coordinates[i]))
            }
        }
    };
}
pub type GoldilocksCubic = p3_field::extension::CubicTrinomialExtensionField<Goldilocks>;
pub type GoldilocksQuintic = p3_field::extension::BinomialExtensionField<Goldilocks, 5>;
extension_encoding!(GoldilocksQuadratic, 2, 16);
extension_encoding!(GoldilocksCubic, 3, 24);
extension_encoding!(GoldilocksQuintic, 5, 40);
