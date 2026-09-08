//! The prime field `F_p`, where `p = 2^128 - 45 * 2^40 + 1`, for Plonky3.
//!
//! Arithmetic delegates to Winterfell's portable F128 backend. Packing is scalar,
//! and P3's blanket implementations supply the degree-one extension and vector
//! space traits. Every wire coordinate is exactly 16 canonical little-endian bytes,
//! including Serde representations. Integer quotient maps reduce modulo `p`;
//! decoding and checked canonical conversions reject out-of-range representatives.

mod extension;
pub use extension::F128Quadratic;

use core::cmp::Ordering;
use core::fmt::{self, Debug, Display, Formatter};
use core::hash::{Hash, Hasher};
use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use num_bigint::BigUint;
use p3_field::integers::QuotientMap;
use p3_field::{
    Field, Packable, PrimeCharacteristicRing, PrimeField, RawDataSerializable, TwoAdicField,
    quotient_map_small_int,
};
use rand::Rng;
use rand::distr::{Distribution, StandardUniform};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use winter_math::{FieldElement, StarkField, fields::f128::BaseElement};

/// A canonical Winterfell field element with Plonky3 traits.
///
/// The backend is private so neither unchecked byte casts nor backend Serde can
/// bypass the adapter's canonical decoding. Arithmetic does not allocate.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[repr(transparent)]
#[must_use]
pub struct F128(BaseElement);

/// Invalid canonical F128 input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// A field coordinate must occupy exactly 16 bytes.
    #[error("F128 encoding must contain 16 bytes, received {actual}")]
    InvalidLength { actual: usize },
    /// A representative at least the modulus is not canonical.
    #[error("F128 representative is greater than or equal to the modulus")]
    NonCanonical,
}

impl F128 {
    /// The exact field order, `2^128 - 45 * 2^40 + 1`.
    pub const MODULUS: u128 = 340282366920938463463374557953744961537;
    /// The fixed generator of the subgroup of order `2^40`.
    pub const TWO_ADIC_ROOT_OF_UNITY: Self = Self::new(23953097886125630542083529559205016746);

    /// Construct an element, reducing any `u128` modulo the field order.
    #[inline]
    pub const fn new(value: u128) -> Self {
        Self(BaseElement::new(value))
    }

    /// Return the unique integer representative in `[0, p)`.
    #[inline]
    pub fn as_canonical_u128(&self) -> u128 {
        self.0.as_int()
    }

    /// Encode the canonical representative in exactly 16 little-endian bytes.
    #[inline]
    pub fn to_le_bytes(self) -> [u8; 16] {
        self.as_canonical_u128().to_le_bytes()
    }

    /// Decode one canonical coordinate, rejecting representatives at least `p`.
    #[inline]
    pub fn from_le_bytes(bytes: [u8; 16]) -> Result<Self, DecodeError> {
        Self::try_from(u128::from_le_bytes(bytes))
    }
}

impl TryFrom<u128> for F128 {
    type Error = DecodeError;

    #[inline]
    fn try_from(value: u128) -> Result<Self, Self::Error> {
        if value < Self::MODULUS {
            Ok(Self::new(value))
        } else {
            Err(DecodeError::NonCanonical)
        }
    }
}

impl TryFrom<&[u8]> for F128 {
    type Error = DecodeError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes = bytes.try_into().map_err(|_| DecodeError::InvalidLength {
            actual: bytes.len(),
        })?;
        Self::from_le_bytes(bytes)
    }
}

impl Serialize for F128 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_le_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for F128 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = <[u8; 16]>::deserialize(deserializer)?;
        Self::from_le_bytes(bytes).map_err(serde::de::Error::custom)
    }
}

impl Hash for F128 {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_canonical_u128().hash(state);
    }
}

impl Ord for F128 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_canonical_u128().cmp(&other.as_canonical_u128())
    }
}

impl PartialOrd for F128 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for F128 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.as_canonical_u128(), f)
    }
}

impl Debug for F128 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.as_canonical_u128(), f)
    }
}

impl Packable for F128 {}

impl PrimeCharacteristicRing for F128 {
    type PrimeSubfield = Self;

    const ZERO: Self = Self::new(0);
    const ONE: Self = Self::new(1);
    const TWO: Self = Self::new(2);
    const NEG_ONE: Self = Self::new(Self::MODULUS - 1);

    #[inline]
    fn from_prime_subfield(f: Self) -> Self {
        f
    }

    #[inline]
    fn halve(&self) -> Self {
        // Avoid overflowing x + p for odd x near the modulus.
        let x = self.as_canonical_u128();
        Self::new((x >> 1) + (x & 1) * ((Self::MODULUS >> 1) + 1))
    }
}

impl RawDataSerializable for F128 {
    const NUM_BYTES: usize = 16;

    #[inline]
    fn into_bytes(self) -> impl IntoIterator<Item = u8> {
        self.to_le_bytes()
    }

    #[inline]
    fn into_parallel_byte_streams<const N: usize>(
        input: impl IntoIterator<Item = [Self; N]>,
    ) -> impl IntoIterator<Item = [u8; N]> {
        input.into_iter().flat_map(|values| {
            let bytes = values.map(Self::to_le_bytes);
            (0..16).map(move |i| core::array::from_fn(|j| bytes[j][i]))
        })
    }
}

impl Field for F128 {
    type Packing = Self;

    const GENERATOR: Self = Self::new(3);

    #[inline]
    fn try_inverse(&self) -> Option<Self> {
        // Winterfell defines inv(0) = 0; P3 requires None instead.
        (!self.is_zero()).then(|| Self(self.0.inv()))
    }

    fn order() -> BigUint {
        Self::MODULUS.into()
    }

    fn try_sqrt(&self) -> Option<Self> {
        p3_field::tonelli_shanks_two_adic(*self)
    }
}

impl PrimeField for F128 {
    fn as_canonical_biguint(&self) -> BigUint {
        self.as_canonical_u128().into()
    }
}

impl TwoAdicField for F128 {
    const TWO_ADICITY: usize = 40;

    /// Return `G^(2^(40 - bits))` for the fixed profile root `G`.
    ///
    /// # Panics
    /// Panics when `bits > 40`.
    fn two_adic_generator(bits: usize) -> Self {
        assert!(
            bits <= Self::TWO_ADICITY,
            "F128 supports at most 40 two-adic bits"
        );
        Self::TWO_ADIC_ROOT_OF_UNITY.exp_power_of_2(Self::TWO_ADICITY - bits)
    }
}

quotient_map_small_int!(F128, u128, [u8, u16, u32, u64]);
quotient_map_small_int!(F128, i128, [i8, i16, i32, i64]);
// P3 supplies usize/isize quotient maps from these fixed-width implementations.

impl QuotientMap<u128> for F128 {
    #[inline]
    fn from_int(int: u128) -> Self {
        Self::new(int)
    }

    #[inline]
    fn from_canonical_checked(int: u128) -> Option<Self> {
        Self::try_from(int).ok()
    }

    #[inline]
    unsafe fn from_canonical_unchecked(int: u128) -> Self {
        Self::new(int)
    }
}

impl QuotientMap<i128> for F128 {
    #[inline]
    fn from_int(int: i128) -> Self {
        let magnitude = Self::new(int.unsigned_abs());
        if int < 0 { -magnitude } else { magnitude }
    }

    #[inline]
    fn from_canonical_checked(int: i128) -> Option<Self> {
        (int.unsigned_abs() <= Self::MODULUS / 2).then(|| Self::from_int(int))
    }

    #[inline]
    unsafe fn from_canonical_unchecked(int: i128) -> Self {
        Self::from_int(int)
    }
}

impl Distribution<F128> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> F128 {
        loop {
            let lo = u128::from(rng.next_u64());
            let hi = u128::from(rng.next_u64());
            if let Ok(value) = F128::try_from(lo | (hi << 64)) {
                return value;
            }
        }
    }
}

macro_rules! backend_operator {
    ($trait:ident, $method:ident, $assign_trait:ident, $assign_method:ident, $op:tt) => {
        impl $trait for F128 {
            type Output = Self;

            #[inline]
            fn $method(self, rhs: Self) -> Self {
                Self(self.0 $op rhs.0)
            }
        }

        impl $assign_trait for F128 {
            #[inline]
            fn $assign_method(&mut self, rhs: Self) {
                *self = *self $op rhs;
            }
        }
    };
}

backend_operator!(Add, add, AddAssign, add_assign, +);
backend_operator!(Sub, sub, SubAssign, sub_assign, -);
backend_operator!(Mul, mul, MulAssign, mul_assign, *);

impl Neg for F128 {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        Self(-self.0)
    }
}

impl Div for F128 {
    type Output = Self;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self {
        // Use P3's zero check rather than Winterfell's zero-valued division by zero.
        self * rhs.inverse()
    }
}

impl DivAssign for F128 {
    #[inline]
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

impl Sum for F128 {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |acc, x| acc + x)
    }
}

impl<'a> Sum<&'a Self> for F128 {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.copied().sum()
    }
}

impl Product for F128 {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ONE, |acc, x| acc * x)
    }
}

impl<'a> Product<&'a Self> for F128 {
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.copied().product()
    }
}
