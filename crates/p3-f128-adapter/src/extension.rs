//! Quadratic challenge field F128[u]/(u² - 3).
use p3_field::extension::{
    Binomial, BinomialExtensionField, BinomiallyExtendable, ExtensionAlgebra,
    HasTwoAdicBinomialExtension, binomial_mul, binomial_square,
};
use p3_field::{PrimeCharacteristicRing, TwoAdicField};

use crate::F128;

pub type F128Quadratic = BinomialExtensionField<F128, 2>;

impl ExtensionAlgebra<Self, 2, Binomial<Self>> for F128 {
    #[inline]
    fn ext_mul(a: &[Self; 2], b: &[Self; 2], res: &mut [Self; 2]) {
        binomial_mul::<Self, Self, Self, 2>(a, b, res, Self::W);
    }

    #[inline]
    fn ext_square(a: &[Self; 2], res: &mut [Self; 2]) {
        binomial_square::<Self, Self, 2>(a, res, Self::W);
    }
}

impl BinomiallyExtendable<2> for F128 {
    // Euler's criterion: 3^((p-1)/2) = -1, hence u²-3 is irreducible.
    const W: Self = Self::new(3);
    const DTH_ROOT: Self = Self::NEG_ONE;
    // The distinct prime divisors of p²-1 are:
    // 2, 3, 7, 29, 181, 286619, 11394379, 18053749339,
    // 307247047, 26369532909343800824333805787.
    // For each divisor l, (8+u)^((p²-1)/l) != 1.
    const EXT_GENERATOR: [Self; 2] = [Self::new(8), Self::ONE];
}

impl HasTwoAdicBinomialExtension<2> for F128 {
    const EXT_TWO_ADICITY: usize = 41;

    fn ext_two_adic_generator(bits: usize) -> [Self; 2] {
        assert!(bits <= Self::EXT_TWO_ADICITY);
        if bits == 41 {
            // u^((p-1)/2^40); its square is the adapter's existing 2^40 root.
            [
                Self::ZERO,
                Self::new(255115544884160683561328857874059708585),
            ]
        } else {
            [Self::two_adic_generator(bits), Self::ZERO]
        }
    }
}
