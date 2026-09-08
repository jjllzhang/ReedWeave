//! Algebraic checks for the new challenge field. These are not benchmarks.
use num_bigint::BigUint;
use p3_f128_adapter::{F128, F128Quadratic as EF};
use p3_field::{
    BasedVectorSpace, Field, PrimeCharacteristicRing, TwoAdicField, extension::HasFrobenius,
};

fn power(mut base: EF, exponent: &BigUint) -> EF {
    let mut result = EF::ONE;
    for i in 0..exponent.bits() {
        if exponent.bit(i) {
            result *= base;
        }
        base = base.square();
    }
    result
}
fn element(a: u128, b: u128) -> EF {
    EF::from_basis_coefficients_fn(|i| F128::new(if i == 0 { a } else { b }))
}

#[test]
fn irreducibility_frobenius_and_inverse_agree_with_field_order() {
    let u = element(0, 1);
    let p = F128::order();
    assert_eq!(u.square(), EF::from(F128::new(3)));
    assert_eq!(power(u, &p), -u);
    for x in [u, element(8, 1), element(F128::MODULUS - 1, 17)] {
        assert_eq!(power(x, &p), x.frobenius());
        assert_eq!(x.frobenius().frobenius(), x);
        assert_eq!(x * x.inverse(), EF::ONE);
        assert_eq!(x.inverse(), power(x, &(EF::order() - 2u32)));
        let coordinates: &[F128] = x.as_basis_coefficients_slice();
        let norm = coordinates[0].square() - F128::new(3) * coordinates[1].square();
        assert_eq!(x * x.frobenius(), EF::from(norm));
    }
    assert_eq!(EF::ZERO.try_inverse(), None);
}

#[test]
fn generator_has_full_order_and_two_adic_roots_extend_base_roots() {
    let factors: [u128; 10] = [
        2,
        3,
        7,
        29,
        181,
        286619,
        11394379,
        18053749339,
        307247047,
        26369532909343800824333805787,
    ];
    let order = EF::order() - 1u32;
    let mut remaining = order.clone();
    for factor in factors {
        let factor = BigUint::from(factor);
        assert_ne!(power(EF::GENERATOR, &(&order / &factor)), EF::ONE);
        while &remaining % &factor == BigUint::from(0u32) {
            remaining /= &factor;
        }
    }
    assert_eq!(remaining, BigUint::from(1u32));
    assert_eq!(power(EF::GENERATOR, &order), EF::ONE);
    for bits in 0..=41 {
        let root = EF::two_adic_generator(bits);
        assert_eq!(root.exp_power_of_2(bits), EF::ONE);
        if bits > 0 {
            assert_eq!(root.exp_power_of_2(bits - 1), EF::NEG_ONE);
            assert_eq!(root.square(), EF::two_adic_generator(bits - 1));
        }
        if bits <= 40 {
            assert_eq!(root, EF::from(F128::two_adic_generator(bits)));
        }
    }
}

#[test]
fn encoding_rejects_noncanonical_extension_coordinates() {
    let value = element(3, 7);
    let bytes = postcard::to_allocvec(&value).unwrap();
    assert_eq!(bytes.len(), 32);
    assert_eq!(postcard::from_bytes::<EF>(&bytes).unwrap(), value);
    for index in 0..2 {
        let mut bad = bytes.clone();
        bad[index * 16..(index + 1) * 16].copy_from_slice(&F128::MODULUS.to_le_bytes());
        assert!(postcard::from_bytes::<EF>(&bad).is_err());
    }
}
