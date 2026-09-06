use brakefri_primitives::fields::{Goldilocks, GoldilocksQuadratic};
use num_bigint::BigUint;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField, TwoAdicField};

#[test]
fn every_goldilocks_root_matches_fixed_profile() {
    let root = Goldilocks::new(0x185629dcda58878c);
    assert_eq!(Goldilocks::TWO_ADICITY, 32);
    let modulus = BigUint::from(18446744069414584321u64);
    let fixed_root = BigUint::from(0x185629dcda58878cu64);
    for bits in 0..=32 {
        let w = Goldilocks::two_adic_generator(bits);
        let expected = fixed_root.modpow(&(BigUint::from(1u8) << (32 - bits)), &modulus);
        assert_eq!(w.as_canonical_biguint(), expected);
        assert_eq!(
            expected.modpow(&(BigUint::from(1u8) << bits), &modulus),
            BigUint::from(1u8)
        );
        if bits > 0 {
            assert_eq!(
                expected.modpow(&(BigUint::from(1u8) << (bits - 1)), &modulus),
                &modulus - 1u8
            );
        }
        assert_eq!(w, root.exp_power_of_2(32 - bits));
        assert_eq!(w.exp_power_of_2(bits), Goldilocks::ONE);
        if bits > 0 {
            assert_ne!(w.exp_power_of_2(bits - 1), Goldilocks::ONE);
            assert_eq!(w.square(), Goldilocks::two_adic_generator(bits - 1));
        }
    }
    let u =
        GoldilocksQuadratic::from_basis_coefficients_slice(&[Goldilocks::ZERO, Goldilocks::ONE])
            .unwrap();
    assert_eq!(
        u.square(),
        GoldilocksQuadratic::from(Goldilocks::from_u8(7))
    );
}
