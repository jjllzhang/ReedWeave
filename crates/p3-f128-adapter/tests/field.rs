use core::convert::Infallible;

use num_bigint::BigUint;
use p3_f128_adapter::{DecodeError, F128};
use p3_field::integers::QuotientMap;
use p3_field::{
    BasedVectorSpace, ExtensionField, Field, PackedField, PackedFieldExtension, PackedFieldPow2,
    PackedValue, PrimeCharacteristicRing, PrimeField, RawDataSerializable, TwoAdicField,
};
use rand::distr::{Distribution, StandardUniform};
use rand::{RngExt, SeedableRng, TryRng, rngs::StdRng};
use winter_math::{StarkField, fields::f128::BaseElement};

// Independent literal: an accidental adapter modulus change must fail the tests.
const P: u128 = 340282366920938463463374557953744961537;
const ROOT: u128 = 23953097886125630542083529559205016746;

fn fixtures() -> Vec<u128> {
    let mut values = vec![
        0,
        1,
        2,
        3,
        P / 2,
        P / 2 + 1,
        P - 2,
        P - 1,
        P,
        P + 1,
        u128::MAX,
    ];
    // Exercise carries at every bit, especially the backend's 64-bit limb boundaries.
    for bit in 1..128 {
        let x = 1u128 << bit;
        values.extend([x - 1, x, x + 1]);
    }
    let mut rng = StdRng::seed_from_u64(0x128b_12af_2026);
    values.extend((0..512).map(|_| rng.random::<u128>()));
    values
}

fn check_pair(a: u128, b: u128) {
    let p = BigUint::from(P);
    let aa = BigUint::from(a) % &p;
    let bb = BigUint::from(b) % &p;
    let x = F128::new(a);
    let y = F128::new(b);
    assert_eq!(
        (x + y).as_canonical_biguint(),
        (&aa + &bb) % &p,
        "add {a}, {b}"
    );
    assert_eq!(
        (x - y).as_canonical_biguint(),
        (&aa + &p - &bb) % &p,
        "sub {a}, {b}"
    );
    assert_eq!(
        (x * y).as_canonical_biguint(),
        (&aa * &bb) % &p,
        "mul {a}, {b}"
    );
    let mut assigned = x;
    assigned += y;
    assert_eq!(assigned, x + y);
    assigned -= y;
    assert_eq!(assigned, x);
    assigned *= y;
    assert_eq!(assigned, x * y);
    if y != F128::ZERO {
        let inv = bb.modpow(&(&p - BigUint::from(2u8)), &p);
        assert_eq!(
            (x / y).as_canonical_biguint(),
            (&aa * inv) % &p,
            "div {a}, {b}"
        );
        assigned /= y;
        assert_eq!(assigned, x);
    }
}

#[test]
fn wide_arithmetic_matches_biguint() {
    let values = fixtures();
    let edges = [
        0,
        1,
        2,
        u64::MAX as u128,
        1 << 64,
        1 << 127,
        P / 2,
        P - 1,
        u128::MAX,
    ];
    for &a in &edges {
        for &b in &edges {
            check_pair(a, b);
        }
    }
    let p = BigUint::from(P);
    let half = BigUint::from((P >> 1) + 1);
    for (i, &a) in values.iter().enumerate() {
        check_pair(a, values[(i * 137 + 31) % values.len()]);
        let x = F128::new(a);
        let aa = BigUint::from(a) % &p;
        assert_eq!(x.as_canonical_biguint(), aa);
        assert_eq!((-x).as_canonical_biguint(), (&p - &aa) % &p);
        assert_eq!(x.halve().as_canonical_biguint(), (&aa * &half) % &p);
        assert_eq!(x.double().as_canonical_biguint(), (&aa * 2u8) % &p);
        assert_eq!(x.square().as_canonical_biguint(), (&aa * &aa) % &p);
        if a % P != 0 {
            assert_eq!(
                x.inverse().as_canonical_biguint(),
                aa.modpow(&(&p - 2u8), &p)
            );
        }
    }
    assert_eq!(F128::ZERO.try_inverse(), None);
    let inputs: Vec<_> = values.iter().copied().map(F128::new).collect();
    let sum = values
        .iter()
        .fold(BigUint::from(0u8), |acc, &a| (acc + a) % &p);
    let product = values
        .iter()
        .filter(|&&a| a % P != 0)
        .fold(BigUint::from(1u8), |acc, &a| (acc * a) % &p);
    assert_eq!(inputs.iter().sum::<F128>().as_canonical_biguint(), sum);
    assert_eq!(
        inputs
            .iter()
            .filter(|x| !x.is_zero())
            .product::<F128>()
            .as_canonical_biguint(),
        product
    );
    assert_eq!(core::iter::empty::<F128>().sum::<F128>(), F128::ZERO);
    assert_eq!(core::iter::empty::<F128>().product::<F128>(), F128::ONE);
}

#[test]
fn fixed_roots_have_exact_orders_and_match_biguint() {
    assert_eq!(F128::MODULUS, P);
    assert_eq!(F128::order(), BigUint::from(P));
    assert_eq!(F128::bits(), 128);
    assert_eq!((P - 1).trailing_zeros(), 40);
    assert_eq!(F128::TWO_ADICITY, 40);
    assert_eq!(F128::GENERATOR.as_canonical_u128(), 3);
    assert_eq!(BaseElement::MODULUS, P);
    assert_eq!(BaseElement::GENERATOR.as_int(), 3);
    assert_eq!(BaseElement::TWO_ADICITY, 40);
    assert_eq!(BaseElement::TWO_ADIC_ROOT_OF_UNITY.as_int(), ROOT);
    let p = BigUint::from(P);
    let root = BigUint::from(ROOT);
    assert_eq!(
        BigUint::from(3u8).modpow(&BigUint::from((P - 1) >> 40), &p),
        root
    );
    assert_eq!(F128::TWO_ADIC_ROOT_OF_UNITY.as_canonical_biguint(), root);
    for bits in 0..=40 {
        let g = F128::two_adic_generator(bits);
        let expected = root.modpow(&(BigUint::from(1u8) << (40 - bits)), &p);
        assert_eq!(
            g.as_canonical_biguint(),
            expected,
            "root convention at {bits}"
        );
        let order = BigUint::from(1u8) << bits;
        assert_eq!(expected.modpow(&order, &p), BigUint::from(1u8));
        assert_eq!(g.exp_power_of_2(bits), F128::ONE);
        if bits > 0 {
            assert_eq!(expected.modpow(&(order >> 1), &p), &p - 1u8);
            assert_eq!(g.exp_power_of_2(bits - 1), F128::NEG_ONE);
            assert_eq!(g.square(), F128::two_adic_generator(bits - 1));
        }
    }
}

#[test]
#[should_panic(expected = "at most 40")]
fn unsupported_root_is_rejected() {
    let _ = F128::two_adic_generator(41);
}

#[test]
#[should_panic(expected = "Tried to invert zero")]
fn division_by_zero_follows_p3_contract() {
    let _ = F128::ONE / F128::ZERO;
}

#[test]
fn square_roots_and_exponentiation() {
    assert_eq!(F128::ZERO.try_sqrt(), Some(F128::ZERO));
    assert_eq!(F128::GENERATOR.try_sqrt(), None);
    let p = BigUint::from(P);
    for a in fixtures().into_iter().step_by(13) {
        let x = F128::new(a);
        let square = x.square();
        assert_eq!(square.try_sqrt().unwrap().square(), square);
        for power in [0, 1, 2, 3, 40, 127, u64::MAX] {
            assert_eq!(
                x.exp_u64(power).as_canonical_biguint(),
                BigUint::from(a).modpow(&BigUint::from(power), &p)
            );
        }
    }
}

#[test]
fn integer_quotient_maps_and_checked_boundaries() {
    for a in fixtures() {
        assert_eq!(F128::from_u128(a), F128::new(a));
        assert_eq!(
            F128::from_canonical_checked(a),
            (a < P).then(|| F128::new(a))
        );
        assert_eq!(F128::try_from(a).ok(), F128::from_canonical_checked(a));
    }
    let bound = (P / 2) as i128;
    let p = BigUint::from(P);
    for a in [
        i128::MIN,
        -bound - 1,
        -bound,
        -1,
        0,
        1,
        bound,
        bound + 1,
        i128::MAX,
    ] {
        let magnitude = BigUint::from(a.unsigned_abs()) % &p;
        let expected = if a < 0 {
            (&p - magnitude) % &p
        } else {
            magnitude
        };
        assert_eq!(F128::from_i128(a).as_canonical_biguint(), expected);
        assert_eq!(
            F128::from_canonical_checked(a).is_some(),
            a >= -bound && a <= bound
        );
    }
    macro_rules! unsigned {
        ($($t:ty),*) => {$({
            for x in [0, 1, <$t>::MAX] {
                assert_eq!(<F128 as QuotientMap<$t>>::from_int(x), F128::new(x as u128));
                assert_eq!(<F128 as QuotientMap<$t>>::from_canonical_checked(x), Some(F128::new(x as u128)));
                // SAFETY: these small unsigned types lie entirely below p.
                assert_eq!(unsafe { <F128 as QuotientMap<$t>>::from_canonical_unchecked(x) }, F128::new(x as u128));
            }
        })*};
    }
    macro_rules! signed {
        ($($t:ty),*) => {$({
            for x in [<$t>::MIN, -1, 0, 1, <$t>::MAX] {
                let expected = F128::from_i128(x as i128);
                assert_eq!(<F128 as QuotientMap<$t>>::from_int(x), expected);
                assert_eq!(<F128 as QuotientMap<$t>>::from_canonical_checked(x), Some(expected));
                // SAFETY: these small signed types lie entirely in the centered canonical range.
                assert_eq!(unsafe { <F128 as QuotientMap<$t>>::from_canonical_unchecked(x) }, expected);
            }
        })*};
    }
    unsigned!(u8, u16, u32, u64, usize);
    signed!(i8, i16, i32, i64, isize);
}

#[test]
fn canonical_bytes_and_serde_reject_malleable_encodings() {
    for a in fixtures().into_iter().filter(|&a| a < P) {
        let x = F128::new(a);
        let bytes = a.to_le_bytes();
        assert_eq!(x.to_le_bytes(), bytes);
        assert_eq!(F128::from_le_bytes(bytes), Ok(x));
        assert_eq!(F128::try_from(bytes.as_slice()), Ok(x));
        assert_eq!(postcard::to_allocvec(&x).unwrap(), bytes);
        assert_eq!(postcard::from_bytes::<F128>(&bytes).unwrap(), x);
        let json = serde_json::to_string(&bytes).unwrap();
        assert_eq!(serde_json::to_string(&x).unwrap(), json);
        assert_eq!(serde_json::from_str::<F128>(&json).unwrap(), x);
    }
    for a in [P, P + 1, u128::MAX] {
        let bytes = a.to_le_bytes();
        assert_eq!(F128::from_le_bytes(bytes), Err(DecodeError::NonCanonical));
        assert!(postcard::from_bytes::<F128>(&bytes).is_err());
        assert!(serde_json::from_str::<F128>(&serde_json::to_string(&bytes).unwrap()).is_err());
    }
    for len in [0, 1, 8, 15, 17, 32] {
        let bytes = vec![0; len];
        assert_eq!(
            F128::try_from(bytes.as_slice()),
            Err(DecodeError::InvalidLength { actual: len })
        );
        assert!(serde_json::from_str::<F128>(&serde_json::to_string(&bytes).unwrap()).is_err());
        if len < 16 {
            assert!(postcard::from_bytes::<F128>(&bytes).is_err());
        }
    }
}

#[test]
fn canonical_hash_order_and_raw_streams() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let hash = |x: F128| {
        let mut h = DefaultHasher::new();
        x.hash(&mut h);
        h.finish()
    };
    assert_eq!(hash(F128::new(P)), hash(F128::ZERO));
    assert_eq!(hash(F128::new(P + 1)), hash(F128::ONE));
    assert!(F128::NEG_ONE > F128::new(1 << 127));
    assert_eq!(F128::NEG_ONE.to_string(), (P - 1).to_string());
    assert_eq!(format!("{:?}", F128::NEG_ONE), (P - 1).to_string());
    let values = [F128::new(0x0102030405060708090a0b0c0d0e0f10), F128::NEG_ONE];
    let bytes: Vec<_> = values.into_iter().flat_map(F128::to_le_bytes).collect();
    assert_eq!(F128::NUM_BYTES, 16);
    assert_eq!(
        F128::into_byte_stream(values)
            .into_iter()
            .collect::<Vec<_>>(),
        bytes
    );
    let words32: Vec<_> = bytes
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .collect();
    let words64: Vec<_> = bytes
        .chunks_exact(8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .collect();
    assert_eq!(
        F128::into_u32_stream(values)
            .into_iter()
            .collect::<Vec<_>>(),
        words32
    );
    assert_eq!(
        F128::into_u64_stream(values)
            .into_iter()
            .collect::<Vec<_>>(),
        words64
    );
    let parallel: Vec<_> = F128::into_parallel_byte_streams([values])
        .into_iter()
        .collect();
    for (i, row) in parallel.iter().enumerate() {
        assert_eq!(*row, [bytes[i], bytes[16 + i]]);
    }
}

#[test]
fn scalar_packing_and_degree_one_extension_contracts() {
    fn bounds<F: PrimeField + TwoAdicField + ExtensionField<F>>()
    where
        F::Packing: PackedFieldPow2,
    {
    }
    bounds::<F128>();
    assert_eq!(<F128 as PackedValue>::WIDTH, 1);
    assert_eq!(<F128 as BasedVectorSpace<F128>>::DIMENSION, 1);
    let mut values = [F128::ONE, F128::TWO, F128::GENERATOR];
    let packed = <F128 as PackedValue>::pack_slice_mut(&mut values);
    packed[1] *= F128::GENERATOR;
    assert_eq!(values[1], F128::new(6));
    assert_eq!(F128::ONE.interleave(F128::TWO, 1), (F128::ONE, F128::TWO));
    assert_eq!(
        F128::from_basis_coefficients_slice(&values[..1]),
        Some(F128::ONE)
    );
    assert_eq!(F128::from_basis_coefficients_slice(&values[..2]), None);
    assert_eq!(F128::from_basis_coefficients_slice(&[]), None);
    assert_eq!(F128::GENERATOR.as_base(), Some(F128::GENERATOR));
    let ext = <F128 as PackedFieldExtension<F128, F128>>::from_ext_slice(&[F128::TWO]);
    assert_eq!(ext, F128::TWO);
    let powers: Vec<_> = <F128 as PackedField>::packed_powers(F128::TWO)
        .take(5)
        .collect();
    assert_eq!(powers, [1, 2, 4, 8, 16].map(F128::new));
}

struct ScriptedRng {
    words: std::vec::IntoIter<u64>,
    consumed: usize,
}

impl TryRng for ScriptedRng {
    type Error = Infallible;

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.consumed += 1;
        Ok(self.words.next().expect("unexpected extra RNG consumption"))
    }

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            chunk.copy_from_slice(&self.try_next_u64()?.to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

#[test]
fn random_sampling_rejects_instead_of_reducing() {
    // Rejection has probability around 2^-82, so a normal random test will not cover it.
    let inputs = [P, P + 1, u128::MAX, P - 1, 0, 1];
    let mut rng = ScriptedRng {
        words: inputs
            .into_iter()
            .flat_map(|x| [x as u64, (x >> 64) as u64])
            .collect::<Vec<_>>()
            .into_iter(),
        consumed: 0,
    };
    let first: F128 = StandardUniform.sample(&mut rng);
    assert_eq!(first, F128::NEG_ONE);
    assert_eq!(rng.consumed, 8);
    let second: F128 = StandardUniform.sample(&mut rng);
    let third: F128 = StandardUniform.sample(&mut rng);
    assert_eq!(second, F128::ZERO);
    assert_eq!(third, F128::ONE);
    assert_eq!(rng.consumed, 12);
}
