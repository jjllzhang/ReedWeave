use p3_field::PrimeCharacteristicRing;
use reedweave_jb_core::codec::{decode_eval_proof, encode_eval_proof};
use reedweave_jb_core::{BaseField, JbParams, PublicParams, ReedWeaveJb};
use reedweave_primitives::{
    fields::Goldilocks as F,
    transcript::{
        FieldProfile, GoldilocksBaseProfile, GoldilocksCubicProfile, GoldilocksProfile,
        GoldilocksQuinticProfile,
    },
};
use reedweave_runtime::ExecutionContext;

fn pp() -> PublicParams {
    PublicParams {
        base_field: BaseField::Goldilocks,
        extension_degree: 1,
        log_d: 4,
        m: 2,
        blowup: 2,
        terminal_coefficients: 2,
        num_queries: 100,
        agreement_numerator: 3,
        agreement_denominator: 4,
    }
}

#[test]
fn rational_radius_is_canonical_and_strict_without_floating_point() {
    use reedweave_jb_core::ParameterError;
    let mut p = pp();
    let canonical = JbParams::new(p.clone()).unwrap();
    p.agreement_numerator = 6;
    p.agreement_denominator = 8;
    let equivalent = JbParams::new(p.clone()).unwrap();
    assert_eq!(canonical, equivalent);
    assert_eq!(equivalent.agreement_numerator(), 3);
    assert_eq!(equivalent.agreement_denominator(), 4);
    assert_eq!(
        canonical.transcript_context().identifier().unwrap(),
        equivalent.transcript_context().identifier().unwrap()
    );
    for (a, b) in [(0, 1), (1, 0), (0, 0), (1, 1), (4, 3), (7, 10)] {
        p.agreement_numerator = a;
        p.agreement_denominator = b;
        assert_eq!(JbParams::new(p.clone()), Err(ParameterError::Agreement));
    }
    p.blowup = 4;
    for (a, b) in [(1, 2), (u32::MAX / 2, u32::MAX)] {
        p.agreement_numerator = a;
        p.agreement_denominator = b;
        assert_eq!(JbParams::new(p.clone()), Err(ParameterError::Agreement));
    }
    p.agreement_numerator = u32::MAX / 2 + 1;
    p.agreement_denominator = u32::MAX;
    assert!(JbParams::new(p.clone()).is_ok());
    p.agreement_numerator = u32::MAX - 1;
    assert!(JbParams::new(p.clone()).is_ok());
    // This large public geometry and maximum u32 coordinates are validated
    // without allocating tables, multiplying in usize, or using sqrt.
    if usize::BITS == 64 {
        p.log_d = 2;
        p.m = 1;
        p.blowup = 1 << 30;
        p.num_queries = 1;
        assert_eq!(
            JbParams::new(p.clone()).unwrap().domain_size() as u64,
            1u64 << 32
        );
    }
    let mut context = canonical.transcript_context();
    context.agreement_numerator = 6;
    context.agreement_denominator = 8;
    assert!(context.identifier().is_err()); // contexts themselves must be canonical
}

#[test]
fn geometry_and_integer_boundaries_without_allocating_domains() {
    assert_eq!(
        "goldilocks".parse::<BaseField>().unwrap().to_string(),
        "goldilocks"
    );
    assert!("other".parse::<BaseField>().is_err());
    for e in [1, 2, 3, 5] {
        let mut p = pp();
        p.extension_degree = e;
        let params = JbParams::new(p.clone()).unwrap();
        assert_eq!(
            (
                params.d(),
                params.k(),
                params.domain_size(),
                params.rounds()
            ),
            (16, 8, 16, 2)
        );
        assert_eq!(params.layer_size(2), Some(4));
        assert_eq!(params.layer_size(3), None);
        assert_eq!(params.layer_size(usize::MAX), None);
        if usize::BITS == 64 {
            p.log_d = 31;
            p.m = 1;
            p.num_queries = 1;
            let large = JbParams::new(p.clone()).unwrap();
            assert_eq!(large.domain_size() as u64, 1u64 << 32);
            p.log_d = 32;
            p.m = 2;
            assert!(JbParams::new(p.clone()).is_ok());
            p.m = 1;
            assert!(JbParams::new(p).is_err());
        }
    }
    for mutation in 0..19 {
        let mut p = pp();
        match mutation {
            0 => p.extension_degree = 0,
            1 => p.extension_degree = 4,
            2 => p.log_d = 0,
            3 => p.log_d = usize::MAX,
            4 => p.log_d = usize::BITS as usize,
            5 => p.m = 0,
            6 => p.m = 3,
            7 => p.m = 16,
            8 => p.blowup = 1,
            9 => p.blowup = 3,
            10 => p.terminal_coefficients = 0,
            11 => p.terminal_coefficients = 3,
            12 => p.terminal_coefficients = 8,
            13 => p.num_queries = 0,
            14 => p.num_queries = usize::MAX,
            15 => {
                p.log_d = usize::BITS as usize - 1;
                p.m = 1usize << (usize::BITS - 2);
            }
            16 => p.blowup = 1usize << (usize::BITS - 1),
            17 => p.terminal_coefficients = 1,
            18 => {
                p.log_d = 1;
                p.m = 1;
                p.terminal_coefficients = 1;
            }
            _ => unreachable!(),
        }
        assert!(JbParams::new(p).is_err(), "mutation {mutation}");
    }
}

fn strict_binding<P: FieldProfile<Base = F>>() {
    let execution = ExecutionContext::new(1).unwrap();
    let mut public = pp();
    public.extension_degree = P::PROFILE.extension_degree();
    let params = JbParams::new(public.clone()).unwrap();
    let pcs = ReedWeaveJb::<P>::new(params.clone()).unwrap();
    let (root, state) = pcs.commit(vec![], &execution).unwrap();
    let opening = pcs.prove(&state, F::ZERO, &execution).unwrap();
    // This deliberately opens every leaf: changing Q cannot be detected by dedup counts.
    assert_eq!(
        opening.proof.initial_opening.rows.len(),
        params.domain_size()
    );
    assert!(
        opening
            .proof
            .initial_opening
            .proof
            .sibling_hashes
            .is_empty()
    );
    let bytes = encode_eval_proof(&params, &opening.proof).unwrap();
    for mutation in 0..7 {
        let mut other = public.clone();
        match mutation {
            0 => other.log_d += 1,
            1 => other.m *= 2,
            2 => other.blowup *= 2,
            3 => other.terminal_coefficients = 4,
            4 => other.num_queries += 1,
            5 => other.extension_degree = if other.extension_degree == 1 { 2 } else { 1 },
            6 => {
                other.agreement_numerator = 4;
                other.agreement_denominator = 5;
            }
            _ => unreachable!(),
        }
        let other = JbParams::new(other).unwrap();
        assert_ne!(
            params.transcript_context().identifier().unwrap(),
            other.transcript_context().identifier().unwrap()
        );
        assert!(encode_eval_proof(&other, &opening.proof).is_err());
        assert!(decode_eval_proof::<P>(&other, &bytes).is_err());
        if mutation != 5 {
            let other_pcs = ReedWeaveJb::<P>::new(other).unwrap();
            assert!(other_pcs.prove(&state, F::ZERO, &execution).is_err());
            assert!(
                other_pcs
                    .verify(&root, F::ZERO, F::ZERO, &opening.proof, &execution)
                    .is_err()
            );
            if mutation == 4 {
                let (_, state2) = other_pcs.commit(vec![], &execution).unwrap();
                let proof2 = other_pcs.prove(&state2, F::ZERO, &execution).unwrap();
                assert_eq!(
                    proof2.proof.initial_opening.rows,
                    opening.proof.initial_opening.rows
                );
            }
        } else {
            assert!(ReedWeaveJb::<P>::new(other).is_err());
        }
    }
    // Obsolete prefixed encodings cannot substitute for the context-first format.
    let mut prefixed = vec![0];
    prefixed.extend_from_slice(&bytes);
    assert!(decode_eval_proof::<P>(&params, &prefixed).is_err());
    let mut bad = opening.proof.clone();
    bad.context_id[0] ^= 1;
    assert!(
        pcs.verify(&root, F::ZERO, F::ZERO, &bad, &execution)
            .is_err()
    );
}
#[test]
fn degenerate_proofs_are_strictly_bound_to_every_public_component() {
    strict_binding::<GoldilocksBaseProfile>();
    strict_binding::<GoldilocksProfile>();
    strict_binding::<GoldilocksCubicProfile>();
    strict_binding::<GoldilocksQuinticProfile>();
}
