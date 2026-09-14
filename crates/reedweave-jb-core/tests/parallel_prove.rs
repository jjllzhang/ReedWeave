use p3_field::PrimeCharacteristicRing;
use reedweave_jb_core::{BaseField, JbParams, PublicParams, ReedWeaveJb, codec::encode_eval_proof};
use reedweave_primitives::transcript::{
    FieldProfile, GoldilocksBaseProfile, GoldilocksCubicProfile, GoldilocksQuadraticProfile,
    GoldilocksQuinticProfile,
};
use reedweave_runtime::ExecutionContext;

fn check<P: FieldProfile>(serial: &ExecutionContext, parallel: &ExecutionContext) {
    // Below/at/above the 16K total-element threshold, a single round (no
    // initial-word combination), and m=1 (serial evaluation, parallel rows).
    for (log_d, m, terminal_coefficients) in [
        (13, 32, 32),
        (14, 32, 32),
        (15, 64, 64),
        (15, 32, 512),
        (14, 1, 256),
    ] {
        let params = JbParams::new(PublicParams {
            base_field: BaseField::Goldilocks,
            extension_degree: P::PROFILE.extension_degree(),
            log_d,
            m,
            blowup: 2,
            terminal_coefficients,
            num_queries: 8,
            agreement_numerator: 177,
            agreement_denominator: 250,
        })
        .unwrap();
        let pcs = ReedWeaveJb::<P>::new(params.clone()).unwrap();
        for len in [0, params.d() - 3] {
            let coefficients: Vec<_> = (0..len).map(|i| P::Base::from_usize(i * i + 7)).collect();
            let (commitment, state) = pcs.commit(coefficients.clone(), serial).unwrap();
            for z in [P::Base::ZERO, P::Base::from_u8(3)] {
                // Reuse exactly the same immutable commitment state on both paths.
                let a = pcs.prove(&state, z, serial).unwrap();
                let b = pcs.prove(&state, z, parallel).unwrap();
                assert_eq!(a.y, b.y);
                assert_eq!(
                    b.y,
                    coefficients
                        .iter()
                        .rev()
                        .fold(P::Base::ZERO, |y, &c| y * z + c)
                );
                assert_eq!(
                    encode_eval_proof(&params, &a.proof).unwrap(),
                    encode_eval_proof(&params, &b.proof).unwrap(),
                    "log_d={log_d}, m={m}, terminal={terminal_coefficients}, len={len}"
                );
                pcs.verify(&commitment, z, b.y, &b.proof, serial).unwrap();
                pcs.verify(&commitment, z, a.y, &a.proof, parallel).unwrap();
            }
        }
    }
}

#[test]
fn parallel_prove_is_byte_identical_to_serial_all_profiles_and_geometries() {
    let serial = ExecutionContext::new(1).unwrap();
    let parallel = ExecutionContext::new(4).unwrap();
    check::<GoldilocksBaseProfile>(&serial, &parallel);
    check::<GoldilocksQuadraticProfile>(&serial, &parallel);
    check::<GoldilocksCubicProfile>(&serial, &parallel);
    check::<GoldilocksQuinticProfile>(&serial, &parallel);
}
