//! End-to-end transport tests using only the public JB constructors and API.
use p3_field::PrimeCharacteristicRing;
use reedweave_jb_core::codec::{
    DecodeError, VerifyEncodedError, decode_commitment, decode_eval_proof, encode_commitment,
    encode_eval_proof,
};
use reedweave_jb_core::{BaseField, JbParams, PublicParams, ReedWeaveJb};
use reedweave_primitives::{
    fields::CanonicalField,
    transcript::{
        FieldProfile, GoldilocksBaseProfile, GoldilocksCubicProfile, GoldilocksProfile,
        GoldilocksQuinticProfile, TranscriptContext,
    },
};
use reedweave_runtime::ExecutionContext;

fn public_params<P: FieldProfile>() -> PublicParams {
    PublicParams {
        base_field: BaseField::Goldilocks,
        extension_degree: P::PROFILE.extension_degree(),
        log_d: 5,
        m: 4,
        blowup: 2,
        terminal_coefficients: 2,
        num_queries: 19, // Q > N intentionally exercises repeated queries.
        agreement_numerator: 18,
        agreement_denominator: 25,
    }
}

fn commitment_malformed<P: FieldProfile>() {
    let params = JbParams::new(public_params::<P>()).unwrap();
    let pcs = ReedWeaveJb::<P>::new(params.clone()).unwrap();
    let execution = ExecutionContext::new(1).unwrap();
    let (commitment, _) = pcs.commit(vec![P::Base::ONE], &execution).unwrap();
    let bytes = encode_commitment(&params, &commitment).unwrap();
    let width = P::Challenge::BYTE_WIDTH;
    let count_offset = 64 + width;
    assert_eq!(bytes[count_offset], params.m() as u8);
    for end in 0..bytes.len() {
        assert!(
            decode_commitment::<P>(&params, &bytes[..end]).is_err(),
            "prefix {end}"
        );
    }
    for suffix in [&[0][..], &[0xff; 32][..]] {
        let mut trailing = bytes.clone();
        trailing.extend_from_slice(suffix);
        assert!(matches!(
            decode_commitment::<P>(&params, &trailing),
            Err(DecodeError::TrailingBytes)
        ));
    }
    for count in [0, params.m() - 1, params.m() + 1, usize::MAX] {
        let mut bad = bytes[..count_offset].to_vec();
        bad.extend(postcard::to_allocvec(&count).unwrap());
        // Even with no remaining element bytes, the announced length is rejected.
        assert!(matches!(
            decode_commitment::<P>(&params, &bad),
            Err(DecodeError::Postcard(postcard::Error::SerdeDeCustom))
        ));
    }
    let mut overlong = bytes[..count_offset].to_vec();
    overlong.extend([0x84, 0]);
    overlong.extend_from_slice(&bytes[count_offset + 1..]);
    assert!(matches!(
        decode_commitment::<P>(&params, &overlong),
        Err(DecodeError::NonCanonicalFraming)
    ));
    let mut overflow = bytes[..count_offset].to_vec();
    overflow.extend_from_slice(&[0xff; 20]);
    assert!(decode_commitment::<P>(&params, &overflow).is_err());

    // Every coordinate of zeta and every c_i rejects p and the largest u64.
    let coordinates = (64..count_offset)
        .step_by(8)
        .chain((count_offset + 1..bytes.len()).step_by(8));
    for offset in coordinates {
        for invalid in [P::PROFILE.modulus() as u64, u64::MAX] {
            let mut bad = bytes.clone();
            bad[offset..offset + 8].copy_from_slice(&invalid.to_le_bytes());
            assert!(
                decode_commitment::<P>(&params, &bad).is_err(),
                "coordinate {offset}"
            );
        }
    }
    for len in [params.m() - 1, params.m() + 1] {
        let mut wrong = commitment.clone();
        wrong.deep_values.resize(len, P::Challenge::ZERO);
        assert!(encode_commitment(&params, &wrong).is_err());
    }
    let mut wrong = commitment.clone();
    wrong.context_id[0] ^= 1;
    assert!(encode_commitment(&params, &wrong).is_err());
    let mut wrong_bytes = bytes.clone();
    wrong_bytes[0] ^= 1;
    assert!(decode_commitment::<P>(&params, &wrong_bytes).is_err());
}

#[test]
fn commitments_reject_malformed_lengths_coordinates_and_framing() {
    commitment_malformed::<GoldilocksBaseProfile>();
    commitment_malformed::<GoldilocksProfile>();
    commitment_malformed::<GoldilocksCubicProfile>();
    commitment_malformed::<GoldilocksQuinticProfile>();
}

fn transport_binding<P: FieldProfile>() {
    let params = JbParams::new(public_params::<P>()).unwrap();
    let pcs = ReedWeaveJb::<P>::new(params).unwrap();
    let execution = ExecutionContext::new(1).unwrap();
    let (commitment, state) = pcs
        .commit(vec![P::Base::ONE, P::Base::ONE], &execution)
        .unwrap();
    let z = P::Base::from_u8(9);
    let opening = pcs.prove(&state, z, &execution).unwrap();
    let commit_bytes = encode_commitment(pcs.params(), &commitment).unwrap();
    let eval_bytes = encode_eval_proof(pcs.params(), &opening.proof).unwrap();
    assert_eq!(
        pcs.verify_encoded(
            &commitment,
            (z, opening.y),
            &commit_bytes,
            &eval_bytes,
            &execution
        )
        .unwrap(),
        commit_bytes.len() + eval_bytes.len()
    );
    for index in 0..commitment.deep_values.len() + 2 {
        let mut wrong = commitment.clone();
        if index < commitment.deep_values.len() {
            wrong.deep_values[index] += P::Challenge::ONE;
        } else if index == commitment.deep_values.len() {
            wrong.zeta += P::Challenge::ONE;
        } else {
            wrong.root[0] ^= 1;
        }
        let wrong_bytes = encode_commitment(pcs.params(), &wrong).unwrap();
        // Correct context/root alone must never suffice: compare every c and zeta.
        assert!(matches!(
            pcs.verify_encoded(
                &commitment,
                (z, opening.y),
                &wrong_bytes,
                &eval_bytes,
                &execution
            ),
            Err(VerifyEncodedError::CommitmentMismatch)
        ));
        assert!(matches!(
            pcs.verify_encoded(
                &wrong,
                (z, opening.y),
                &commit_bytes,
                &eval_bytes,
                &execution
            ),
            Err(VerifyEncodedError::CommitmentMismatch)
        ));
        // Matching a corrupted expected commitment still requires typed verification.
        assert!(matches!(
            pcs.verify_encoded(
                &wrong,
                (z, opening.y),
                &wrong_bytes,
                &eval_bytes,
                &execution
            ),
            Err(VerifyEncodedError::Verify(_))
        ));
    }
    for statement in [(z + P::Base::ONE, opening.y), (z, opening.y + P::Base::ONE)] {
        assert!(matches!(
            pcs.verify_encoded(
                &commitment,
                statement,
                &commit_bytes,
                &eval_bytes,
                &execution
            ),
            Err(VerifyEncodedError::Verify(_))
        ));
    }
}

#[test]
fn full_expected_commitment_and_caller_statement_are_bound() {
    transport_binding::<GoldilocksBaseProfile>();
    transport_binding::<GoldilocksProfile>();
    transport_binding::<GoldilocksCubicProfile>();
    transport_binding::<GoldilocksQuinticProfile>();
}

fn context_binding<P: FieldProfile>() {
    let pp = public_params::<P>();
    let params = JbParams::new(pp.clone()).unwrap();
    let pcs = ReedWeaveJb::<P>::new(params.clone()).unwrap();
    let execution = ExecutionContext::new(1).unwrap();
    // Zero must not mask protocol/radius/profile/geometry separation.
    let (commitment, state) = pcs.commit(vec![P::Base::ZERO], &execution).unwrap();
    let opening = pcs.prove(&state, P::Base::ZERO, &execution).unwrap();
    let cb = encode_commitment(&params, &commitment).unwrap();
    let eb = encode_eval_proof(&params, &opening.proof).unwrap();
    for index in 0..7 {
        let mut wrong = pp.clone();
        match index {
            0 => wrong.agreement_numerator = 19,
            1 => wrong.m = 2,
            2 => wrong.num_queries += 1,
            3 => wrong.extension_degree = if pp.extension_degree == 1 { 2 } else { 1 },
            4 => wrong.log_d += 1,
            5 => wrong.blowup = 4,
            6 => wrong.terminal_coefficients = 4,
            _ => unreachable!(),
        }
        let other = JbParams::new(wrong).unwrap();
        assert!(encode_commitment(&other, &commitment).is_err());
        assert!(encode_eval_proof(&other, &opening.proof).is_err());
        assert!(decode_commitment::<P>(&other, &cb).is_err());
        assert!(decode_eval_proof::<P>(&other, &eb).is_err());
    }
    // Equivalent radius fractions have exactly the same canonical transport.
    let mut equivalent = pp.clone();
    equivalent.agreement_numerator *= 2;
    equivalent.agreement_denominator *= 2;
    let equivalent = JbParams::new(equivalent).unwrap();
    assert_eq!(encode_commitment(&equivalent, &commitment).unwrap(), cb);
    assert_eq!(encode_eval_proof(&equivalent, &opening.proof).unwrap(), eb);

    // UB root-only commitments and UB's context are never JB transport, including
    // zero proofs. Use the shared UB context API without adding a UB dependency.
    assert!(decode_commitment::<P>(&params, &commitment.root).is_err());
    let ub_context = TranscriptContext {
        base_field: pp.base_field,
        extension_degree: pp.extension_degree,
        log_d: pp.log_d,
        m: pp.m,
        blowup: pp.blowup,
        terminal_coefficients: pp.terminal_coefficients,
        num_queries: pp.num_queries,
    }
    .identifier()
    .unwrap();
    assert_ne!(ub_context, commitment.context_id);
    let mut ub_commit = cb.clone();
    ub_commit[..32].copy_from_slice(&ub_context);
    let mut ub_proof = eb.clone();
    ub_proof[..32].copy_from_slice(&ub_context);
    assert!(decode_commitment::<P>(&params, &ub_commit).is_err());
    assert!(decode_eval_proof::<P>(&params, &ub_proof).is_err());
    assert!(decode_commitment::<P>(&params, &eb).is_err());
    assert!(decode_eval_proof::<P>(&params, &cb).is_err());
}

#[test]
fn zero_transport_cannot_cross_parameters_profiles_radius_or_protocol() {
    context_binding::<GoldilocksBaseProfile>();
    context_binding::<GoldilocksProfile>();
    context_binding::<GoldilocksCubicProfile>();
    context_binding::<GoldilocksQuinticProfile>();
}
