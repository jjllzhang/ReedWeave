use super::*;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use std::collections::VecDeque;
struct Bytes(VecDeque<u8>);
impl CanSample<u8> for Bytes {
    fn sample(&mut self) -> u8 {
        self.0.pop_front().unwrap()
    }
}
fn context<P: FieldProfile>() -> TranscriptContext {
    TranscriptContext {
        base_field: BaseField::Goldilocks,
        extension_degree: P::PROFILE.extension_degree(),
        log_d: 5,
        m: 4,
        blowup: 4,
        terminal_coefficients: 2,
        num_queries: 40,
    }
}
fn sampling<P: FieldProfile>() {
    let mut bytes = Vec::new();
    for i in 0..P::PROFILE.extension_degree() {
        bytes.extend(Goldilocks::ORDER_U64.to_le_bytes());
        bytes.extend(u64::MAX.to_le_bytes());
        bytes.extend((i as u64 + 11).to_le_bytes());
    }
    let mut source = Bytes(bytes.into());
    let value = P::sample_challenge(&mut source);
    let expected: Vec<_> = (0..P::PROFILE.extension_degree())
        .flat_map(|i| (i as u64 + 11).to_le_bytes())
        .collect();
    assert_eq!(value.to_canonical_bytes().as_ref(), expected);
    assert!(source.0.is_empty());
    for coordinate in 0..P::PROFILE.extension_degree() {
        let mut bad = expected.clone();
        bad[8 * coordinate..8 * coordinate + 8]
            .copy_from_slice(&Goldilocks::ORDER_U64.to_le_bytes());
        assert!(P::Challenge::from_canonical_bytes(&bad).is_err());
    }
}
#[test]
fn rejection_sampling_all_coordinates_and_32_bit_indices() {
    sampling::<GoldilocksBaseProfile>();
    sampling::<GoldilocksProfile>();
    sampling::<GoldilocksCubicProfile>();
    sampling::<GoldilocksQuinticProfile>();
    for bits in 0..=32.min(usize::BITS as usize - 1) {
        let mut source = Bytes(vec![255; bits.div_ceil(8)].into());
        assert_eq!(
            sample_index(&mut source, bits).unwrap(),
            (1usize << bits) - 1
        );
        assert!(source.0.is_empty());
    }
    let mut source = Bytes([1, 1].into());
    assert_eq!(sample_index(&mut source, 1).unwrap(), 1);
    assert_eq!(sample_index(&mut source, 1).unwrap(), 1);
    assert!(sample_index(&mut source, 33).is_err());
}
fn replay<P: FieldProfile>() {
    let pp = context::<P>();
    let mut transcript = Transcript::<P>::new(pp.clone()).unwrap();
    let mut reference = HashChallenger::new(Vec::new(), TranscriptHash);
    fn event(reference: &mut HashChallenger<u8, TranscriptHash, 32>, tag: u8, payload: Vec<u8>) {
        for byte in [tag]
            .into_iter()
            .chain((payload.len() as u64).to_le_bytes())
            .chain(payload)
        {
            reference.observe(byte);
        }
    }
    // Independently assemble the context, rather than call production canonical_bytes.
    let mut bytes = Vec::new();
    for string in [
        b"BrakeFRI-Section3-Multiproof-v3".as_slice(),
        b"goldilocks",
        P::PROFILE.representation(),
    ] {
        bytes.extend((string.len() as u64).to_le_bytes());
        bytes.extend(string);
    }
    for value in [pp.extension_degree, 5, 4, 4, 2, 40] {
        bytes.extend((value as u64).to_le_bytes());
    }
    for string in [b"blake3".as_slice(), b"canonical-coordinates-multiproof-v3"] {
        bytes.extend((string.len() as u64).to_le_bytes());
        bytes.extend(string);
    }
    assert_eq!(pp.identifier().unwrap(), TranscriptHash.hash_slice(&bytes));
    event(&mut reference, 1, bytes);
    transcript.observe_statement(&[9; 32], P::Base::TWO);
    event(
        &mut reference,
        2,
        [9; 32]
            .into_iter()
            .chain(P::Base::TWO.to_canonical_bytes())
            .collect(),
    );
    transcript.observe_claim(P::Base::ONE);
    event(
        &mut reference,
        3,
        P::Base::ONE.to_canonical_bytes().into_iter().collect(),
    );
    let v = vec![P::Base::TWO; 4];
    transcript.observe_block_values(&v).unwrap();
    event(
        &mut reference,
        4,
        4u64.to_le_bytes()
            .into_iter()
            .chain(v.iter().flat_map(CanonicalField::to_canonical_bytes))
            .collect(),
    );
    assert_eq!(
        transcript.sample_challenge(),
        P::sample_challenge(&mut reference)
    );
    for j in 0..2 {
        transcript
            .observe_round(j, P::Challenge::ONE, P::Challenge::TWO)
            .unwrap();
        event(
            &mut reference,
            5,
            (j as u64)
                .to_le_bytes()
                .into_iter()
                .chain(P::Challenge::ONE.to_canonical_bytes())
                .chain(P::Challenge::TWO.to_canonical_bytes())
                .collect(),
        );
        assert_eq!(
            transcript.sample_challenge(),
            P::sample_challenge(&mut reference)
        );
        transcript.observe_round_root(j, &[7; 32]).unwrap();
        event(
            &mut reference,
            6,
            (j as u64)
                .to_le_bytes()
                .into_iter()
                .chain([7; 32])
                .collect(),
        );
    }
    let terminal = vec![P::Challenge::TWO; 2];
    transcript.observe_terminal(&terminal).unwrap();
    event(
        &mut reference,
        7,
        2u64.to_le_bytes()
            .into_iter()
            .chain(terminal.iter().flat_map(CanonicalField::to_canonical_bytes))
            .collect(),
    );
    let expected: Vec<_> = (0..40)
        .map(|_| sample_index(&mut reference, 5).unwrap())
        .collect();
    assert_eq!(transcript.sample_queries(), expected);
    assert!(transcript.observe_block_values(&[]).is_err());
    assert!(transcript.observe_terminal(&[]).is_err());
    assert!(transcript.observe_round_root(2, &[0; 32]).is_err());
    assert!(
        transcript
            .observe_round(2, P::Challenge::ZERO, P::Challenge::ZERO)
            .is_err()
    );
    for mutation in 0..6 {
        let mut other = pp.clone();
        match mutation {
            0 => other.log_d += 1,
            1 => other.m *= 2,
            2 => other.blowup *= 2,
            3 => other.terminal_coefficients = 1,
            4 => other.num_queries += 1,
            5 => other.extension_degree = if other.extension_degree == 1 { 2 } else { 1 },
            _ => unreachable!(),
        }
        assert_ne!(pp.identifier().unwrap(), other.identifier().unwrap());
        if mutation != 5 {
            assert_ne!(
                Transcript::<P>::new(pp.clone()).unwrap().sample_challenge(),
                Transcript::<P>::new(other).unwrap().sample_challenge()
            );
        } else {
            assert!(Transcript::<P>::new(other).is_err());
        }
    }
}
#[test]
fn independent_v3_framing_and_complete_context_binding() {
    replay::<GoldilocksBaseProfile>();
    replay::<GoldilocksProfile>();
    replay::<GoldilocksCubicProfile>();
    replay::<GoldilocksQuinticProfile>();
}
