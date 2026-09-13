use super::*;
use p3_field::{PrimeField64, TwoAdicField};
use reedweave_primitives::{
    fields::Goldilocks,
    transcript::{
        GoldilocksBaseProfile, GoldilocksCubicProfile, GoldilocksProfile, GoldilocksQuinticProfile,
    },
};
use std::collections::VecDeque;
struct Bytes(VecDeque<u8>);
impl CanSample<u8> for Bytes {
    fn sample(&mut self) -> u8 {
        self.0.pop_front().expect("mock source exhausted")
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
        agreement_numerator: 3,
        agreement_denominator: 4,
    }
}
fn sampling<P: FieldProfile>() {
    for accepted in [P::Challenge::ZERO, P::Challenge::TWO] {
        let mut bytes = Vec::new();
        // Several domain elements are rejected, not just 1. Each canonical
        // coordinate also rejects p and u64::MAX without modular reduction.
        for rejected in [
            P::Challenge::ONE,
            -P::Challenge::ONE,
            P::Challenge::from(P::Base::two_adic_generator(5)),
        ] {
            for chunk in rejected.to_canonical_bytes().as_ref().chunks_exact(8) {
                bytes.extend(Goldilocks::ORDER_U64.to_le_bytes());
                bytes.extend(u64::MAX.to_le_bytes());
                bytes.extend(chunk);
            }
        }
        bytes.extend(accepted.to_canonical_bytes());
        let mut source = Bytes(bytes.into());
        assert_eq!(sample_ood::<P>(&mut source, 32), accepted);
        assert!(source.0.is_empty());
    }
    // All extension coordinates are sampled, with independent rejection.
    let mut bytes = Vec::new();
    let mut expected = Vec::new();
    for i in 0..P::PROFILE.extension_degree() {
        bytes.extend(Goldilocks::ORDER_U64.to_le_bytes());
        bytes.extend((i as u64 + 11).to_le_bytes());
        expected.extend((i as u64 + 11).to_le_bytes());
    }
    let mut source = Bytes(bytes.into());
    assert_eq!(
        P::sample_challenge(&mut source)
            .to_canonical_bytes()
            .as_ref(),
        expected
    );
    assert!(source.0.is_empty());
}
#[test]
fn uniform_ood_rejects_domain_and_noncanonical_coordinates_but_allows_zero_and_base() {
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
// Deliberately independent framing, including explicit labels and integer widths.
fn reference_event(challenger: &mut Challenger, tag: u8, payload: &[u8]) {
    for byte in [tag]
        .into_iter()
        .chain((payload.len() as u64).to_le_bytes())
        .chain(payload.iter().copied())
    {
        challenger.observe(byte);
    }
}
fn reference_context<P: FieldProfile>() -> Vec<u8> {
    let mut out = Vec::new();
    for string in [
        b"ReedWeave_JB-Commit-Multiproof-v1".as_slice(),
        b"ReedWeave_JB-Eval-Multiproof-v1",
        b"goldilocks",
        P::PROFILE.representation(),
    ] {
        out.extend((string.len() as u64).to_le_bytes());
        out.extend(string);
    }
    for value in [P::PROFILE.extension_degree(), 5, 4, 4, 2, 40] {
        out.extend((value as u64).to_le_bytes());
    }
    out.extend(3u32.to_le_bytes());
    out.extend(4u32.to_le_bytes());
    for string in [
        b"blake3".as_slice(),
        b"canonical-coordinates-jb-multiproof-v1",
    ] {
        out.extend((string.len() as u64).to_le_bytes());
        out.extend(string);
    }
    out
}
fn replay<P: FieldProfile>() {
    let context = context::<P>();
    let bytes = reference_context::<P>();
    assert_eq!(
        context.identifier().unwrap(),
        TranscriptHash.hash_slice(&bytes)
    );
    let root = [9; 32];
    let mut commit = Challenger::new(Vec::new(), TranscriptHash);
    reference_event(&mut commit, 0, b"ReedWeave_JB-Commit-Multiproof-v1");
    reference_event(&mut commit, 1, &bytes);
    reference_event(&mut commit, 2, &root);
    let expected = loop {
        let c = P::sample_challenge(&mut commit);
        if c.exp_u64(32) != P::Challenge::ONE {
            break c;
        }
    };
    let zeta = commit_challenge::<P>(context.clone(), &root).unwrap();
    assert_eq!(zeta, expected);
    let commitment = JbCommitment {
        context_id: context.identifier().unwrap(),
        root,
        zeta,
        deep_values: vec![P::Challenge::TWO; 4],
    };
    let mut actual = Transcript::<P>::new(context.clone()).unwrap();
    let mut expected = Challenger::new(Vec::new(), TranscriptHash);
    reference_event(&mut expected, 0, b"ReedWeave_JB-Eval-Multiproof-v1");
    reference_event(&mut expected, 1, &bytes);
    actual
        .observe_statement(&commitment, P::Base::TWO, P::Base::ONE)
        .unwrap();
    let mut payload = commitment.context_id.to_vec();
    payload.extend(root);
    payload.extend(zeta.to_canonical_bytes());
    payload.extend(4u64.to_le_bytes());
    for c in &commitment.deep_values {
        payload.extend(c.to_canonical_bytes());
    }
    payload.extend(P::Base::TWO.to_canonical_bytes());
    payload.extend(P::Base::ONE.to_canonical_bytes());
    reference_event(&mut expected, 2, &payload);
    let blocks = vec![P::Base::TWO; 4];
    actual.observe_block_values(&blocks).unwrap();
    let mut payload = 4u64.to_le_bytes().to_vec();
    for c in &blocks {
        payload.extend(c.to_canonical_bytes());
    }
    reference_event(&mut expected, 4, &payload);
    assert_eq!(
        actual.sample_challenge(),
        P::sample_challenge(&mut expected)
    );
    for j in 0..2 {
        let values = [
            P::Challenge::ONE,
            P::Challenge::TWO,
            P::Challenge::from_u8(3),
            P::Challenge::from_u8(4),
        ];
        actual
            .observe_round(j, values[0], values[1], values[2], values[3])
            .unwrap();
        let mut payload = (j as u64).to_le_bytes().to_vec();
        for c in values {
            payload.extend(c.to_canonical_bytes());
        }
        reference_event(&mut expected, 5, &payload);
        assert_eq!(
            actual.sample_challenge(),
            P::sample_challenge(&mut expected)
        );
        if j == 0 {
            actual.observe_round_root(j, &[7; 32]).unwrap();
            let mut payload = (j as u64).to_le_bytes().to_vec();
            payload.extend([7; 32]);
            reference_event(&mut expected, 6, &payload);
        }
    }
    actual.observe_terminal(&[P::Challenge::TWO; 2]).unwrap();
    let mut payload = 2u64.to_le_bytes().to_vec();
    for _ in 0..2 {
        payload.extend(P::Challenge::TWO.to_canonical_bytes());
    }
    reference_event(&mut expected, 7, &payload);
    let queries: Vec<_> = (0..40)
        .map(|_| sample_index(&mut expected, 5).unwrap())
        .collect();
    assert_eq!(actual.sample_queries(), queries);
    assert_eq!(queries.len(), 40); // Q>N retains repeats
    assert!(actual.observe_round_root(1, &[0; 32]).is_err()); // no terminal tree
    assert!(actual.observe_round(2, zeta, zeta, zeta, zeta).is_err());
    assert!(actual.observe_terminal(&[]).is_err());
    assert!(actual.observe_block_values(&[]).is_err());
}
#[test]
fn independent_commit_and_eval_replay_all_profiles() {
    replay::<GoldilocksBaseProfile>();
    replay::<GoldilocksProfile>();
    replay::<GoldilocksCubicProfile>();
    replay::<GoldilocksQuinticProfile>();
}
#[test]
fn every_message_precedes_its_challenge_and_domains_are_separate() {
    type P = GoldilocksProfile;
    type F = <P as FieldProfile>::Base;
    type K = <P as FieldProfile>::Challenge;
    let context = context::<P>();
    let root = [1; 32];
    let zeta = commit_challenge::<P>(context.clone(), &root).unwrap();
    let commitment = JbCommitment::<P> {
        context_id: context.identifier().unwrap(),
        root,
        zeta,
        deep_values: vec![K::TWO; 4],
    };
    let prefix = |c: &JbCommitment<P>, z, y, v: &[F]| {
        let mut t = Transcript::<P>::new(context.clone()).unwrap();
        t.observe_statement(c, z, y).unwrap();
        t.observe_block_values(v).unwrap();
        t
    };
    let baseline = prefix(&commitment, F::ONE, F::TWO, &[F::ONE; 4]).sample_challenge();
    for mutation in 0..7 {
        let mut c = commitment.clone();
        let mut z = F::ONE;
        let mut y = F::TWO;
        let mut v = [F::ONE; 4];
        match mutation {
            0 => c.context_id[0] ^= 1,
            1 => c.root[0] ^= 1,
            2 => c.zeta += K::ONE,
            3 => c.deep_values[0] += K::ONE,
            4 => z += F::ONE,
            5 => y += F::ONE,
            _ => v[0] += F::ONE,
        }
        assert_ne!(baseline, prefix(&c, z, y, &v).sample_challenge());
        // c, z, y and v are absent from the commit challenge interface/prefix.
        assert_eq!(zeta, commit_challenge::<P>(context.clone(), &root).unwrap());
    }
    let mut before = prefix(&commitment, F::ONE, F::TWO, &[F::ONE; 4]);
    let _ = before.sample_challenge();
    let gamma = |values: [K; 4]| {
        let mut t = before.clone();
        t.observe_round(0, values[0], values[1], values[2], values[3])
            .unwrap();
        t.sample_challenge()
    };
    let baseline = gamma([K::ONE; 4]);
    for i in 0..4 {
        let mut values = [K::ONE; 4];
        values[i] += K::ONE;
        assert_ne!(baseline, gamma(values));
    }
    let mut a = before.clone();
    let mut b = before.clone();
    a.observe_round_root(0, &[0; 32]).unwrap();
    b.observe_round_root(0, &[1; 32]).unwrap();
    assert_ne!(a.sample_challenge(), b.sample_challenge());
    let mut a = before.clone();
    let mut b = before;
    a.observe_terminal(&[K::ONE; 2]).unwrap();
    b.observe_terminal(&[K::TWO; 2]).unwrap();
    assert_ne!(a.sample_queries(), b.sample_queries());
    let commit = start::<P>(&context, COMMIT_LABEL).unwrap();
    let eval = start::<P>(&context, EVAL_LABEL).unwrap();
    assert_ne!(
        P::sample_challenge(&mut commit.clone()),
        P::sample_challenge(&mut eval.clone())
    );
}
