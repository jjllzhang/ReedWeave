use std::{hint::black_box, time::Instant};

use reedweave_jb_core::{
    JbParams, ReedWeaveJb,
    codec::{decode_commitment, decode_eval_proof, encode_commitment, encode_eval_proof},
};
use reedweave_primitives::{
    fields::CanonicalField,
    transcript::{
        FieldProfile, GoldilocksBaseProfile, GoldilocksCubicProfile, GoldilocksQuadraticProfile,
        GoldilocksQuinticProfile,
    },
};
use reedweave_runtime::ExecutionContext;

use crate::{
    Result,
    config::{Case, Settings},
    output::{self, VerifiedTrial},
    resources::{self, Available, Estimate},
};

/// Versioned, noncryptographic fixture generator. Never used by protocol challenges.
struct Fixture(u64);
impl Fixture {
    fn word(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    fn field<F: CanonicalField>(&mut self) -> F {
        loop {
            // All supported canonical widths fit, without per-coefficient allocation.
            let mut bytes = [0u8; 40];
            for chunk in bytes[..F::BYTE_WIDTH].chunks_exact_mut(8) {
                chunk.copy_from_slice(&self.word().to_le_bytes());
            }
            if let Ok(value) = F::from_canonical_bytes(&bytes[..F::BYTE_WIDTH]) {
                return value;
            }
        }
    }
}

pub fn run(case: &Case, settings: &Settings) -> Result<()> {
    // Only the isolated worker calls run: bind before creating threads or data.
    settings.measurement.apply(case.threads)?;
    let params = case.params()?;
    let estimate = Estimate::new(case)?;
    resources::admit(&estimate, settings, &Available::detect())?;
    match params.extension_degree() {
        1 => run_generic::<GoldilocksBaseProfile>(case, settings, &params, &estimate),
        2 => run_generic::<GoldilocksQuadraticProfile>(case, settings, &params, &estimate),
        3 => run_generic::<GoldilocksCubicProfile>(case, settings, &params, &estimate),
        5 => run_generic::<GoldilocksQuinticProfile>(case, settings, &params, &estimate),
        _ => Err("unsupported extension degree".into()),
    }
}
fn run_generic<P: FieldProfile>(
    case: &Case,
    settings: &Settings,
    params: &JbParams,
    estimate: &Estimate,
) -> Result<()> {
    let campaign = settings.measurement.campaign(settings.seed)?;
    let path = output::csv_path(case, &settings.output);
    let execution = ExecutionContext::new(case.threads)?;
    let mut csv = output::open_csv(&path, params)?;
    eprintln!(
        "START {} {} resource_model=jb parameter_selection=explicit-geometry-only warmups=1 repetitions={}",
        case.label(),
        campaign.replace('\n', " "),
        settings.repetitions
    );
    let point_seed = settings.seed ^ 0x706f696e74730000 ^ case.pp.log_d as u64;
    let mut points = Fixture(point_seed);
    // Iteration zero executes the complete pipeline as a discarded warmup.
    // Every iteration owns a fresh PCS/DFT instance and releases it on exit.
    for repetition in 0..=settings.repetitions {
        resources::admit(estimate, settings, &Available::detect())?;
        // Same polynomial across repetitions, suites and thread counts. Fresh allocation
        // is consumed by each commit, and drops before the next trial.
        let mut fixture = Fixture(settings.seed ^ case.pp.log_d as u64);
        let mut coefficients = Vec::new();
        coefficients.try_reserve_exact(params.d())?;
        coefficients.extend((0..params.d()).map(|_| fixture.field::<P::Base>()));
        let pcs = ReedWeaveJb::<P>::new(params.clone())?;
        let start = Instant::now();
        // Includes encoding, the initial tree, OOD sampling and every DEEP value.
        let (commitment, state) = pcs.commit(coefficients, &execution)?;
        let commit_time = start.elapsed().as_secs_f64();
        let commit_bytes = encode_commitment::<P>(pcs.params(), &commitment)?;

        // Supplied only after commitment; external point selection is not prover work.
        let z = points.field::<P::Base>();
        let start = Instant::now();
        let opening = pcs.prove(&state, z, &execution)?;
        let prove_time = start.elapsed().as_secs_f64();
        let eval_bytes = encode_eval_proof::<P>(pcs.params(), &opening.proof)?;

        // Strict wire round-trip and application binding are outside core timers.
        let received = decode_commitment::<P>(pcs.params(), &commit_bytes)?;
        if received != commitment {
            return Err("decoded commitment mismatch".into());
        }
        let decoded_proof = decode_eval_proof::<P>(pcs.params(), &eval_bytes)?;
        // Same decoded proof: one untimed verification, then a timed batch.
        // Each call includes commitment shape/context, zeta replay and both chains.
        let verify_time = settings.measurement.time_verification(|| {
            pcs.verify(
                black_box(&received),
                black_box(z),
                black_box(opening.y),
                black_box(&decoded_proof),
                &execution,
            )
        })?;
        let proof_size = commit_bytes
            .len()
            .checked_add(eval_bytes.len())
            .ok_or("total protocol byte length overflow")?;
        if repetition == 0 {
            eprintln!("WARMUP VERIFIED {} proof_size={}", case.label(), proof_size);
            // Preserve the formal trials' original deterministic point sequence.
            points = Fixture(point_seed);
            continue;
        }
        let trial = VerifiedTrial {
            commit_time,
            prove_time,
            verify_time,
            proof_size,
        };
        output::append_trial(&mut csv, params, case.threads, &trial)?;
        eprintln!(
            "VERIFIED {} repetition={} proof_size={}",
            case.label(),
            repetition,
            proof_size
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn measured_csv_size_matches_actual_core_buffers_all_profiles() {
        fn check<P: FieldProfile>(degree: usize) {
            let directory = tempfile::tempdir().unwrap();
            let mut case = crate::tests::case();
            case.pp.extension_degree = degree;
            let settings = Settings {
                measurement: Default::default(),
                output: directory.path().into(),
                seed: 42,
                repetitions: 1,
                max_memory_mib: Some(512),
                time_limit_seconds: None,
            };
            run(&case, &settings).unwrap();
            let params = case.params().unwrap();
            let mut fixture = Fixture(settings.seed ^ case.pp.log_d as u64);
            let coefficients = (0..params.d())
                .map(|_| fixture.field::<P::Base>())
                .collect();
            let mut points = Fixture(settings.seed ^ 0x706f696e74730000 ^ case.pp.log_d as u64);
            let z = points.field::<P::Base>();
            let execution = ExecutionContext::new(1).unwrap();
            let pcs = ReedWeaveJb::<P>::new(params).unwrap();
            let (commitment, state) = pcs.commit(coefficients, &execution).unwrap();
            let opening = pcs.prove(&state, z, &execution).unwrap();
            let commit_bytes = encode_commitment::<P>(pcs.params(), &commitment).unwrap();
            let eval_bytes = encode_eval_proof::<P>(pcs.params(), &opening.proof).unwrap();
            let actual = pcs
                .verify_encoded(
                    &commitment,
                    (z, opening.y),
                    &commit_bytes,
                    &eval_bytes,
                    &execution,
                )
                .unwrap();
            assert_eq!(actual, commit_bytes.len() + eval_bytes.len());
            assert!(commit_bytes.len() > 32 + (case.pp.m + 1) * 8 * degree);
            let csv = std::fs::read_to_string(output::csv_path(&case, directory.path())).unwrap();
            let measured: f64 = csv
                .lines()
                .nth(1)
                .unwrap()
                .split(',')
                .next_back()
                .unwrap()
                .parse()
                .unwrap();
            // CSV preserves the UB campaign convention of three decimal KiB places.
            assert!((measured * 1024.0 - actual as f64).abs() <= 0.5121);
        }
        check::<GoldilocksBaseProfile>(1);
        check::<GoldilocksQuadraticProfile>(2);
        check::<GoldilocksCubicProfile>(3);
        check::<GoldilocksQuinticProfile>(5);
    }

    #[test]
    fn fixture_and_immutable_state_wire_reuse() {
        use reedweave_primitives::fields::Goldilocks;
        let mut fixture = Fixture(0);
        assert_eq!(fixture.word(), 0xe220a8397b1dcdaf);
        let execution = ExecutionContext::new(1).unwrap();
        let pcs =
            ReedWeaveJb::<GoldilocksQuadraticProfile>::new(crate::tests::case().params().unwrap())
                .unwrap();
        let coefficients: Vec<_> = (0..pcs.params().d())
            .map(|_| fixture.field::<Goldilocks>())
            .collect();
        let (commitment, state) = pcs.commit(coefficients, &execution).unwrap();
        let bytes =
            encode_commitment::<GoldilocksQuadraticProfile>(pcs.params(), &commitment).unwrap();
        for _ in 0..2 {
            let z = fixture.field::<Goldilocks>();
            let opening = pcs.prove(&state, z, &execution).unwrap();
            let proof =
                encode_eval_proof::<GoldilocksQuadraticProfile>(pcs.params(), &opening.proof)
                    .unwrap();
            assert_eq!(
                pcs.verify_encoded(&commitment, (z, opening.y), &bytes, &proof, &execution)
                    .unwrap(),
                bytes.len() + proof.len()
            );
            assert!(bytes.len() > 32);
            let mut wrong = bytes.clone();
            wrong[0] ^= 1;
            assert!(
                pcs.verify_encoded(&commitment, (z, opening.y), &wrong, &proof, &execution)
                    .is_err()
            );
        }
    }
}
