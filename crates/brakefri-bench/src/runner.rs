use std::time::Instant;

use brakefri_core::{
    BrakeFri, BrakeParams, Profile,
    codec::{encode_commitment, encode_eval_proof},
};
use brakefri_primitives::{
    fields::CanonicalField,
    transcript::{F128Profile, FieldProfile, GoldilocksProfile},
};
use brakefri_runtime::ExecutionContext;

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
            let mut bytes = [0u8; 16];
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
    let params = case.params()?;
    let estimate = Estimate::new(case)?;
    resources::admit(&estimate, settings, &Available::detect())?;
    match case.field {
        Profile::GoldilocksQuadratic => {
            run_generic::<GoldilocksProfile>(case, settings, &params, &estimate)
        }
        Profile::F128Base => run_generic::<F128Profile>(case, settings, &params, &estimate),
    }
}
fn run_generic<P: FieldProfile>(
    case: &Case,
    settings: &Settings,
    params: &BrakeParams,
    estimate: &Estimate,
) -> Result<()> {
    let execution = ExecutionContext::new(case.threads)?;
    let mut csv = output::open_csv(&output::csv_path(case, &settings.output))?;
    eprintln!(
        "START {} seed={} warmups=1 repetitions={}",
        case.label(),
        settings.seed,
        settings.repetitions
    );
    let point_seed = settings.seed ^ 0x706f696e74730000 ^ case.log_n as u64;
    let mut points = Fixture(point_seed);
    // Iteration zero executes the complete pipeline as a discarded warmup.
    // Every iteration owns a fresh PCS/DFT instance and releases it on exit.
    for repetition in 0..=settings.repetitions {
        resources::admit(estimate, settings, &Available::detect())?;
        // Same polynomial across repetitions, suites and thread counts. Fresh allocation
        // is consumed by each commit, and drops before the next trial.
        let mut fixture = Fixture(settings.seed ^ case.log_n as u64);
        let mut coefficients = Vec::new();
        coefficients.try_reserve_exact(params.n())?;
        coefficients.extend((0..params.n()).map(|_| fixture.field::<P::Base>()));
        let pcs = BrakeFri::<P>::new(params.clone())?;
        let start = Instant::now();
        let (commitment, state) = pcs.commit(coefficients, &execution)?;
        let commit_bytes = encode_commitment(&commitment);
        let commit_time = start.elapsed().as_secs_f64();

        // Supplied only after commitment; external point selection is not prover work.
        let z = points.field::<P::Base>();
        let start = Instant::now();
        let opening = pcs.prove(&state, z, &execution)?;
        let eval_bytes = encode_eval_proof::<P>(pcs.params(), &opening.proof)?;
        let prove_time = start.elapsed().as_secs_f64();

        let start = Instant::now();
        let proof_size = pcs.verify_encoded(
            &commitment,
            (z, opening.y),
            &commit_bytes,
            &eval_bytes,
            &execution,
        )?;
        let verify_time = start.elapsed().as_secs_f64();
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
    fn fixture_and_immutable_state_wire_reuse() {
        use brakefri_primitives::fields::Goldilocks;
        let mut fixture = Fixture(0);
        assert_eq!(fixture.word(), 0xe220a8397b1dcdaf);
        let execution = ExecutionContext::new(1).unwrap();
        let pcs = BrakeFri::<GoldilocksProfile>::new(
            BrakeParams::new(Profile::GoldilocksQuadratic, 14).unwrap(),
        )
        .unwrap();
        let coefficients: Vec<_> = (0..pcs.params().n())
            .map(|_| fixture.field::<Goldilocks>())
            .collect();
        let (commitment, state) = pcs.commit(coefficients, &execution).unwrap();
        let bytes = encode_commitment(&commitment);
        for _ in 0..2 {
            let z = fixture.field::<Goldilocks>();
            let opening = pcs.prove(&state, z, &execution).unwrap();
            let proof =
                encode_eval_proof::<GoldilocksProfile>(pcs.params(), &opening.proof).unwrap();
            assert_eq!(
                pcs.verify_encoded(&commitment, (z, opening.y), &bytes, &proof, &execution)
                    .unwrap(),
                32 + proof.len()
            );
            let mut wrong = bytes;
            wrong[0] ^= 1;
            assert!(
                pcs.verify_encoded(&commitment, (z, opening.y), &wrong, &proof, &execution)
                    .is_err()
            );
        }
    }
}
