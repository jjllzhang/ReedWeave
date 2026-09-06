use std::time::Instant;

use brakefri_core::{
    BrakeFri, BrakeParams, Profile,
    codec::{encode_commitment, encode_eval_proof},
};
use brakefri_primitives::{
    fields::CanonicalField,
    hash::{Blake3Suite, HashSuite, KeccakSuite, Sha256Suite},
    transcript::{F128Profile, FieldProfile, GoldilocksProfile},
};
use brakefri_runtime::ExecutionContext;

use crate::{
    Result,
    config::{Case, Hash, Settings},
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
    resources::admit(&Estimate::new(case)?, settings, &Available::detect())?;
    match case.field {
        Profile::GoldilocksQuadratic => dispatch::<GoldilocksProfile>(case, settings),
        Profile::F128Base => dispatch::<F128Profile>(case, settings),
    }
}
fn dispatch<P: FieldProfile>(case: &Case, settings: &Settings) -> Result<()> {
    match case.hash {
        Hash::Keccak256 => run_generic::<P, _>(case, settings, KeccakSuite),
        Hash::Sha256 => run_generic::<P, _>(case, settings, Sha256Suite),
        Hash::Blake3 => run_generic::<P, _>(case, settings, Blake3Suite),
    }
}
fn run_generic<P: FieldProfile, S: HashSuite>(
    case: &Case,
    settings: &Settings,
    suite: S,
) -> Result<()> {
    let execution = ExecutionContext::new(case.threads)?;
    let mut csv = output::open_csv(&output::csv_path(case, &settings.output))?;
    output::metadata(case, settings)?;
    let mut points = Fixture(settings.seed ^ 0x706f696e74730000 ^ case.log_n as u64);
    for repetition in 0..settings.repetitions {
        resources::admit(&Estimate::new(case)?, settings, &Available::detect())?;
        // Same polynomial across repetitions, suites and thread counts. Fresh allocation
        // is consumed by each measured commit, and drops before the next trial.
        let mut fixture = Fixture(settings.seed ^ case.log_n as u64);
        let params = BrakeParams::new(P::PROFILE, case.log_n)?;
        let mut coefficients = Vec::new();
        coefficients.try_reserve_exact(params.n())?;
        coefficients.extend((0..params.n()).map(|_| fixture.field::<P::Base>()));
        let pcs = BrakeFri::<P, S>::new(params, suite.clone())?;
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
        let trial = VerifiedTrial {
            commit_time,
            prove_time,
            verify_time,
            proof_size,
        };
        output::append_trial(&mut csv, case, &trial)?;
        output::log(
            &settings.output,
            &format!(
                "VERIFIED {} repetition={} proof_size={}",
                case.label(),
                repetition + 1,
                proof_size
            ),
        )?;
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
        let pcs = BrakeFri::<GoldilocksProfile, _>::new(
            BrakeParams::new(Profile::GoldilocksQuadratic, 11).unwrap(),
            Blake3Suite,
        )
        .unwrap();
        let coefficients: Vec<_> = (0..2048).map(|_| fixture.field::<Goldilocks>()).collect();
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
