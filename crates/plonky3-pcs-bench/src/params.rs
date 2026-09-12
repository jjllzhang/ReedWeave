//! Audited parameters plus scalar admission checks; no prover data is allocated.
use brakefri_primitives::fields::CanonicalField;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{ExtensionField, TwoAdicField};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_security::whir::SecurityAssumption;
use p3_stir::{StirConfig, StirParameters, TwoAdicStirPcs};

use crate::{
    Result,
    config::{Case, Protocol},
    crypto::{BaseMmcs, ChallengeMmcs, Challenger, mmcs},
};

/// Fixed comparison FRI geometry, independent of parameterized BrakeFRI.
pub const FRI_TERMINAL_COEFFICIENTS: usize = 128;

pub type Fri<F, EF> = TwoAdicFriPcs<F, Radix2DitParallel<F>, BaseMmcs<F>, ChallengeMmcs<F, EF>>;
pub type Stir<F, EF> =
    TwoAdicStirPcs<F, Radix2DitParallel<F>, BaseMmcs<F>, ChallengeMmcs<F, EF>, EF, Challenger<F>>;

pub fn fri<F: CanonicalField + TwoAdicField, EF: ExtensionField<F>>() -> Fri<F, EF> {
    TwoAdicFriPcs::new(
        Radix2DitParallel::default(),
        mmcs(0),
        FriParameters {
            log_blowup: 1,
            log_final_poly_len: FRI_TERMINAL_COEFFICIENTS.ilog2() as usize,
            max_log_arity: 1,
            num_queries: 244,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: 0,
            mmcs: ExtensionMmcs::new(mmcs(1)),
        },
    )
}
fn stir_parameters<F: CanonicalField, EF: ExtensionField<F>>()
-> StirParameters<ChallengeMmcs<F, EF>> {
    StirParameters {
        log_blowup: 1,
        log_folding_factor: 2,
        log_starting_folding_factor: 2,
        soundness_type: SecurityAssumption::JohnsonBound,
        security_level: 100,
        max_pow_bits: 0,
        mmcs: ExtensionMmcs::new(mmcs(1)),
    }
}
pub fn stir<F: CanonicalField + TwoAdicField, EF: ExtensionField<F> + TwoAdicField>() -> Stir<F, EF>
{
    TwoAdicStirPcs::new(Radix2DitParallel::default(), mmcs(0), stir_parameters())
}
#[derive(Debug)]
pub struct Audit {
    pub bits: f64,
    pub terminal: usize,
    pub queries: Vec<usize>,
    pub radii: Vec<f64>,
}
impl Audit {
    pub fn queries_text(&self) -> String {
        self.queries
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(";")
    }
    pub fn radii_text(&self) -> String {
        self.radii
            .iter()
            .map(|r| format!("{r:.17}"))
            .collect::<Vec<_>>()
            .join(";")
    }
}
pub(crate) fn union_bits(terms: &[f64]) -> f64 {
    let weakest = terms.iter().copied().fold(f64::INFINITY, f64::min);
    weakest - libm::log2(terms.iter().map(|b| libm::exp2(weakest - b)).sum())
}
pub fn audit<F, EF>(case: &Case) -> Result<Audit>
where
    F: CanonicalField + TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
{
    case.validate()?;
    if case.protocol == Protocol::Whir {
        return crate::whir_params::audit(case);
    }
    if case.log_n + 1 > F::TWO_ADICITY {
        return Err("initial domain exceeds base-field two-adicity".into());
    }
    // Use a strict lower bound on log2(|EF|), including for domain-excluded samples.
    let lower_bits = EF::bits() - 1;
    let domain = 1usize << (case.log_n + 1);
    if EF::order() - domain < (num_bigint::BigUint::from(1u32) << lower_bits) {
        return Err("challenge field/domain gap too small".into());
    }
    let result = match case.protocol {
        Protocol::Whir => unreachable!("WHIR uses its own parameter audit"),
        Protocol::Fri => {
            let n = (1usize << case.log_n) as f64;
            let alpha = (3.0 * n + 1.0) / (4.0 * n);
            let q_lower = libm::exp2(lower_bits as f64);
            let terms = [
                lower_bits as f64 - libm::log2((case.log_n - 7) as f64 * (2.0 * n + 1.0)),
                -244.0 * libm::log2(alpha),
                libm::log2(q_lower - 2.0 * n) - libm::log2(2.0 * n),
            ];
            Audit {
                bits: union_bits(&terms),
                terminal: FRI_TERMINAL_COEFFICIENTS,
                queries: vec![244],
                radii: vec![1.0 - alpha],
            }
        }
        Protocol::Stir => {
            let config = StirConfig::<F, EF, _, Challenger<F>>::try_new(
                case.log_n,
                stir_parameters::<F, EF>(),
            )?;
            let mut terms = Vec::new();
            let mut queries = Vec::new();
            let mut radii = Vec::new();
            let mut initial_eta = config.final_eta;
            for (i, round) in config.round_configs.iter().enumerate() {
                if i == 0 {
                    initial_eta = round.eta;
                }
                if round.pow_bits != 0 || round.folding_pow_bits != 0 {
                    return Err("unexpected STIR grinding".into());
                }
                stage_terms(
                    lower_bits,
                    round.log_degree,
                    round.log_domain_size - round.log_degree,
                    round.eta,
                    round.num_queries,
                    false,
                    &mut terms,
                    &mut radii,
                );
                queries.push(round.num_queries);
            }
            if config.final_pow_bits != 0 || config.final_folding_pow_bits != 0 {
                return Err("unexpected final STIR grinding".into());
            }
            let rounds = config.num_rounds();
            stage_terms(
                lower_bits,
                case.log_n - 2 * rounds,
                1 + rounds,
                config.final_eta,
                config.final_queries,
                true,
                &mut terms,
                &mut radii,
            );
            queries.push(config.final_queries);
            let log_list = -0.5 - libm::log2(initial_eta);
            terms.push(lower_bits as f64 - 2.0 * log_list - (case.log_n + 1) as f64);
            Audit {
                bits: union_bits(&terms),
                terminal: config.final_poly_len(),
                queries,
                radii,
            }
        }
    };
    if !result.bits.is_finite() || result.bits < 100.0 {
        return Err(format!("algebraic security budget {:.9} < 100 bits", result.bits).into());
    }
    Ok(result)
}
#[allow(clippy::too_many_arguments)]
fn stage_terms(
    bits: usize,
    degree: usize,
    inv_rate: usize,
    eta: f64,
    queries: usize,
    final_stage: bool,
    terms: &mut Vec<f64>,
    radii: &mut Vec<f64>,
) {
    let jb = SecurityAssumption::JohnsonBound;
    let log_eta = libm::log2(eta);
    let rho = libm::exp2(-(inv_rate as f64));
    let m = libm::ceil(libm::exp2(-(inv_rate as f64) / 2.0 - 1.0 - log_eta)).max(3.0);
    let shifted = m + 0.5;
    let count = (2.0 * libm::pow(shifted, 5.0) + 3.0 * shifted * rho) / (3.0 * libm::pow(rho, 1.5))
        * libm::exp2((degree + inv_rate) as f64)
        + shifted / libm::sqrt(rho);
    let base = libm::sqrt(rho) + eta;
    radii.push(1.0 - base);
    terms.extend([
        bits as f64 - libm::log2(count),
        jb.fold_sumcheck_error_at_log_eta(bits, degree, inv_rate, log_eta),
        -(queries as f64) * libm::log2(base),
    ]);
    if !final_stage {
        terms.extend([
            jb.ood_error_at_log_eta(degree, inv_rate, bits, 1, log_eta),
            jb.queries_combination_error_at_log_eta(bits, degree, inv_rate, 1, queries, log_eta),
            bits as f64 - libm::log2(2.0 * (queries + 1) as f64),
        ]);
    }
}
