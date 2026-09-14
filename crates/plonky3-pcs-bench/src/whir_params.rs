//! Native WHIR parameters and a conservative, whole-protocol algebraic budget.
//! The formulas and folding convention are implemented below; see the repository
//! README.md for benchmark commands and measurement semantics.
use p3_field::{Field as _, TwoAdicField};
use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig};
use reedweave_primitives::fields::Goldilocks;

use crate::{
    Result,
    config::{Case, Field, Protocol},
    crypto::Challenger,
    params::{Audit, LOG_INV_RATE, union_bits},
    runner::GoldilocksCubic,
};

pub type Config = WhirConfig<GoldilocksCubic, Goldilocks, Challenger<Goldilocks>>;
pub const SECURITY_BITS: usize = 100;
/// Two variables per round = arity four, NOT FoldingFactor::Constant(4).
pub const FOLD_VARIABLES: usize = 2;

pub fn config(log_n: usize) -> Result<Config> {
    let mut config = Config::new(
        log_n,
        ProtocolParameters {
            security_level: SECURITY_BITS,
            pow_bits: 0,
            folding_factor: FoldingFactor::Constant(FOLD_VARIABLES),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: LOG_INV_RATE,
            // Upstream default: halve the RS domain each round, rate exponent +1.
            round_log_inv_rates: Vec::new(),
        },
    )?;
    // Upstream targets each query stage separately. Reserve half the total
    // error budget for their UNION, not 100 bits for each stage in isolation.
    let stages = config.n_rounds() + 1;
    let query_bits = SECURITY_BITS + (2 * stages).next_power_of_two().ilog2() as usize;
    let mut old_rate = config.starting_log_inv_rate;
    for round in &mut config.round_parameters {
        round.num_queries = SecurityAssumption::JohnsonBound.queries(query_bits, old_rate);
        old_rate = round.log_inv_rate;
    }
    config.final_queries = SecurityAssumption::JohnsonBound.queries(query_bits, old_rate);
    audit_config(&config)?;
    Ok(config)
}

pub fn audit(case: &Case) -> Result<Audit> {
    case.validate()?;
    if case.protocol != Protocol::Whir || case.field != Field::Goldilocks {
        return Err("expected WHIR/Goldilocks configuration".into());
    }
    audit_config(&config(case.log_n)?)
}

pub(crate) fn audit_config(config: &Config) -> Result<Audit> {
    let jb = SecurityAssumption::JohnsonBound;
    if config.params.soundness_type != jb
        || config.params.security_level != SECURITY_BITS
        || config.params.starting_log_inv_rate != LOG_INV_RATE
        || config.params.pow_bits != 0
        || config.max_pow_bits() != 0
        || !matches!(
            config.params.folding_factor,
            FoldingFactor::Constant(FOLD_VARIABLES)
        )
        || config.folding_schedule.iter().any(|&k| k != FOLD_VARIABLES)
    {
        return Err("WHIR parameters differ from the fixed zero-PoW JohnsonBound profile".into());
    }
    if config.max_fft_size() > Goldilocks::TWO_ADICITY {
        return Err("WHIR FFT exceeds Goldilocks two-adicity".into());
    }
    // EF::bits() rounds up. Use an actual lower bound on the field order,
    // also leaving enough headroom for any domain-excluded OOD sampling.
    let bits = GoldilocksCubic::bits() - 1;
    let domain = config.starting_domain_size();
    if GoldilocksCubic::order() - domain < (num_bigint::BigUint::from(1u32) << bits) {
        return Err("WHIR challenge field/domain gap too small".into());
    }
    let mut terms = vec![
        jb.ood_error(config.num_variables, LOG_INV_RATE, bits, config.commitment_ood_samples),
        // Initial linear combination of OOD constraints and one public opening.
        bits as f64
            - libm::log2(2.0 * (config.commitment_ood_samples + 1) as f64)
            - jb.list_size_bits(config.num_variables, LOG_INV_RATE),
    ];
    fold_terms(
        bits,
        config.num_variables,
        LOG_INV_RATE,
        config.round_folding_factor(0),
        &mut terms,
    );
    let mut old_rate = LOG_INV_RATE;
    let mut queries = Vec::new();
    let mut radii = Vec::new();
    for (i, round) in config.round_parameters.iter().enumerate() {
        if round.log_inv_rate != old_rate + 1 || config.rs_reduction_factor(i) != 1 {
            return Err("WHIR rate schedule changed; renew the audit".into());
        }
        queries.push(round.num_queries);
        radii.push(1.0 - libm::exp2(jb.log_1_delta(old_rate)));
        terms.extend([
            jb.queries_error(old_rate, round.num_queries),
            jb.ood_error(
                round.num_variables,
                round.log_inv_rate,
                bits,
                round.ood_samples,
            ),
            jb.queries_combination_error(
                bits,
                round.num_variables,
                round.log_inv_rate,
                round.ood_samples,
                round.num_queries,
            ),
        ]);
        fold_terms(
            bits,
            round.num_variables,
            round.log_inv_rate,
            config.round_folding_factor(i + 1),
            &mut terms,
        );
        old_rate = round.log_inv_rate;
    }
    queries.push(config.final_queries);
    radii.push(1.0 - libm::exp2(jb.log_1_delta(old_rate)));
    terms.push(jb.queries_error(old_rate, config.final_queries));
    // Degree-two final sumcheck: sum its error over every residual variable.
    if config.final_sumcheck_rounds > 0 {
        terms.push(bits as f64 - 1.0 - libm::log2(config.final_sumcheck_rounds as f64));
    }
    if terms.iter().any(|b| !b.is_finite()) {
        return Err("non-finite WHIR security term".into());
    }
    let bound = union_bits(&terms);
    if bound < SECURITY_BITS as f64 {
        return Err(format!("WHIR algebraic security budget {bound:.9} < 100 bits").into());
    }
    Ok(Audit {
        bits: bound,
        terminal: 1 << config.final_sumcheck_rounds,
        queries,
        radii,
    })
}

fn fold_terms(bits: usize, degree: usize, rate: usize, folds: usize, terms: &mut Vec<f64>) {
    let rho = libm::exp2(-(rate as f64));
    // Full BCSS25 finite-size expression, gamma <= 1 and m=10 for eta=sqrt(rho)/20.
    // Unlike upstream's dominant-term approximation, retain both additive terms.
    let s = 10.5;
    let exceptions = (2.0 * libm::pow(s, 5.0) + 3.0 * s * rho) / (3.0 * libm::pow(rho, 1.5))
        * libm::exp2((degree + rate) as f64)
        + s / libm::sqrt(rho);
    // Degrees/domains only decrease within a folding group. Charge every
    // binary fold at the group's largest degree, including its sumcheck error.
    let union_cost = libm::log2(folds as f64);
    terms.extend([
        bits as f64 - libm::log2(exceptions) - union_cost,
        SecurityAssumption::JohnsonBound.fold_sumcheck_error(bits, degree, rate) - union_cost,
    ]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_production_sizes_clear_the_whole_protocol_target_without_pow() {
        for log_n in 20..=28 {
            let config = config(log_n).unwrap();
            let audit = audit_config(&config).unwrap();
            assert!(audit.bits >= 100.0, "log_n={log_n}: {}", audit.bits);
            assert_eq!(config.max_pow_bits(), 0);
            assert_eq!(config.folding_schedule, vec![2; (log_n - 5) / 2]);
            assert_eq!(audit.terminal, if log_n % 2 == 0 { 64 } else { 32 });
            assert_eq!(audit.queries.len(), (log_n - 5) / 2);
            assert_eq!(config.max_fft_size(), log_n + LOG_INV_RATE - 2);
        }
    }

    #[test]
    fn endpoint_query_schedules_match_the_fixed_profile() {
        // q(r)=ceil(lambda_q/(r/2-log2(21/20))), with lambda_q=104 or 105.
        let endpoints = if LOG_INV_RATE == 1 {
            [
                (20, vec![243, 112, 73, 54, 43, 36, 31]),
                (28, vec![245, 113, 74, 55, 44, 36, 31, 27, 24, 22, 20]),
            ]
        } else {
            [
                (20, vec![112, 73, 54, 43, 36, 31, 27]),
                (28, vec![113, 74, 55, 44, 36, 31, 27, 24, 22, 20, 18]),
            ]
        };
        for (log_n, expected) in endpoints {
            let config = config(log_n).unwrap();
            assert_eq!(audit_config(&config).unwrap().queries, expected);
            assert_eq!(config.commitment_ood_samples, 1);
            assert!(config.round_parameters.iter().all(|r| r.ood_samples == 1));
        }
    }

    #[test]
    fn per_stage_100_bit_queries_are_not_a_100_bit_union_bound() {
        let mut config = config(28).unwrap();
        let mut rate = LOG_INV_RATE;
        for round in &mut config.round_parameters {
            round.num_queries = SecurityAssumption::JohnsonBound.queries(100, rate);
            rate = round.log_inv_rate;
        }
        config.final_queries = SecurityAssumption::JohnsonBound.queries(100, rate);
        assert!(audit_config(&config).is_err());
    }

    #[test]
    fn insufficient_queries_and_nonzero_pow_are_rejected() {
        let mut config = config(20).unwrap();
        config.final_queries = 1;
        assert!(audit_config(&config).is_err());
        let mut config = super::config(20).unwrap();
        config.starting_folding_pow_bits = 1;
        assert!(audit_config(&config).is_err());
    }
}
