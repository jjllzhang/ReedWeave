#!/usr/bin/env python3
"""Find ReedWeave_JB's minimum Q; Python 3.11+, standard library only.

Bounds one commitment and evaluation using ordinary unique-decoding or Johnson
MCA errors: binding + MCA + evaluation constraints + a**Q <= 2**-lambda.
Certifies ONE interactive commitment plus ONE Eval, NOT Merkle/Fiat-Shamir,
hash security, repeated openings, runtime memory, or an executable extractor.
All challenges (including zeta) use q**e; FFTs stay in the Goldilocks base field.

Read only TOML [pp], ignoring Q and cases; CLI overrides it. Explicit e is never
upgraded in simple mode. Otherwise select minimum feasible e in 1,2,3,5, then Q.
Default stdout is Q only; --json includes canonical pp and an interval certificate.
Theoretical sizes include commitment once but exclude framing/context digests.

--search evaluates a bounded Cartesian grid, selecting independently per log_d.
List flags take comma-separated values; omitted axes use [pp]/CLI singletons
(degrees default to 1,2,3,5). --objective min_e_then_q and min_expected_bytes are
separate policies. Exact antipodal-pair expected bytes determine byte rankings,
not independent paths or rounded floats. Ties use canonical parameter order.
Only the declared finite grid is searched, not a global optimum or runtime tune.
No benchmark, runtime docs import, dependencies, or implicit output file writes.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
from decimal import Decimal, localcontext, ROUND_CEILING, ROUND_FLOOR
from fractions import Fraction as F
from itertools import product
from math import isqrt, log2, prod
from pathlib import Path
import json
import re
import sys
import tomllib

BASE_ORDER = (1 << 64) - (1 << 32) + 1
DEGREES = (1, 2, 3, 5)
GOLDILOCKS_MODULUS = BASE_ORDER
ALLOWED_EXTENSION_DEGREES = DEGREES
GEOMETRY_FIELDS = ("extension_degree", "log_d", "m", "blowup", "terminal_coefficients")
AGREEMENT_FIELDS = ("agreement_numerator", "agreement_denominator")
MODEL = "ReedWeave_JB-IOP-binding-plus-knowledge-v1"
SECURITY_SCOPE = ("one interactive commitment plus one Eval (IOP only); "
                  "Merkle/Fiat-Shamir, hash security and repeated openings not certified")
# Calculator work limits, NOT protocol limits or runtime memory certification.
MAX_QUERIES = 4096
MAX_SEARCH_CANDIDATES = 512
MAX_AXIS_VALUES = 64
PRECISION_BITS = (96, 192, 384, 768)
MAX_CONFIG_BYTES = 1 << 20


class InsufficientFieldError(ValueError):
    """Even infinitely many queries cannot certify the target with this bound."""

    def __init__(self, message: str, *, budget: dict | None = None, bits: int | None = None):
        super().__init__(message)
        self.budget = budget
        self.bits = bits


class PrecisionError(ValueError):
    """The available rational intervals do not decide the requested inequality."""


class ResourceLimitError(ValueError):
    """Calculator work limit reached; this is not mathematical infeasibility."""


def positive_int(name: str, value: int) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class PublicParams:
    """Mathematical pp without Q; agreement is stored canonically as two u32s.

    q is accepted for API parity with the UB calculator, but only Goldilocks and
    its supported profiles are implemented. No oracle-sized allocation occurs.
    """

    log_d: int
    m: int
    blowup: int
    terminal_coefficients: int
    agreement_numerator: int
    agreement_denominator: int
    extension_degree: int = 1
    q: int = BASE_ORDER

    def __post_init__(self) -> None:
        for name in (*GEOMETRY_FIELDS, *AGREEMENT_FIELDS, "q"):
            positive_int(name, getattr(self, name))
        if self.q != BASE_ORDER:
            raise ValueError("only the Goldilocks base-field order is supported")
        if not 2 <= self.log_d <= 62:
            raise ValueError("calculator supports 2 <= log_d <= 62")
        for name in ("m", "blowup", "terminal_coefficients"):
            if getattr(self, name).bit_length() > 63:
                raise ResourceLimitError(f"{name} exceeds the 63-bit geometry limit")
        for name in AGREEMENT_FIELDS:
            if getattr(self, name) >= 1 << 32:
                raise ValueError(f"{name} must fit u32 before canonicalization")
        agreement = F(self.agreement_numerator, self.agreement_denominator)
        object.__setattr__(self, "agreement_numerator", agreement.numerator)
        object.__setattr__(self, "agreement_denominator", agreement.denominator)
        if self.extension_degree not in DEGREES:
            raise ValueError(f"extension_degree must be in {DEGREES}")
        for name in ("m", "blowup", "terminal_coefficients"):
            value = getattr(self, name)
            if value & (value - 1):
                raise ValueError(f"{name} must be a power of two")
        if (self.d % self.m or self.k < 4 or self.blowup < 2
                or not 2 <= self.terminal_coefficients <= self.k // 2):
            raise ValueError("require k=d/m>=4, blowup>=2, and 2<=k_t<=k/2")
        if self.n > (1 << 32):
            raise ValueError("N must divide the base-field order minus one; e does not enlarge N")
        if not (0 < self.agreement < 1 and self.agreement**2 > self.rho):
            raise ValueError("require sqrt(rho) < agreement < 1 (strict Johnson radius)")

    @property
    def agreement(self) -> F:
        return F(self.agreement_numerator, self.agreement_denominator)

    @property
    def d(self) -> int:
        return 1 << self.log_d

    @property
    def k(self) -> int:
        return self.d // self.m

    @property
    def n(self) -> int:
        return self.blowup * self.k

    @property
    def t(self) -> int:
        return (self.k // self.terminal_coefficients).bit_length() - 1

    @property
    def rho(self) -> F:
        return F(1, self.blowup)

    @property
    def delta(self) -> F:
        return 1 - self.agreement

    @property
    def field_order(self) -> int:
        return BASE_ORDER**self.extension_degree

    @property
    def list_bound(self) -> int:
        reciprocal = 1 / (self.agreement**2 - self.rho)
        return reciprocal.numerator // reciprocal.denominator


@dataclass(frozen=True)
class Bounds:
    lower: F
    upper: F

    @classmethod
    def exact(cls, value: F) -> Bounds:
        return cls(value, value)

    def __add__(self, other: Bounds) -> Bounds:
        return Bounds(self.lower + other.lower, self.upper + other.upper)


def sqrt_bounds(value: F, bits: int) -> Bounds:
    """Exact dyadic enclosure, including exact endpoints for rational roots."""
    if value <= 0 or type(bits) is not int or not 1 <= bits <= PRECISION_BITS[-1]:
        raise ValueError("positive radicand and precision in 1..768 required")
    scale = 1 << bits
    root = isqrt(value.numerator * scale**2 // value.denominator)
    low = F(root, scale)
    high = low if low**2 == value else F(root + 1, scale)
    return Bounds(low, high)


def johnson_s(rate_minus_one: F, agreement: F) -> int:
    """Exact max(ceil(sqrt(r)/(a-sqrt(r))), 3), without computing sqrt.

    For positive s: sqrt(r)/(a-sqrt(r)) <= s iff
    (s+1)^2*r <= s^2*a^2. This also handles an exact integer threshold.
    """
    if not 0 < rate_minus_one < agreement**2:
        raise ValueError("invalid Johnson slack")

    def enough(s: int) -> bool:
        return (s + 1)**2 * rate_minus_one <= s**2 * agreement**2

    low, high = 0, 3
    while not enough(high):
        low, high = high, 2 * high
    while high - low > 1:
        mid = (low + high) // 2
        if enough(mid):
            high = mid
        else:
            low = mid
    return max(high, 3)


def mca_bounds(k: int, n: int, arity: int, agreement: F,
               field_order: int, bits: int) -> tuple[Bounds, int | None, str]:
    """MCA error bound; do not extrapolate the unique-decoding bound into Johnson."""
    if not (2 <= k < n and arity >= 1 and 0 < agreement < 1
            and agreement**2 > F(k, n)):
        raise ValueError("outside supported MCA bound geometry")
    if arity == 1:
        return Bounds.exact(F(0)), None, "identity"
    delta = 1 - agreement
    if delta <= (1 - F(k, n)) / 2:
        # Use the conservative unique-decoding bound without optional refinements.
        return Bounds.exact(F((arity - 1) * n, field_order)), None, "unique"
    r = F(k - 1, n)
    s = johnson_s(r, agreement)
    h = F(2 * s + 1, 2)
    # Algebraically identical to the displayed Johnson formula:
    # ((2*h^5 + 3*h*delta*r)*n/(3*r) + h) / sqrt(r).
    numerator = ((2 * h**5 + 3 * h * delta * r) * n / (3 * r) + h)
    numerator *= F(arity - 1, field_order)
    root = sqrt_bounds(r, bits)
    if root.lower == 0:
        raise PrecisionError("increase square-root precision")
    return Bounds(numerator / root.upper, numerator / root.lower), s, "johnson"


def error_budget(pp: PublicParams, bits: int = 96) -> dict:
    b = pp.list_bound
    binding = Bounds.exact(F(b * (b - 1) // 2 * (pp.k - 1), pp.field_order - pp.n))
    constraints = Bounds.exact(F(b * (pp.m - 1 + pp.t), pp.field_order))
    layers = []
    mca = Bounds.exact(F(0))
    # Initial m-fold uses C_0; binary folds use C_1 through C_t, INCLUDING C_t.
    for layer in range(pp.t + 1):
        k, n = pp.k >> layer, pp.n >> layer
        arity = pp.m if layer == 0 else 2
        error, s, branch = mca_bounds(k, n, arity, pp.agreement, pp.field_order, bits)
        layers.append(dict(layer=layer, k=k, n=n, arity=arity, s=s,
                           branch=branch, error=error))
        mca = mca + error
    return dict(binding=binding, constraints=constraints, mca=mca,
                floor=binding + constraints + mca, layers=layers)


def least_queries(agreement: F, residual: F) -> int:
    """Exact minimum Q>=1 for a^Q <= residual; queries have replacement."""
    if not (0 < agreement < 1 and residual > 0):
        raise ValueError("positive query budget and 0<a<1 required")
    if agreement <= residual:
        return 1
    low, high = 1, 2
    while agreement**high > residual:
        if high >= MAX_QUERIES:
            raise ResourceLimitError(f"minimum Q exceeds calculator limit {MAX_QUERIES}")
        low, high = high, min(2 * high, MAX_QUERIES)
    while high - low > 1:
        mid = (low + high) // 2
        if agreement**mid <= residual:
            high = mid
        else:
            low = mid
    return high


def certify(pp: PublicParams, security_bits: int) -> tuple[int, dict, int]:
    """Prove both success at Q and failure at Q-1 for this chosen IOP bound."""
    positive_int("security_bits", security_bits)
    if security_bits > 4096:
        raise ResourceLimitError("calculator caps security_bits at 4096")
    target = F(1, 1 << security_bits)
    for bits in PRECISION_BITS:
        budget = error_budget(pp, bits)
        floor = budget["floor"]
        if floor.lower >= target:
            raise InsufficientFieldError(
                f"e={pp.extension_degree}: algebraic floor >= target; no finite Q "
                "certifies binding + knowledge IOP error with this bound",
                budget=budget, bits=bits)
        if floor.upper >= target:
            continue
        count = least_queries(pp.agreement, target - floor.upper)
        if count == 1 or floor.lower + pp.agreement**(count - 1) > target:
            return count, budget, bits
    raise PrecisionError("inconclusive near an exact boundary; not a security certificate")


def select(pp: PublicParams, security_bits: int, automatic: bool) -> tuple[PublicParams, int, dict, int]:
    """Automatic mode minimizes feasible e first, NOT proof size or runtime."""
    degrees = DEGREES if automatic else (pp.extension_degree,)
    for degree in degrees:
        candidate = replace(pp, extension_degree=degree)
        try:
            count, budget, bits = certify(candidate, security_bits)
            return candidate, count, budget, bits
        except InsufficientFieldError:
            if not automatic:
                raise
    raise InsufficientFieldError(f"no supported degree in {DEGREES} certifies the target")


def expected_opening(height: int, queries: int) -> tuple[F, F]:
    """Expected leaves/frontier hashes for Q independent antipodal query pairs.

    Natural-order binary trees, sorted/deduplicated union of (i, i+height/2).
    This is NOT the expectation for 2Q independent single-leaf queries.
    """
    positive_int("height", height)
    positive_int("queries", queries)
    if height < 2 or height & (height - 1) or height > 1 << 32:
        raise ValueError("power-of-two height in 2..2**32 required")
    if queries > MAX_QUERIES:
        raise ResourceLimitError(f"queries exceed calculator limit {MAX_QUERIES}")
    leaves = height * (1 - F(height - 2, height)**queries)
    hashes = F(0)
    for level in range(height.bit_length() - 2):
        width = 1 << level
        hashes += (height // width) * (
            (1 - F(2 * width, height))**queries
            - (1 - F(4 * width, height))**queries)
    return leaves, hashes


def size_estimates(pp: PublicParams, queries: int) -> dict:
    positive_int("queries", queries)
    n = pp.n.bit_length() - 1
    # Count R,zeta,c once; v is base-valued; all four round values are extension-valued.
    base = pp.m * (1 + 2 * queries)
    extension = pp.m + 1 + 4 * pp.t + pp.terminal_coefficients + 2 * queries * (pp.t - 1)
    hashes = pp.t + 2 * queries * (pp.t * n - pp.t * (pp.t - 1) // 2)
    independent = 8 * base + 8 * pp.extension_degree * extension + 32 * hashes
    expected = expected_proof_size(pp, queries)
    return dict(independent_paths=dict(base_elements=base, extension_elements=extension,
                                      hash_values=hashes, bytes=independent, kib=independent / 1024),
                expected_multiproof=dict(bytes=float(expected), kib=float(expected / 1024)),
                scope="protocol-only, includes R/zeta/c once; excludes context/framing, "
                      "public z/y and query indices; NOT actual serialized bytes")


def expected_proof_size(pp: PublicParams, queries: int) -> F:
    """Exact rational antipodal multiproof expectation, used for search ranking."""
    openings = [expected_opening(pp.n >> j, queries) for j in range(pp.t)]
    base = pp.m * (1 + openings[0][0])
    extension = (pp.m + 1 + 4 * pp.t + pp.terminal_coefficients
                 + sum((v for v, _ in openings[1:]), F(0)))
    hashes = pp.t + sum((h for _, h in openings), F(0))
    return 8 * base + 8 * pp.extension_degree * extension + 32 * hashes


def theoretical_proof_size(pp: PublicParams, num_queries: int) -> dict:
    """UB-style independent-path payload breakdown plus pair-multiproof estimate.

    JB adds c and explicit zeta in the commitment, and four scalars per fold.
    No terminal root/tree/authentication, context digests, vector framing, public
    z/y or query indices are charged. Neither model is actual serialized size.
    """
    size = size_estimates(pp, num_queries)
    independent = size["independent_paths"]
    return dict(size, base_elements=independent["base_elements"],
                extension_elements=independent["extension_elements"],
                hash_values=independent["hash_values"],
                base_element_bytes=8, extension_element_bytes=8 * pp.extension_degree,
                hash_bytes=32, base_payload_bytes=8 * independent["base_elements"],
                extension_payload_bytes=8 * pp.extension_degree * independent["extension_elements"],
                hash_payload_bytes=32 * independent["hash_values"],
                theoretical_proof_size_bytes=independent["bytes"],
                theoretical_proof_size_kib=independent["kib"])


def minimum_queries(pp: PublicParams, security_bits: int) -> int:
    """Return certified minimum Q>=1 for one binding-plus-Eval IOP budget.

    Queries have replacement and may exceed N. Distinguish an exhausted field
    budget (InsufficientFieldError), undecided intervals (PrecisionError), and
    calculator limits (ResourceLimitError); none is silently certified.
    """
    return certify(pp, security_bits)[0]


def normalize_params(raw: dict) -> dict:
    """Copy/normalize a pp mapping; do not modify callers or consume cases."""
    raw = dict(raw)
    raw.pop("num_queries", None)
    if raw.pop("base_field", "goldilocks") != "goldilocks":
        raise ValueError("only base_field=goldilocks is supported")
    return raw


def select_parameters(pp: dict, security_bits: int) -> tuple[PublicParams, int]:
    """UB-style (resolved pp, Q); explicit e never upgraded, input not mutated."""
    raw = normalize_params(pp)
    automatic = "extension_degree" not in raw
    selected, count, _, _ = select(PublicParams(**raw), security_bits, automatic)
    return selected, count


def decimal_text(value: F, upper: bool) -> str:
    with localcontext() as context:
        context.prec = 24
        context.rounding = ROUND_CEILING if upper else ROUND_FLOOR
        return format(Decimal(value.numerator) / Decimal(value.denominator), ".23E")


def interval_report(bounds: Bounds) -> dict:
    return dict(lower=decimal_text(bounds.lower, False), upper=decimal_text(bounds.upper, True))


def report(pp: PublicParams, count: int, budget: dict, bits: int, security_bits: int) -> dict:
    query = pp.agreement**count
    total = budget["floor"] + Bounds.exact(query)
    root = sqrt_bounds(pp.rho, bits)
    return dict(
        model=MODEL,
        security_scope=SECURITY_SCOPE,
        pp=dict(base_field="goldilocks", extension_degree=pp.extension_degree,
                log_d=pp.log_d, m=pp.m, blowup=pp.blowup,
                terminal_coefficients=pp.terminal_coefficients,
                agreement_numerator=pp.agreement.numerator,
                agreement_denominator=pp.agreement.denominator, num_queries=count),
        derived=dict(d=pp.d, k=pp.k, N=pp.n, t=pp.t, rho=str(pp.rho),
                     delta=str(pp.delta), B=pp.list_bound,
                     eta=interval_report(Bounds(pp.agreement - root.upper,
                                                pp.agreement - root.lower)),
                     challenge_field_order=str(pp.field_order)),
        security_bits=security_bits, num_queries=count,
        certificate=dict(certified=True, minimal_for_selected_bound=True,
                         square_root_precision_bits=bits, comparisons="exact rational intervals",
                         target=interval_report(Bounds.exact(F(1, 1 << security_bits))),
                         at_Q_upper_le_target=total.upper <= F(1, 1 << security_bits),
                         at_Q_minus_one_lower_gt_target=(budget["floor"].lower
                             + pp.agreement**(count - 1) > F(1, 1 << security_bits)),
                         at_Q_minus_one=interval_report(budget["floor"]
                             + Bounds.exact(pp.agreement**(count - 1)))),
        errors={**{key: interval_report(budget[key])
                   for key in ("binding", "constraints", "mca", "floor")},
                "query": interval_report(Bounds.exact(query)), "total": interval_report(total),
                "total_bits_approx": log2(total.upper.denominator) - log2(total.upper.numerator)},
        mca_layers=[{**row, "error": interval_report(row["error"])} for row in budget["layers"]],
        proof_size=theoretical_proof_size(pp, count))


def parse_agreement(text: str) -> F:
    """Bounded rational/decimal parser: no binary floats or huge exponents."""
    if not isinstance(text, str) or len(text) > 128:
        raise ValueError("agreement must be a rational/decimal string of at most 128 characters")
    text = text.strip()
    if not re.fullmatch(r"[0-9]+(?:/[0-9]+|\.[0-9]+)?", text):
        raise ValueError("agreement must be an exact rational like 18/25 or decimal like 0.72")
    try:
        value = F(text)
    except ZeroDivisionError as error:
        raise ValueError("agreement denominator must be positive") from error
    if not 0 < value < 1 or max(value.numerator, value.denominator) >= 1 << 32:
        raise ValueError("agreement must be in (0,1), with canonical numerator/denominator fitting u32")
    return value


def bounded_axis(name: str, values, *, rational: bool = False) -> list:
    # Require a finite materialized sequence; never consume an unbounded iterator.
    if not isinstance(values, (list, tuple)) or not 1 <= len(values) <= MAX_AXIS_VALUES:
        raise ResourceLimitError(f"{name} must contain 1..{MAX_AXIS_VALUES} values")
    result = []
    for value in values:
        if rational:
            if isinstance(value, str):
                value = parse_agreement(value)
            if not isinstance(value, F):
                raise ValueError("search agreements must be Fraction or rational strings")
            if not 0 < value < 1 or max(value.numerator, value.denominator) >= 1 << 32:
                raise ValueError("search agreement must be in (0,1) with u32 numerator/denominator")
        else:
            positive_int(name, value)
            if value.bit_length() > 63:
                raise ResourceLimitError(f"{name} exceeds the 63-bit input limit")
        result.append(value)
    return sorted(set(result))


def search_parameters(pp: dict, security_bits: int, *, m_values=None, blowup_values=None,
                      terminal_coefficients_values=None, agreements=None,
                      extension_degrees=None, log_d_values=None,
                      objective: str = "min_e_then_q",
                      max_candidates: int = MAX_SEARCH_CANDIDATES) -> dict:
    """Audit a finite grid; choose separately for each log_d, never across sizes.

    All axes are sorted/deduplicated, with deterministic candidate IDs. Explicit
    list axes override singleton pp values ONLY in this explicit search API.
    Missing degrees use all supported profiles, unless pp explicitly fixes e.
    Invalid geometry, exhausted floors, unresolved precision and calculator work
    limits remain in the audit with distinct statuses. If any candidates cannot
    be decided, optimality is claimed only among the certified candidates.
    """
    positive_int("security_bits", security_bits)
    if security_bits > 4096:
        raise ResourceLimitError("calculator caps security_bits at 4096")
    positive_int("max_candidates", max_candidates)
    if max_candidates > MAX_SEARCH_CANDIDATES:
        raise ResourceLimitError(f"search cap cannot exceed {MAX_SEARCH_CANDIDATES}")
    if objective not in ("min_e_then_q", "min_expected_bytes"):
        raise ValueError("objective must be min_e_then_q or min_expected_bytes")
    raw = normalize_params(pp)
    allowed = {*GEOMETRY_FIELDS, *AGREEMENT_FIELDS, "q"}
    if raw.keys() - allowed:
        raise ValueError(f"unknown pp fields: {sorted(raw.keys() - allowed)}")
    if "q" in raw and (type(raw["q"]) is not int or raw["q"] != BASE_ORDER):
        raise ValueError("only the Goldilocks base-field order is supported")
    axes = {}
    for name, values in (("log_d", log_d_values), ("m", m_values),
                         ("blowup", blowup_values),
                         ("terminal_coefficients", terminal_coefficients_values),
                         ("extension_degree", extension_degrees)):
        if values is None:
            if name == "extension_degree" and name not in raw:
                values = DEGREES
            elif name in raw:
                values = [raw[name]]
            else:
                raise ValueError(f"search needs {name} or its explicit list")
        axes[name] = bounded_axis(name, values)
    if agreements is None:
        for name in AGREEMENT_FIELDS:
            if name not in raw:
                raise ValueError(f"search needs {name} or --search-agreements")
            positive_int(name, raw[name])
            if raw[name] >= 1 << 32:
                raise ValueError(f"{name} must fit u32 before canonicalization")
        agreements = [F(raw["agreement_numerator"], raw["agreement_denominator"])]
    axes["agreement"] = bounded_axis("agreements", agreements, rational=True)
    candidate_count = prod(len(axis) for axis in axes.values())
    if candidate_count > max_candidates:
        raise ResourceLimitError(f"search grid has {candidate_count} candidates; limit is {max_candidates}")
    candidates, best = [], {}
    # This order also defines the final deterministic canonical tie breaker.
    names = ("log_d", "m", "blowup", "terminal_coefficients", "agreement", "extension_degree")
    for candidate_id, values in enumerate(product(*(axes[name] for name in names))):
        candidate = dict(zip(names, values))
        agreement = candidate.pop("agreement")
        candidate.update(agreement_numerator=agreement.numerator,
                         agreement_denominator=agreement.denominator)
        row = dict(candidate_id=candidate_id, pp=dict(base_field="goldilocks", **candidate))
        try:
            params = PublicParams(**candidate)
            count, budget, bits = certify(params, security_bits)
            result = report(params, count, budget, bits, security_bits)
            expected = expected_proof_size(params, count)
            tie = (params.m, params.blowup, params.terminal_coefficients,
                   params.agreement, params.extension_degree, count)
            key = ((params.extension_degree, count, tie) if objective == "min_e_then_q"
                   else (expected, tie))
            row.update(status="certified", **result)
            if params.log_d not in best or key < best[params.log_d][0]:
                best[params.log_d] = (key, candidate_id)
        except InsufficientFieldError as error:
            row.update(status="infeasible", reason=str(error))
            if error.budget is not None:
                row.update(square_root_precision_bits=error.bits,
                           errors={name: interval_report(error.budget[name])
                                   for name in ("binding", "constraints", "mca", "floor")},
                           mca_layers=[{**layer, "error": interval_report(layer["error"])}
                                       for layer in error.budget["layers"]])
        except ResourceLimitError as error:
            row.update(status="resource_limit", reason=str(error))
        except PrecisionError as error:
            row.update(status="precision_unresolved", reason=str(error))
        except (ValueError, TypeError) as error:
            row.update(status="invalid", reason=str(error))
        candidates.append(row)
    selected_ids = [best[log_d][1] for log_d in axes["log_d"] if log_d in best]
    unresolved = any(row["status"] in ("resource_limit", "precision_unresolved") for row in candidates)
    missing = [log_d for log_d in axes["log_d"] if log_d not in best]
    counts = {status: sum(row["status"] == status for row in candidates)
              for status in ("certified", "infeasible", "invalid", "resource_limit", "precision_unresolved")}
    return dict(model=MODEL, security_scope=SECURITY_SCOPE, security_bits=security_bits,
                pp=candidates[selected_ids[0]]["pp"] if selected_ids else None,
                cases=[candidates[index]["pp"] for index in selected_ids],
                selections=[candidates[index] for index in selected_ids],
                search=dict(objective=objective,
                            domain={name: [str(x) for x in axis] if name == "agreement" else axis
                                    for name, axis in axes.items()},
                            candidate_count=candidate_count, status_counts=counts,
                            selected_candidate_ids=selected_ids, missing_log_d=missing,
                            complete=not missing and not unresolved,
                            optimality="declared finite grid only" if not unresolved else
                                       "certified candidates only; unresolved candidates remain",
                            tie_breaker="m, blowup, terminal_coefficients, rational agreement, e, Q",
                            ranking_arithmetic="exact rational expected bytes (not displayed floats)",
                            resource_scope="calculator limits only; Rust preflight still required",
                            limits=dict(max_candidates=max_candidates, max_axis_values=MAX_AXIS_VALUES,
                                        max_queries=MAX_QUERIES, precision_bits=list(PRECISION_BITS)),
                            candidates=candidates))


def csv_axis(text: str, *, rational: bool = False) -> list:
    if len(text) > 8192 or text.count(",") >= MAX_AXIS_VALUES:
        raise ResourceLimitError(f"search list exceeds {MAX_AXIS_VALUES} values or 8192 characters")
    parts = text.split(",")
    return bounded_axis("search list", parts if rational else [int(x) for x in parts], rational=rational)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", type=Path, help="Read [pp] only; ignore num_queries and [[cases]]")
    field = parser.add_mutually_exclusive_group()
    field.add_argument("--base-field", choices=("goldilocks",))
    field.add_argument("--q", type=int, help="UB-compatible numeric order; only Goldilocks supported")
    for name in (*GEOMETRY_FIELDS, *AGREEMENT_FIELDS):
        parser.add_argument("--" + name.replace("_", "-"), type=int)
    parser.add_argument("--agreement", help="Exact a=1-delta, e.g. 18/25 or 0.72")
    parser.add_argument("--security-bits", "--lambda", dest="security_bits", type=int, required=True)
    parser.add_argument("--json", action="store_true", help="Emit canonical pp and IOP error certificate/audit")
    parser.add_argument("--search", action="store_true", help="Explicit bounded grid search; one winner per log_d")
    parser.add_argument("--objective", choices=("min_e_then_q", "min_expected_bytes"), default=None)
    parser.add_argument("--max-candidates", type=int, default=None)
    search_flags = (("m", "m_values"), ("blowups", "blowup_values"),
                    ("terminal-coefficients", "terminal_coefficients_values"),
                    ("agreements", "agreements"), ("degrees", "extension_degrees"),
                    ("log-d", "log_d_values"))
    for flag, dest in search_flags:
        parser.add_argument("--search-" + flag, dest=dest, help="Comma-separated finite candidate list")
    args = parser.parse_args(argv)
    try:
        raw = {}
        if args.config:
            with args.config.open("rb") as stream:
                data = stream.read(MAX_CONFIG_BYTES + 1)
            if len(data) > MAX_CONFIG_BYTES:
                raise ResourceLimitError("config exceeds 1 MiB calculator limit")
            config = tomllib.loads(data.decode("utf-8"))
            if not isinstance(config.get("pp"), dict):
                raise ValueError("config must contain [pp]")
            raw = dict(config["pp"])
        raw.pop("num_queries", None)
        if args.base_field is not None:
            raw.pop("q", None)
        elif args.q is not None:
            raw.pop("base_field", None)
        for name in ("base_field", "q", *GEOMETRY_FIELDS, *AGREEMENT_FIELDS):
            if getattr(args, name) is not None:
                raw[name] = getattr(args, name)
        if args.agreement is not None:
            if any(getattr(args, name) is not None for name in AGREEMENT_FIELDS):
                raise ValueError("use --agreement or numerator/denominator flags, not both")
            agreement = parse_agreement(args.agreement)
            raw.update(agreement_numerator=agreement.numerator,
                       agreement_denominator=agreement.denominator)
        if args.search:
            lists = {dest: csv_axis(getattr(args, dest), rational=dest == "agreements")
                     for _, dest in search_flags if getattr(args, dest) is not None}
            result = search_parameters(raw, args.security_bits, **lists,
                                       objective=args.objective or "min_e_then_q",
                                       max_candidates=(args.max_candidates if args.max_candidates is not None
                                                       else MAX_SEARCH_CANDIDATES))
            selections = result["selections"]
            status = 0 if result["search"]["complete"] else 1
        else:
            if (args.objective is not None or args.max_candidates is not None
                    or any(getattr(args, dest) is not None for _, dest in search_flags)):
                raise ValueError("search lists/objective/limits require explicit --search")
            raw = normalize_params(raw)
            selected, count, budget, bits = select(PublicParams(**raw), args.security_bits,
                                                  automatic="extension_degree" not in raw)
            result = report(selected, count, budget, bits, args.security_bits)
            selections, status = [result], 0
    except (OSError, ValueError, TypeError, KeyError, ZeroDivisionError) as error:
        parser.error(str(error))
    if args.json:
        print(json.dumps(result, indent=2, allow_nan=False))
    else:
        for selected in selections:
            pp, size = selected["pp"], selected["proof_size"]
            print(f"log_d={pp['log_d']} selected extension_degree={pp['extension_degree']} "
                  f"agreement={pp['agreement_numerator']}/{pp['agreement_denominator']} "
                  f"theoretical_proof_size_bytes={size['theoretical_proof_size_bytes']} "
                  f"expected_multiproof_bytes={size['expected_multiproof']['bytes']:.6f} "
                  "(protocol only; not wire bytes)", file=sys.stderr)
            print(selected["num_queries"])
        print(SECURITY_SCOPE, file=sys.stderr)
        if args.search:
            print(f"objective={result['search']['objective']}; {result['search']['optimality']}; "
                  f"statuses={result['search']['status_counts']}", file=sys.stderr)
    if status:
        print("search incomplete: no certified candidate for some sizes or unresolved calculator limits; "
              "inspect --json audit", file=sys.stderr)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
