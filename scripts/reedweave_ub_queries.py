#!/usr/bin/env python3
"""Find ReedWeave_UB's smallest Q using the unique-decoding IOP bound.

Python 3.11+, standard library only. Input pp excludes Q; security_bits is a
separate required input. For TOML, read only [pp] and ignore num_queries.
The calculation uses q**e, not a rounded field bit size, and exact integer
comparisons. It does not certify Fiat-Shamir, hash security, or runtime resources.
Custom q must be the order of an odd finite field; field construction/primality
is the caller's responsibility. An explicit e may be any positive integer.
If e is omitted, choose the smallest feasible e from 1, 2, 3, 5 (the Goldilocks
runtime profiles). Report the selected e and theoretical proof size on stderr,
keeping Q alone on stdout; --json emits a structured report instead. Proof size
counts prover-to-verifier communication with independent full Merkle paths,
including the initial commitment, but no deduplication or serialization overhead.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, replace
import json
from pathlib import Path
import sys
import tomllib

GOLDILOCKS_MODULUS = (1 << 64) - (1 << 32) + 1
ALLOWED_EXTENSION_DEGREES = (1, 2, 3, 5)
GEOMETRY_FIELDS = ("extension_degree", "log_d", "m", "blowup", "terminal_coefficients")


def positive_integer(name: str, value: int) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class PublicParams:
    """Mathematical pp without Q; q is the base-field order, d = 2**log_d."""

    q: int
    extension_degree: int
    log_d: int
    m: int
    blowup: int
    terminal_coefficients: int

    def __post_init__(self) -> None:
        for name in ("q", *GEOMETRY_FIELDS):
            positive_integer(name, getattr(self, name))
        if self.q <= 2 or self.q % 2 == 0:
            raise ValueError("q must be the order of an odd finite field")
        for name in ("m", "blowup", "terminal_coefficients"):
            value = getattr(self, name)
            if value & (value - 1):
                raise ValueError(f"{name} must be a power of two")
        if self.blowup < 2:
            raise ValueError("blowup must be at least 2 (rho < 1)")
        log_k = self.log_d - (self.m.bit_length() - 1)
        if log_k < 2:
            raise ValueError("m must divide d with k = d/m >= 4")
        if self.terminal_coefficients < 2:
            raise ValueError("terminal_coefficients must be at least 2 (required by the unique-decoding bound)")
        if self.terminal_coefficients.bit_length() - 1 >= log_k:
            raise ValueError("terminal_coefficients must be at most k/2 (at least one binary fold)")
        # Check exponents before constructing d or N, including for huge log_d.
        log_n = log_k + self.blowup.bit_length() - 1
        q_minus_one = self.q - 1
        two_adicity = (q_minus_one & -q_minus_one).bit_length() - 1
        if log_n > two_adicity:
            raise ValueError("encoding domain N must divide q - 1; increasing e does not enlarge the base domain")


class InsufficientFieldError(ValueError):
    """The algebraic floor leaves no query budget for the requested target."""


def minimum_queries(pp: PublicParams, security_bits: int) -> int:
    """Return the minimum Q >= 1 with ((1+rho)/2)**Q + A_t/q**e <= 2**-lambda.

    Here rho = 1/blowup and A_t = blowup*(d-k_t) + m-1+t.
    Raise ValueError if the algebraic floor already exhausts the target budget.
    Query positions are sampled with replacement, so Q is NOT capped at N.
    """
    positive_integer("security_bits", security_bits)
    d = 1 << pp.log_d
    k = d // pp.m
    t = (k // pp.terminal_coefficients).bit_length() - 1
    algebraic_numerator = pp.blowup * (d - pp.terminal_coefficients) + pp.m - 1 + t
    field_size = pp.q ** pp.extension_degree
    # Short-circuit absurd lambda values without allocating 2**lambda.
    if (security_bits >= field_size.bit_length()
            or (algebraic_numerator << security_bits) >= field_size):
        raise InsufficientFieldError(
            "algebraic error A_t/q^e >= 2^-lambda: no finite Q certifies this target; "
            "increase extension_degree or q, or lower security_bits"
        )
    scale = 1 << security_bits
    remaining = field_size - algebraic_numerator * scale

    def meets_target(queries: int) -> bool:
        # ((b+1)/(2b))**Q <= (q**e - A_t*2**lambda)/(q**e*2**lambda).
        # Cross-multiplication avoids floating-point logs and cancellation.
        return ((pp.blowup + 1) ** queries * field_size * scale
                <= (2 * pp.blowup) ** queries * remaining)

    low, high = 0, 1  # Q=0 fails, and the positive residual guarantees a finite upper bound.
    while not meets_target(high):
        low, high = high, 2 * high
    while high - low > 1:
        middle = (low + high) // 2
        if meets_target(middle):
            high = middle
        else:
            low = middle
    return high


def select_parameters(pp: dict[str, int], security_bits: int) -> tuple[PublicParams, int]:
    """Resolve optional extension_degree and return (complete pp, minimum Q).

    pp uses a numeric base-field order q. Explicit degrees are never upgraded.
    Automatic selection minimizes e first, then Q; it does not mutate the input.
    Only an exhausted algebraic budget triggers trying a larger degree.
    """
    raw = dict(pp)
    automatic = "extension_degree" not in raw
    raw.setdefault("extension_degree", ALLOWED_EXTENSION_DEGREES[0])
    params = PublicParams(**raw)
    if not automatic:
        return params, minimum_queries(params, security_bits)
    for degree in ALLOWED_EXTENSION_DEGREES:
        candidate = replace(params, extension_degree=degree)
        try:
            return candidate, minimum_queries(candidate, security_bits)
        except InsufficientFieldError:
            continue
    raise InsufficientFieldError(
        f"no allowed extension degree in {ALLOWED_EXTENSION_DEGREES} certifies this target; "
        "no finite Q suffices for these degrees; lower security_bits or change pp"
    )


def theoretical_proof_size(pp: PublicParams, num_queries: int) -> dict[str, int | float]:
    """Protocol-only bytes, with two independent full paths per query per layer.

    Count the initial commitment once, both scalar messages in each binary round,
    t-1 intermediate roots, and terminal coefficients, but no terminal root,
    terminal table or terminal authentication.
    No query indices, verifier messages, context digests, or vector prefixes
    are included. Even repeated queries are charged in full (no multiproofs).
    Goldilocks uses 8-byte coordinates. For custom q, assume byte-aligned base
    coordinates of ceil(log2(q)/8) bytes and e such coordinates per extension
    element. Hashes are always 32 bytes. This is NOT the runtime wire size.
    """
    positive_integer("num_queries", num_queries)
    k = (1 << pp.log_d) // pp.m
    n = (k * pp.blowup).bit_length() - 1
    t = (k // pp.terminal_coefficients).bit_length() - 1
    base_elements = pp.m * (1 + 2 * num_queries)
    extension_elements = 2 * t + pp.terminal_coefficients + 2 * num_queries * (t - 1)
    hash_values = t + 2 * num_queries * (t * n - t * (t - 1) // 2)
    base_element_bytes = ((pp.q - 1).bit_length() + 7) // 8
    extension_element_bytes = pp.extension_degree * base_element_bytes
    base_payload = base_elements * base_element_bytes
    extension_payload = extension_elements * extension_element_bytes
    hash_payload = hash_values * 32
    total = base_payload + extension_payload + hash_payload
    return {
        "base_elements": base_elements,
        "extension_elements": extension_elements,
        "hash_values": hash_values,
        "base_element_bytes": base_element_bytes,
        "extension_element_bytes": extension_element_bytes,
        "hash_bytes": 32,
        "base_payload_bytes": base_payload,
        "extension_payload_bytes": extension_payload,
        "hash_payload_bytes": hash_payload,
        "theoretical_proof_size_bytes": total,
        "theoretical_proof_size_kib": total / 1024,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, help="Read [pp] from TOML; ignore old num_queries and benchmark/cases")
    field = parser.add_mutually_exclusive_group()
    field.add_argument("--base-field", choices=("goldilocks",), help="Named base field (or supply --q)")
    field.add_argument("--q", type=int, help="Custom base-field order, NOT the extension-field order")
    for name in GEOMETRY_FIELDS:
        help_text = ("If absent from both CLI and [pp], select the minimum feasible e from 1,2,3,5"
                     if name == "extension_degree" else None)
        parser.add_argument("--" + name.replace("_", "-"), type=int, help=help_text)
    parser.add_argument("--security-bits", "--lambda", dest="security_bits", type=int, required=True,
                        help="Target lambda: IOP error at most 2^-lambda")
    parser.add_argument("--json", action="store_true",
                        help="Print resolved pp, Q, and protocol-only proof-size breakdown as JSON")
    args = parser.parse_args(argv)
    try:
        raw = {}
        if args.config is not None:
            with args.config.open("rb") as stream:
                config = tomllib.load(stream)
            if not isinstance(config.get("pp"), dict):
                raise ValueError("config must contain a [pp] table")
            raw = dict(config["pp"])
        raw.pop("num_queries", None)
        for name in GEOMETRY_FIELDS:
            if getattr(args, name) is not None:
                raw[name] = getattr(args, name)
        if args.base_field is not None:
            raw.pop("q", None)
            raw["base_field"] = args.base_field
        elif args.q is not None:
            raw.pop("base_field", None)
            raw["q"] = args.q
        if "base_field" in raw:
            if raw.pop("base_field") != "goldilocks":
                raise ValueError("unsupported base_field; supply an explicit field order with --q")
            if "q" in raw:
                raise ValueError("specify only one of base_field and q")
            raw["q"] = GOLDILOCKS_MODULUS
        automatic = "extension_degree" not in raw
        params, result = select_parameters(raw, args.security_bits)
        size = theoretical_proof_size(params, result)
    except (OSError, ValueError, TypeError) as error:
        parser.error(str(error))
    if args.json:
        print(json.dumps({"pp": asdict(params), "security_bits": args.security_bits,
                          "num_queries": result, "proof_size": size}, indent=2))
    else:
        if automatic:
            print(f"selected extension_degree={params.extension_degree}", file=sys.stderr)
        print(f"theoretical_proof_size_bytes={size['theoretical_proof_size_bytes']} "
              f"theoretical_proof_size_kib={size['theoretical_proof_size_kib']:.6f} "
              "(independent paths; protocol only)", file=sys.stderr)
        print(result)  # Q only, suitable for --num-queries "$(python3 ...)".
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
