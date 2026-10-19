#!/usr/bin/env python3
"""Measure, validate and plot Goldilocks PCS benchmarks (default 20..34).

Plotting keeps the original CLI: --rate 1/2 --validate-only (or render figures).
Measurement uses this same entry point: benchmark plan/build/run/merge/plot.
Run disposable regression tests with: self-test.
Existing measurements/failure markers are reused; benchmark plan --rerun creates
fresh results without duplicating or replacing the bundled CSVs.

Paths do not distinguish timing models: use logs to identify measurement provenance.
Do not mix historical times with new core algorithm times.
Read each protocol from <root>/<protocol>/goldilocks.csv.
ReedWeave_UB and ReedWeave_JB require full public-parameter schemas; legacy compact headers are rejected.
The CSV has no protocol-version column; campaign provenance is external metadata.
Use --log-d 1..3 (alias --log-sizes) to select other sizes, including tiny cases.
ReedWeave UB/JB pp may vary with log_d, but must be fixed within each size across trials
and thread counts; ambiguous campaigns are rejected.
Plot arithmetic means of measured trials.
CSV times are already in ms and proof sizes in KiB; no unit conversion is applied.
Zero timings (including rounded zeros) are retained. Metrics containing zero use
linear axes, consistently across thread figures; positive-only metrics use log axes.
Use --rate (default 1/2) to select a rate before grouping trials.
Write figures directly to <out>/<base_field>/threads_<count>_rate_<num>_<den>.png;
the default output root is results/figures, with no comparison subdirectory.
Overlay selected protocols at matching base fields, sizes and thread counts.
By default, use thread counts shared by all selected protocols for each field;
--threads selects explicit counts and requires every protocol to cover them.
Every included thread count must cover all selected size exponents.
By default, discover available protocol CSVs and compare supported protocols per
field. BaseFold, Brakedown, Shockwave and WHIR are Goldilocks-only. Explicit --protocols
compares their common supported fields unless --fields restricts them further.
Brakedown and Shockwave supply one record per size; others default to five records.
Brakedown retains its measured native code rate regardless of --rate.
Input semantics, security assumptions and PoW settings can differ across protocols.
Compact CSVs do not record seeds/revisions or trial IDs: use separate directories
for independent campaigns and retain benchmark logs for reproducibility.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
from datetime import datetime, timezone
import math
import struct
from fractions import Fraction
from pathlib import Path
from statistics import mean

FIELDS = {"goldilocks": "Goldilocks"}
PROTOCOLS = {
    "reedweave_ub": ("ReedWeave_UB", "#009E73"),
    "reedweave_jb": ("ReedWeave_JB", "#AA4499"),
    "fri": ("FRI", "#0072B2"),
    "stir": ("STIR", "#D55E00"),
    "whir": ("WHIR", "#CC79A7"),
    "basefold": ("BaseFold", "#E69F00"),
    "shockwave": ("Shockwave", "#56B4E9"),
    "brakedown": ("Brakedown", "#332288"),
}
GOLDILOCKS_ONLY = {"whir", "basefold", "shockwave", "brakedown"}
SINGLE_RECORD_PROTOCOLS = {"shockwave", "brakedown"}
PLONKY3_PROTOCOLS = {"fri", "stir", "whir"}
PCS_HEADER = "log_n,rho,threads,commit_time_ms,open_time_ms,verify_time_ms,proof_size_KiB".split(",")
HEADER = "base_field,extension_degree,log_d,m,blowup,terminal_coefficients,num_queries,threads,commit_time_ms,open_time_ms,verify_time_ms,proof_size_KiB".split(",")
PP_COLUMNS = ("base_field", "extension_degree", "m", "blowup",
              "terminal_coefficients", "num_queries")
JB_HEADER = HEADER[:7] + ["agreement_numerator", "agreement_denominator"] + HEADER[7:]
JB_PP_COLUMNS = PP_COLUMNS + ("agreement_numerator", "agreement_denominator")
REEDWEAVE_PROTOCOLS = {"reedweave_ub", "reedweave_jb"}
LOG_SIZES = tuple(range(20, 35))
UNSATISFIED_SECURITY_PARAMETER = "unsatisfied security parameter"
MISSING_MARKERS = {"-", UNSATISFIED_SECURITY_PARAMETER}
REPETITIONS = 5
METRICS = (
    ("commit_time_ms", "Commit time", "ms"),
    ("open_time_ms", "Open time", "ms"),
    ("verify_time_ms", "Verify time", "ms"),
    ("proof_size_KiB", "Proof size", "KiB"),
)
Key = tuple[str, int, int, str]


def protocol_root(protocol, results, plonky3_results=None):
    if protocol in PLONKY3_PROTOCOLS and plonky3_results is not None:
        return plonky3_results
    return results


def expected_repetitions(protocol, override=None):
    return override if override is not None else (1 if protocol in SINGLE_RECORD_PROTOCOLS else REPETITIONS)


def csv_path(protocol, root, field="goldilocks"):
    directory = root / PROTOCOLS[protocol][0]
    return directory / f"{field}.csv"


def validate_reedweave_ub(row, *, word_bytes=struct.calcsize("P")):
    return _validate_reedweave(row, word_bytes=word_bytes, jb=False)


def validate_reedweave_jb(row, *, word_bytes=struct.calcsize("P")):
    return _validate_reedweave(row, word_bytes=word_bytes, jb=True)


def _validate_reedweave(row, *, word_bytes, jb):
    """Mirror UbParams/JbParams geometry on the plotting platform; no security claim.

    Rust usize/pointers occupy one word and Vec metadata occupies three words.
    The optional word size permits synthetic 32/64-bit boundary regression tests.
    """
    usize_max = (1 << (8 * word_bytes)) - 1
    isize_max = usize_max >> 1
    vec_bytes = 3 * word_bytes

    def mul(a, b):
        value = a * b
        if value > isize_max:
            raise ValueError("pp exceeds addressable implementation sizes")
        return value

    def add(*values):
        value = sum(values)
        if value > usize_max:
            raise ValueError("pp arithmetic overflow")
        return value

    if row["base_field"] != "goldilocks":
        raise ValueError("ReedWeave requires base_field=goldilocks")
    e, log_d, m, blowup, terminal, queries = (
        int(row[column]) for column in ("extension_degree", "log_d", "m", "blowup",
                                        "terminal_coefficients", "num_queries"))
    if any(value < 0 or value > usize_max for value in (e, log_d, m, blowup, terminal, queries)):
        raise ValueError("pp integer outside platform usize range")
    if e not in (1, 2, 3, 5) or not 1 <= log_d < 8 * word_bytes:
        raise ValueError("unsupported extension_degree or log_d")
    d = 1 << log_d
    power_two = lambda n: n > 0 and n & (n - 1) == 0
    if m <= 0 or d % m or queries <= 0:
        raise ValueError("m must divide d and num_queries must be positive")
    k = d // m
    if not power_two(k) or k < 4 or not power_two(blowup) or blowup < 2:
        raise ValueError("k and blowup must be powers of two with k >= 4 and blowup >= 2")
    if not power_two(terminal) or terminal < 2 or terminal > k // 2:
        raise ValueError("terminal_coefficients must be a power of two in 2..k/2")
    domain = blowup * k
    if domain > usize_max:
        raise ValueError("pp arithmetic overflow")
    if domain > 1 << 32:
        raise ValueError("encoding domain exceeds Goldilocks two-adicity")
    if jb:
        numerator, denominator = (int(row[key]) for key in
                                  ("agreement_numerator", "agreement_denominator"))
        if not 0 < numerator < denominator <= (1 << 32) - 1:
            raise ValueError("agreement must satisfy 0 < numerator < denominator within u32")
        if math.gcd(numerator, denominator) != 1:
            raise ValueError("agreement fraction must be canonical (reduced)")
        if blowup * numerator * numerator <= denominator * denominator:
            raise ValueError("agreement must be strictly above the Johnson boundary")
    # Keep these intermediate and aggregate bounds in sync with core/lib.rs.
    matrix = mul(blowup, d)
    mul(matrix, 8)
    width = mul(8, e)
    mul(domain, width)
    mul(add(mul(m, width), width + 84 if jb else 32), 1)
    nodes = mul(domain, 2) - 1
    mul(nodes, 32)
    query_slots = mul(queries, 2)
    rounds = (k // terminal).bit_length() - 1
    mul(mul(query_slots, rounds), word_bytes)
    openings = min(query_slots, domain)
    row_bytes = add(mul(m, 8), vec_bytes)
    initial_bytes = mul(openings, row_bytes)
    prefix_bytes = add(mul(m, 8), mul(rounds, (4 if jb else 2) * width), mul(rounds - 1, 32), mul(terminal, width))
    framing_bytes = add(mul(openings, 10), mul(rounds, 4 * vec_bytes + 40), 128)
    auth_bytes = mul(mul(mul(openings, domain.bit_length() - 1), rounds), 32)
    scalar_bytes = mul(mul(openings, rounds), width)
    mul(add(initial_bytes, auth_bytes, scalar_bytes, prefix_bytes, framing_bytes), 1)
    identity = ("goldilocks", e, m, blowup, terminal, queries)
    return log_d, identity + ((numerator, denominator) if jb else ())


def discover_protocols(results, plonky3_results=None):
    """Discover known protocols with CSVs; missing explicit selections still fail."""
    protocols = tuple(p for p in PROTOCOLS if
                      csv_path(p, protocol_root(p, results, plonky3_results)).is_file())
    if not protocols:
        raise ValueError("no supported protocol CSVs found")
    return protocols


def comparison_fields(protocols, fields=None) -> tuple[str, ...]:
    supported = ("goldilocks",) if GOLDILOCKS_ONLY.intersection(protocols) else tuple(FIELDS)
    if fields is None:
        return supported
    if not fields or len(set(fields)) != len(fields) or any(f not in supported for f in fields):
        raise ValueError(f"selected protocols support fields={','.join(supported)}")
    return tuple(fields)


def load_means(results: Path, plonky3_results: Path | None = None,
                 protocols=("reedweave_ub",), repetitions: int | None = None,
                 threads: tuple[int, ...] | None = None,
                 fields: tuple[str, ...] | None = None,
                 log_sizes: tuple[int, ...] = LOG_SIZES,
                 rate: Fraction = Fraction(1, 2)
                 ) -> dict[Key, dict[str, float]]:
    if not protocols or any(p not in PROTOCOLS for p in protocols):
        raise ValueError("choose supported protocols")
    if repetitions is not None and repetitions <= 0:
        raise ValueError("repetitions must be positive")
    rate = Fraction(rate)
    if not 0 < rate < 1:
        raise ValueError("code rate must be between 0 and 1")
    fields = comparison_fields(protocols, fields)
    data: dict[Key, dict[str, float]] = {}
    for protocol in protocols:
        root = protocol_root(protocol, results, plonky3_results)
        required = expected_repetitions(protocol, repetitions)
        for field in fields:
            path = csv_path(protocol, root, field)
            identities = {}
            header = (JB_HEADER if protocol == "reedweave_jb" else
                      HEADER if protocol == "reedweave_ub" else PCS_HEADER)
            groups: dict[tuple[int, int], list[dict[str, str]]] = {}
            with path.open(newline="") as stream:
                reader = csv.DictReader(stream)
                if reader.fieldnames != header:
                    raise ValueError(f"{path}: unexpected CSV header")
                for row in reader:
                    if None in row or any(value is None for value in row.values()):
                        raise ValueError(f"{path}:{reader.line_num}: row must have exactly {len(header)} columns")
                    try:
                        metric_text = [row[column] for column, _, _ in METRICS]
                        missing = any(value in MISSING_MARKERS for value in metric_text)
                        if missing and (len(set(metric_text)) != 1 or metric_text[0] not in MISSING_MARKERS):
                            raise ValueError("missing rows must mark every metric consistently")
                        thread_count = int(row["threads"])
                        if protocol in REEDWEAVE_PROTOCOLS:
                            if missing:
                                log_n = int(row["log_d"])
                                if row["base_field"] != "goldilocks" or not 1 <= log_n <= 34:
                                    raise ValueError("invalid missing-row field/size")
                            else:
                                validator = validate_reedweave_jb if protocol == "reedweave_jb" else validate_reedweave_ub
                                log_n, identity = validator(row)
                            row_rate = Fraction(1, int(row["blowup"]))
                            if thread_count <= 0:
                                raise ValueError("threads must be positive")
                        else:
                            log_n = int(row["log_n"])
                            max_log_n = 34
                            if not 20 <= log_n <= max_log_n or thread_count not in (1, 32):
                                raise ValueError("unexpected size/thread configuration")
                            try:
                                row_rate = (Fraction(1, 2) if missing and protocol == "brakedown" and row["rho"] == "-"
                                            else Fraction(row["rho"]))
                            except (ValueError, ZeroDivisionError) as error:
                                raise ValueError("invalid code rate") from error
                            if not 0 < row_rate < 1:
                                raise ValueError("code rate must be between 0 and 1")
                        # Filter before campaign-identity checks and repetition grouping.
                        # Brakedown is an explicitly native-rate reference curve.
                        if protocol != "brakedown" and row_rate != rate:
                            continue
                        # Check campaign identity before thread filtering: a selected
                        # thread must not hide incompatible pp measured on another.
                        if protocol in REEDWEAVE_PROTOCOLS and not missing and log_n in log_sizes:
                            if identities.setdefault(log_n, identity) != identity:
                                raise ValueError(f"ambiguous {PROTOCOLS[protocol][0]} pp: parameters must be fixed at each log_d "
                                                 "across trials and thread counts")
                        if log_n not in log_sizes or (threads is not None and thread_count not in threads):
                            continue
                        for column, _, _ in (() if missing else METRICS):
                            value = float(row[column])
                            if not math.isfinite(value) or value < 0:
                                raise ValueError(f"invalid {column}")
                        if not missing and float(row["proof_size_KiB"]) <= 32.0 / 1024.0:
                            raise ValueError("invalid protocol proof size in KiB")
                    except ValueError as error:
                        raise ValueError(f"{path}:{reader.line_num}: {error}") from error
                    groups.setdefault((thread_count, log_n), []).append(row)
            for log_n, identity in sorted(identities.items()):
                columns = JB_PP_COLUMNS if protocol == "reedweave_jb" else PP_COLUMNS
                print(f"{PROTOCOLS[protocol][0]} log_d={log_n}: " + ", ".join(
                    f"{key}={value}" for key, value in zip(columns, identity)))
            if not groups:
                raise ValueError(f"{path}: no measurements")
            counts = set(threads) if threads is not None else {t for t, _ in groups}
            for thread_count in sorted(counts):
                for log_n in log_sizes:
                    rows = groups.get((thread_count, log_n), [])
                    missing_rows = [r for r in rows if r["commit_time_ms"] in MISSING_MARKERS]
                    if missing_rows:
                        if len(rows) != 1:
                            raise ValueError(f"{path}: cannot mix missing markers and measured trials")
                        data[field, thread_count, log_n, protocol] = {column: math.nan for column, _, _ in METRICS}
                        continue
                    if len(rows) != required:
                        raise ValueError(
                            f"{path}: log_n={log_n}, threads={thread_count}: "
                            f"expected {required} trials, got {len(rows)}")
                    data[field, thread_count, log_n, protocol] = {
                        column: mean(float(row[column]) for row in rows)
                        for column, _, _ in METRICS
                    }
    for field in fields:
        coverage = [{t for f, t, _, p in data if f == field and p == protocol}
                    for protocol in protocols]
        common = set.intersection(*coverage)
        if not common:
            raise ValueError(f"{field}: selected protocols have no common thread counts")
        omitted = set.union(*coverage) - common
        if omitted:
            print(f"{field}: comparing shared threads={sorted(common)}; "
                  f"omitting threads={sorted(omitted)} not available for every protocol.")
        data = {key: values for key, values in data.items()
                if key[0] != field or key[1] in common}
    return data


def load_comparison(results, plonky3_results=None, protocols=None, repetitions=None,
                    threads=None, fields=None, log_sizes=LOG_SIZES, rate=Fraction(1, 2)):
    if protocols is not None:
        return load_means(results, plonky3_results, protocols, repetitions, threads, fields, log_sizes, rate)
    selected = discover_protocols(results, plonky3_results)
    data = {}
    for field in fields or tuple(FIELDS):
        available = tuple(p for p in selected if field in comparison_fields((p,)) and
                          csv_path(p, protocol_root(p, results, plonky3_results), field).is_file())
        if not available:
            if fields is not None:
                raise ValueError(f"no protocol CSVs found for requested field {field}")
            continue
        print(f"{field}: available protocols={','.join(available)}")
        data.update(load_means(results, plonky3_results, available, repetitions,
                                 threads, (field,), log_sizes, rate))
    if not data:
        raise ValueError("no supported field CSVs found")
    return data


def axis_limits(data: dict[Key, dict[str, float]], profile: str, metric: str):
    values = [metrics[metric] for key, metrics in data.items()
              if key[0] == profile and math.isfinite(metrics[metric])]
    if not values:
        return 1.0, 2.0
    if min(values) == 0:
        # Axis padding only: preserve the actual zeros in plotted data and means.
        return 0.0, max(values) * 1.07 if max(values) > 0 else 1.0
    low, high = math.log2(min(values)), math.log2(max(values))
    padding = max((high - low) * 0.07, math.log2(1.035))
    return 2.0 ** math.floor(low - padding), 2.0 ** math.ceil(high + padding)


def configure_y_axis(ax, title: str, unit: str, limits):
    from matplotlib.ticker import FixedLocator, FuncFormatter, NullFormatter

    if limits[0] == 0:
        ax.set_yscale("linear")
        ax.text(0.02, 0.97, "Linear scale (includes zero timings)",
                transform=ax.transAxes, va="top", fontsize=8, color="#555555")
    else:
        ax.set_yscale("log", base=2)
        low, high = (round(math.log2(bound)) for bound in limits)
        step = max(1, math.ceil((high - low) / 8))
        exponents = sorted(set(range(low, high + 1, step)) | {high})
        ax.yaxis.set_major_locator(FixedLocator([2.0 ** exponent for exponent in exponents]))
        ax.yaxis.set_major_formatter(FuncFormatter(
            lambda value, _position: rf"$2^{{{round(math.log2(value))}}}$"
        ))
    ax.set_ylim(*limits)
    ax.set_ylabel(f"{title} ({unit})")
    ax.yaxis.set_minor_locator(FixedLocator([]))
    ax.yaxis.set_minor_formatter(NullFormatter())
    ax.grid(axis="both", which="major", color="#D9DEE5", linewidth=0.7)
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)


def plot_profile(data, profile: str, threads: int, out: Path, dpi: int,
                 protocols=("reedweave_ub",), log_sizes=LOG_SIZES, rate=Fraction(1, 2)) -> Path:
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(2, 2, figsize=(13.2, 9.0))
    rate = Fraction(rate)
    fig.subplots_adjust(left=0.095, right=0.98, top=0.92, bottom=0.09, hspace=0.30, wspace=0.30)
    for ax, (metric, title, unit) in zip(axes.flat, METRICS):
        for protocol in protocols:
            name, color = PROTOCOLS[protocol]
            # Format only the legend; keep the CSV directory name unchanged.
            label = (rf"ReedWeave$_{{\mathrm{{{protocol[-2:].upper()}}}}}$"
                     if protocol in REEDWEAVE_PROTOCOLS else name)
            values = [data[profile, threads, n, protocol][metric] for n in log_sizes]
            ax.plot(log_sizes, values, color=color, label=label, linestyle="-", linewidth=1.8,
                    marker="o", markersize=5, markeredgecolor="white", markeredgewidth=0.6)
        configure_y_axis(ax, title, unit, axis_limits(data, profile, metric))
        ax.set_xlim(log_sizes[0] - 0.3, log_sizes[-1] + 0.3)
        ax.set_xticks(log_sizes, [rf"$2^{{{n}}}$" for n in log_sizes])
        ax.set_xlabel("Number of constraints", labelpad=7)
    handles, labels = axes.flat[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 0.99),
               bbox_transform=fig.transFigure, ncol=len(protocols), frameon=False,
               fontsize=10, handlelength=3, columnspacing=2)
    path = out / profile / f"threads_{threads}_rate_{rate.numerator}_{rate.denominator}.png"
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=dpi, facecolor="white", metadata={"Software": "PCS plot_results.py"})
    plt.close(fig)
    return path


def parse_protocols(value: str) -> tuple[str, ...] | None:
    if value.strip().lower() == "all":
        return None
    protocols = tuple(part.strip().lower() for part in value.split(","))
    if any(p not in PROTOCOLS for p in protocols) or len(set(protocols)) != len(protocols):
        raise argparse.ArgumentTypeError("choose all or distinct protocols from " + ",".join(PROTOCOLS))
    return protocols


def parse_rate(value: str) -> Fraction:
    try:
        rate = Fraction(value)
    except (ValueError, ZeroDivisionError) as error:
        raise argparse.ArgumentTypeError("choose a rational code rate, e.g. 1/4") from error
    if not 0 < rate < 1:
        raise argparse.ArgumentTypeError("code rate must be between 0 and 1")
    return rate


def parse_fields(value: str) -> tuple[str, ...]:
    fields = tuple(part.strip() for part in value.split(","))
    if not fields or any(f not in FIELDS for f in fields) or len(set(fields)) != len(fields):
        raise argparse.ArgumentTypeError("choose goldilocks")
    return fields


def parse_threads(value: str) -> tuple[int, ...]:
    try:
        counts = tuple(int(part.strip()) for part in value.split(","))
    except ValueError as error:
        raise argparse.ArgumentTypeError("choose positive thread counts") from error
    if not counts or any(t <= 0 for t in counts) or len(set(counts)) != len(counts):
        raise argparse.ArgumentTypeError("choose distinct positive thread counts")
    return counts


def parse_log_sizes(value):
    try:
        if ".." in value:
            lo, hi = (int(part.strip()) for part in value.split(".."))
            if not 1 <= lo <= hi <= 63:
                raise ValueError("range must be within 1..63")
            sizes = tuple(range(lo, hi + 1))
        else:
            sizes = tuple(int(part.strip()) for part in value.split(","))
    except ValueError as error:
        raise argparse.ArgumentTypeError("choose distinct positive size exponents") from error
    if not sizes or any(n <= 0 for n in sizes) or len(set(sizes)) != len(sizes):
        raise argparse.ArgumentTypeError("choose distinct positive size exponents")
    return tuple(sorted(sizes))


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=root / "results",
                        help="CSV root containing protocol directories (default: results/)")
    parser.add_argument("--plonky3-results", type=Path,
                        help="Optional separate root for FRI/STIR/WHIR (default: --results)")
    parser.add_argument("--protocols", type=parse_protocols,
                        help="all (default: discover existing CSVs) or comma-separated protocols: " + ",".join(PROTOCOLS))
    parser.add_argument("--fields", type=parse_fields,
                        help="Base fields (default: available fields for all; common supported fields for explicit protocols)")
    parser.add_argument("--threads", type=parse_threads,
                        help="Thread counts, e.g. 32 or 1,32 (default: shared counts per field)")
    parser.add_argument("--rate", type=parse_rate, default=Fraction(1, 2),
                        help="Select initial code rate (default: 1/2); Brakedown keeps its native rate")
    parser.add_argument("--repetitions", type=int,
                        help="Override required records per configuration for every protocol (defaults: Brakedown/Shockwave 1, others 5)")
    parser.add_argument("--out", type=Path,
                        help="Figure root; writes <out>/<base_field>/threads_<count>_rate_<num>_<den>.png. "
                             "Default: <results>/figures")
    parser.add_argument("--log-sizes", "--log-d", type=parse_log_sizes, default=LOG_SIZES,
                        help="Size exponent list or inclusive range, e.g. 1,2,3 or 1..3 (default: 20..34); ReedWeave UB/JB log_d, others native log_n")
    parser.add_argument("--dpi", type=int, default=220)
    parser.add_argument("--validate-only", action="store_true",
                        help="Validate CSV completeness without importing Matplotlib or plotting")
    args = parser.parse_args()
    if args.dpi <= 0 or (args.repetitions is not None and args.repetitions <= 0):
        parser.error("--dpi and --repetitions must be positive")
    try:
        data = load_comparison(args.results, args.plonky3_results, args.protocols,
                               args.repetitions, args.threads, args.fields, args.log_sizes, args.rate)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    configurations = sorted({(profile, threads) for profile, threads, _, _ in data})
    protocols = tuple(p for p in PROTOCOLS if any(key[3] == p for key in data))
    records = sum(expected_repetitions(key[3], args.repetitions)
                  if all(math.isfinite(v) for v in metrics.values()) else 1
                  for key, metrics in data.items())
    print("Timing models are not encoded in CSV paths/columns; check logs and do not mix old and new times.")
    print(f"Validated {len(data)} configurations, {records} input records "
          f"in {len({(f, p) for f, _, _, p in data})} CSVs; protocols={','.join(protocols)}.")
    print("Cross-protocol inputs, security assumptions and PoW can differ; compare native configurations, not identical tasks.")
    for protocol in protocols:
        if protocol in REEDWEAVE_PROTOCOLS:
            print(f"{PROTOCOLS[protocol][0]}: structural pp validation only; security strength has not been assessed. "
                  "No Fiat–Shamir security certification is implied.")
    for protocol in protocols:
        if protocol in SINGLE_RECORD_PROTOCOLS:
            print(f"{PROTOCOLS[protocol][0]}: one supplied record per size by default, "
                  "not five repeated measurements.")
    if args.validate_only:
        return
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11, "axes.labelsize": 10.5,
                         "xtick.labelsize": 10, "ytick.labelsize": 10})
    for profile, threads in configurations:
        plotted = tuple(p for p in protocols if (profile, threads, args.log_sizes[0], p) in data)
        print(plot_profile(data, profile, threads, args.out or args.results / "figures",
                           args.dpi, plotted, args.log_sizes, args.rate))
    print(f"Generated {len(configurations)} figures; raw CSV files were not modified.")


# Unified measurement workflow; original plotting API above remains unchanged.

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_PROTOCOLS = tuple(name for name, _ in PROTOCOLS.values())
BENCHMARK_METRICS = tuple(column for column, _, _ in METRICS)
BENCHMARK_RW = {PROTOCOLS[key][0] for key in REEDWEAVE_PROTOCOLS}
BENCHMARK_P3 = {PROTOCOLS[key][0] for key in PLONKY3_PROTOCOLS}
BENCHMARK_SECURITY = UNSATISFIED_SECURITY_PARAMETER
BENCHMARK_MISSING = MISSING_MARKERS


def _benchmark_save(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n")
    temporary.replace(path)


def _benchmark_load(path):
    return json.loads(Path(path).read_text())


def _benchmark_read_csv(path):
    with Path(path).open(newline="") as stream:
        reader = csv.DictReader(stream)
        return reader.fieldnames, list(reader)


def _benchmark_utc():
    return datetime.now(timezone.utc).isoformat()


def _benchmark_classify_failure(text):
    lower = text.lower()
    if any(s in lower for s in ("security budget", "algebraic security", "insufficientfield", "cannot certify", "field error floor", "field too small", "exceeds target", "insufficient field", "cannot meet", "insufficientfieldorder")):
        return BENCHMARK_SECURITY
    if any(s in lower for s in ("two-adicity", "two_adicity", "fft exceeds", "initial domain exceeds")):
        return "domain limit"
    if any(s in lower for s in ("memory allocation", "could not allocate", "failed to allocate", "cannot allocate memory", "tryreserveerror", "allocationfailed", "allocerror", "out of memory", "allocation failure", "allocation failed")):
        return "memory limit"
    return "runtime failure"


def _benchmark_case_dir(campaign, case):
    return campaign / "cases" / case["id"]


def _benchmark_command_for(campaign, case):
    d = _benchmark_case_dir(campaign, case)
    p, t, n, rate = case["pcs"], case["threads"], case["log_d"], case["rate"]
    b = campaign / "binaries"
    env = {}
    cwd = REPOSITORY_ROOT
    if p in BENCHMARK_RW:
        command = [str(b / (p + ".bin")), "run", "--config", str(d / "config.toml"), "--allow-memory-overcommit", "--no-binding"]
    elif p in BENCHMARK_P3:
        command = [str(b / ("plonky3_" + rate.replace("/", "_") + ".bin")), "run", "--protocol", p.lower(), "--field", "goldilocks", "--log-n", str(n), "--threads", str(t), "--repetitions", "5", "--seed", "20260906", "--allow-memory-overcommit", "--out", str(d / "native")]
    elif p == "BaseFold":
        command = [str(b / ("BaseFold_" + rate.replace("/", "_") + ".bin"))]
        env = {"BASEFOLD_MIN_VARS": str(n), "BASEFOLD_MAX_VARS": str(n), "BASEFOLD_THREADS": str(t), "BASEFOLD_SAMPLES": "5", "BASEFOLD_CSV": str(d / "raw.csv")}
        cwd = Path(case["repository"])
    else:
        command = [str(b / (p + ".bin")), "--min-log", str(n), "--max-log", str(n), "--threads", str(t), "--warmup", "1", "--repetitions", "3", "--seed", "0"]
        if p == "Shockwave":
            command += ["--rate", rate]
    return command, env, str(cwd)


def _benchmark_plan(args):
    """Plan the normal size range; reuse every existing case unless --rerun."""
    campaign = args.campaign.resolve()
    campaign.mkdir(parents=True, exist_ok=False)
    cases, sources = [], {}
    for p in BENCHMARK_PROTOCOLS:
        path = args.results.resolve() / p / "goldilocks.csv"
        original = path.read_bytes()
        header, rows = _benchmark_read_csv(path)
        expected_header = JB_HEADER if p == "ReedWeave_JB" else HEADER if p in BENCHMARK_RW else PCS_HEADER
        if header != expected_header:
            raise ValueError(f"{path}: unexpected CSV header")
        backup = campaign / "baseline" / p / "goldilocks.csv"
        backup.parent.mkdir(parents=True)
        backup.write_bytes(original)
        sources[p] = {"path": str(path), "sha256": hashlib.sha256(original).hexdigest(), "bytes": len(original), "header": header}
        series = {}
        for r in rows:
            n = int(r.get("log_d", r.get("log_n")))
            rate = str(Fraction(1, int(r["blowup"]))) if p in BENCHMARK_RW else r["rho"]
            if p == "Brakedown":
                rate = "native"
            key = (rate, int(r["threads"]))
            series.setdefault(key, {}).setdefault(n, []).append(r)
        for (rate, threads), sizes in series.items():
            if threads not in (1, 32):
                raise ValueError(f"{p}: unsupported thread count {threads}")
            for n in range(args.min_log, args.max_log + 1):
                present = sizes.get(n, [])
                if present:
                    markers = [r["commit_time_ms"] in BENCHMARK_MISSING for r in present]
                    required = 1 if any(markers) or p in ("Shockwave", "Brakedown") else 5
                    if len(present) != required or (any(markers) and not all(markers)):
                        raise ValueError(f"{p} {rate} t{threads} d{n}: incomplete or conflicting existing records")
                    for r in present:
                        values = [r[k] for k in BENCHMARK_METRICS]
                        if any(v in BENCHMARK_MISSING for v in values):
                            if len(set(values)) != 1:
                                raise ValueError("inconsistent existing missing-data markers")
                        elif not all(math.isfinite(float(v)) and float(v) >= 0 for v in values):
                            raise ValueError("invalid existing measured metric")
                # Use the exact original per-size profile when available, not a
                # single late-size profile for every size of the ordinary sweep.
                reference_n = max((v for v in sizes if v <= n), default=min(sizes))
                template = sizes[reference_n][0]
                rate_id = rate.replace("/", "_")
                existing = bool(present) and not args.rerun
                case = {"id": f"{p}/{rate_id}/t{threads}/d{n}", "series": f"{p}/{rate_id}/t{threads}", "pcs": p, "rate": rate, "threads": threads, "log_d": n, "template": template, "status": "existing" if existing else "pending", "attempted": False}
                if existing:
                    case["reason"] = "existing measured or unavailable result preserved; no duplicate measurement"
                if p in BENCHMARK_RW:
                    pp = {k: (v if k == "base_field" or v == "-" else int(v)) for k, v in template.items() if k not in BENCHMARK_METRICS and k != "threads"}
                    pp["log_d"] = n
                    case["pp"] = pp
                elif p == "BaseFold":
                    case["repository"] = str(args.basefold.resolve())
                elif p in ("Shockwave", "Brakedown"):
                    case["repository"] = str(args.lcpc.resolve())
                cases.append(case)
    cases.sort(key=lambda c: (c["log_d"], -c["threads"], BENCHMARK_PROTOCOLS.index(c["pcs"]), c["rate"]))
    manifest = {"created": _benchmark_utc(), "results": str(args.results.resolve()), "basefold": str(args.basefold.resolve()), "lcpc": str(args.lcpc.resolve()), "memory_limit_gib": args.memory_limit_gib, "min_log": args.min_log, "max_log": args.max_log, "rerun": args.rerun, "staged_directory": "staged", "sources": sources, "cases": cases}
    _benchmark_save(campaign / "manifest.json", manifest)
    for c in cases:
        d = _benchmark_case_dir(campaign, c)
        d.mkdir(parents=True)
        if c["pcs"] in BENCHMARK_RW:
            if c["status"] != "existing":
                # Keep extension/geometry fixed; only resolve the certified Q.
                command = [sys.executable, str(REPOSITORY_ROOT / "scripts" / ("reedweave_" + c["pcs"][-2:].lower() + "_queries.py")), "--security-bits", "100", "--json"]
                for k, v in c["pp"].items():
                    if k != "num_queries":
                        command += ["--" + k.replace("_", "-"), str(v)]
                resolved = subprocess.run(command, cwd=REPOSITORY_ROOT, capture_output=True, text=True)
                (d / "parameter.log").write_text(resolved.stderr)
                if resolved.returncode:
                    c["status"] = _benchmark_classify_failure(resolved.stderr)
                    if c["status"] == "runtime failure":
                        raise RuntimeError(f"Unrecognized parameter failure for {c['id']}: {resolved.stderr}")
                    c["reason"] = resolved.stderr.strip()
                    c["pp"]["num_queries"] = "-"
                else:
                    certificate = json.loads(resolved.stdout)
                    (d / "certificate.json").write_text(resolved.stdout)
                    c["pp"]["num_queries"] = certificate["num_queries"]
            text = "[pp]\n" + "\n".join(f"{k} = {json.dumps(v)}" for k, v in c["pp"].items())
            text += f'\n\n[benchmark]\nthreads = [{c["threads"]}]\nrepetitions = 5\nverify_repetitions = 32\nseed = 20260906\noutput_dir = "{d / "native"}"\n'
            (d / "config.toml").write_text(text)
        if c["status"] == "pending" and c["pcs"] in BENCHMARK_P3 and c["log_d"] > 32:
            c.update(status="domain limit", reason="native benchmark input cap is log_d=32")
        command, env, cwd = _benchmark_command_for(campaign, c)
        _benchmark_save(d / "command.json", {"argv": command, "env": env, "cwd": cwd})
    _benchmark_save(campaign / "manifest.json", manifest)
    commands = ["#!/usr/bin/env bash", "# Normal PCS measurement workflow (existing cases are reused unless --rerun)."]
    for c in cases:
        cmd = [sys.executable, str(REPOSITORY_ROOT / "scripts/plot_results.py"), "benchmark", "execute-case", "--campaign", str(campaign), "--case-id", c["id"]]
        commands += [f"# {c['id']} initial status: {c['status']}", shlex.join(cmd)]
    (campaign / "commands.sh").write_text("\n".join(commands) + "\n")
    (campaign / "policy.txt").write_text("Standard range 20..34; exact existing per-size profiles retained. Existing measurements and failure markers are reused by default. --rerun writes a separate fresh result set and never duplicates main CSV rows. No estimate-based RAM admission. Actual attempts use a process-local RLIMIT_AS cap. Native-domain/security validation retained. A real memory failure skips larger cases only in the same series.\n")
    _benchmark_stage(campaign, manifest)
    print(f"Planned {len(cases)} configurations in {campaign}")

def _benchmark_build(args):
    campaign = args.campaign.resolve()
    manifest = _benchmark_load(campaign / "manifest.json")
    binaries = campaign / "binaries"
    binaries.mkdir(exist_ok=True)
    records = []
    if not any(c["status"] == "pending" for c in manifest["cases"]):
        _benchmark_save(campaign / "builds.json", records)
        print("All requested cases are already recorded or unavailable; no build needed.")
        return

    def cargo(cwd, argv, name, target):
        with (campaign / ("build_" + name + ".log")).open("w") as log:
            subprocess.run(argv, cwd=cwd, stdout=log, stderr=log, check=True)
        source = Path(cwd) / target
        destination = binaries / (name + ".bin")
        shutil.copy2(source, destination)
        records.append({"name": name, "command": argv, "cwd": str(cwd), "sha256": hashlib.sha256(destination.read_bytes()).hexdigest()})

    for name, package in (("ReedWeave_UB", "reedweave-ub-bench"), ("ReedWeave_JB", "reedweave-jb-bench")):
        cargo(REPOSITORY_ROOT, ["cargo", "build", "--release", "--locked", "--offline", "-p", package], name, "target/release/" + package)
    for rate in ("1_4", "1_2"):
        flags = ["--features", "rate-half"] if rate == "1_2" else []
        cargo(REPOSITORY_ROOT, ["cargo", "build", "--release", "--locked", "--offline", "-p", "plonky3-pcs-bench"] + flags, "plonky3_" + rate, "target/release/plonky3-pcs-bench")
    external = Path(manifest["basefold"])
    for rate in ("1_4", "1_2"):
        features = "parallel" + (",benchmark-rate-half" if rate == "1_2" else "")
        command = ["cargo", "+nightly-2025-08-18", "bench", "--locked", "--offline", "-p", "mpcs", "--bench", "basefold", "--features", features, "--no-run", "--message-format=json"]
        output = subprocess.run(command, cwd=external, capture_output=True, text=True)
        (campaign / ("build_BaseFold_" + rate + ".log")).write_text(output.stdout + output.stderr)
        output.check_returncode()
        executable = next(json.loads(line)["executable"] for line in output.stdout.splitlines()
                          if line.startswith('{') and json.loads(line).get("reason") == "compiler-artifact"
                          and json.loads(line).get("target", {}).get("name") == "basefold" and json.loads(line).get("executable"))
        destination = binaries / ("BaseFold_" + rate + ".bin")
        shutil.copy2(executable, destination)
        records.append({"name": "BaseFold_" + rate, "command": command, "cwd": str(external), "sha256": hashlib.sha256(destination.read_bytes()).hexdigest()})
    for name, package, example in (("Shockwave", "lcpc-ligero-pc", "goldilocks_bench"), ("Brakedown", "lcpc-brakedown-pc", "brakedown_goldilocks_bench")):
        cargo(Path(manifest["lcpc"]), ["cargo", "+nightly", "build", "--release", "--locked", "--offline", "-p", package, "--example", example], name, "target/release/examples/" + example)
    _benchmark_save(campaign / "builds.json", records)
    # Capture working-tree provenance without discarding unrelated user edits.
    for name, repo in (("reedweave", REPOSITORY_ROOT), ("basefold", external), ("lcpc", Path(manifest["lcpc"]))):
        (campaign / (name + ".patch")).write_bytes(subprocess.check_output(["git", "diff", "HEAD"], cwd=repo))
        (campaign / (name + ".revision")).write_bytes(subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo))
    (campaign / "environment.txt").write_text(subprocess.check_output(["bash", "-c", "lscpu; free -h; rustc --version; sysctl kernel.numa_balancing vm.zone_reclaim_mode"], text=True))
    print("Frozen 8 executable profiles; builds completed.")


def _benchmark_bounded_exec(args):
    # This helper is launched as a separate process, so the controller never
    # inherits the limit. RLIMIT_AS applies to children and is not a RAM estimate.
    campaign = args.campaign.resolve()
    manifest = _benchmark_load(campaign / "manifest.json")
    c = next(c for c in manifest["cases"] if c["id"] == args.case_id)
    if c["status"] != "running" or not c["attempted"]:
        raise RuntimeError("internal worker requires an active controller-owned case")
    d = _benchmark_case_dir(campaign, c)
    command = _benchmark_load(d / "command.json")
    import resource
    limit = manifest["memory_limit_gib"] * 1024**3
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env = dict(os.environ)
    env.pop("REEDWEAVE_OPEN_PROFILE", None)
    env.pop("REEDWEAVE_FEASIBILITY_BYPASS_ADMISSION", None)
    env.update(command["env"])
    cpu_list = "0-31" if c["threads"] == 32 else "0"
    argv = ["/usr/bin/time", "-v", "-o", str(d / "resources.log"), "taskset", "-c", cpu_list] + command["argv"]
    with (d / "stdout.log").open("w") as out, (d / "stderr.log").open("w") as err:
        code = subprocess.call(argv, cwd=command["cwd"], env=env, stdout=out, stderr=err)
    return code


def _benchmark_convert(campaign, c):
    d, p = _benchmark_case_dir(campaign, c), c["pcs"]
    if p in BENCHMARK_RW or p in BENCHMARK_P3:
        _, rows = _benchmark_read_csv(d / "native" / p / "goldilocks.csv")
        if len(rows) != 5:
            raise ValueError(f"{c['id']}: expected five verified rows, got {len(rows)}")
        for r in rows:
            assert int(r.get("log_d", r.get("log_n"))) == c["log_d"]
            assert int(r["threads"]) == c["threads"]
            if p in BENCHMARK_RW:
                assert all(str(r[k]) == str(v) for k, v in c["pp"].items())
            else:
                assert r["rho"] == c["rate"]
    elif p == "BaseFold":
        _, raw = _benchmark_read_csv(d / "raw.csv")
        assert len(raw) == 1
        r = raw[0]
        assert int(r["samples"]) == 5 and int(r["num_vars"]) == c["log_d"] and int(r["threads"]) == c["threads"]
        assert r["merkle_hash"] == r["transcript_hash"] == "BLAKE3" and r["pow_bits"] == "0"
        assert int(r["rate_log"]) == (1 if c["rate"] == "1/2" else 2)
        assert int(r["queries"]) == (380 if c["rate"] == "1/2" else 241)
        rows = [dict(log_n=str(c["log_d"]), rho=c["rate"], threads=str(c["threads"]),
                     commit_time_ms=r[f"commit_sample_{i}_ms"], open_time_ms=r[f"open_sample_{i}_ms"], verify_time_ms=r[f"verify_sample_{i}_ms"], proof_size_KiB=f"{int(r['proof_bytes'])/1024:.3f}") for i in range(1, 6)]
    else:
        _, raw = _benchmark_read_csv(d / "stdout.log")
        assert len(raw) == 3 and {r["sample"] for r in raw} == {"0", "1", "2"}
        assert all(int(r["log_n"]) == c["log_d"] and int(r["threads"]) == c["threads"] and r["security_parameter_bits"] == "100" for r in raw)
        rates = {f"{r['rate_num']}/{r['rate_den']}" for r in raw}
        assert len(rates) == 1
        rate = rates.pop()
        if p != "Brakedown":
            assert rate == c["rate"]
        rows = [dict(log_n=str(c["log_d"]), rho=rate, threads=str(c["threads"]),
                     commit_time_ms=f"{mean(float(r['commit_ms']) for r in raw):.3f}",
                     open_time_ms=f"{mean(float(r['open_ms']) for r in raw):.3f}",
                     verify_time_ms=f"{mean(float(r['verify_ms']) for r in raw):.3f}",
                     proof_size_KiB=f"{mean(int(r['proof_bytes']) for r in raw)/1024:.3f}")]
    for r in rows:
        assert all(math.isfinite(float(r[k])) and float(r[k]) >= 0 for k in BENCHMARK_METRICS)
        assert float(r["proof_size_KiB"]) > 32 / 1024
    _benchmark_save(d / "validated_rows.json", rows)
    return rows


def _benchmark_missing_row(c):
    marker = BENCHMARK_SECURITY if c["status"] == BENCHMARK_SECURITY else "-"
    if c["pcs"] in BENCHMARK_RW:
        row = {k: str(v) for k, v in c["pp"].items()}
        row["threads"] = str(c["threads"])
    else:
        row = {"log_n": str(c["log_d"]), "rho": "-" if c["rate"] == "native" else c["rate"], "threads": str(c["threads"])}
    row.update({k: marker for k in BENCHMARK_METRICS})
    return row


def _benchmark_stage(campaign, manifest):
    # Rebuild only staged new records; reused existing rows stay in the baseline.
    counts = {}
    for p in BENCHMARK_PROTOCOLS:
        path = campaign / manifest.get("staged_directory", "extension") / p / "goldilocks.csv"
        path.parent.mkdir(parents=True, exist_ok=True)
        buffer = io.StringIO(newline="")
        writer = csv.DictWriter(buffer, fieldnames=manifest["sources"][p]["header"], lineterminator="\n")
        writer.writeheader()
        for c in manifest["cases"]:
            if c["pcs"] != p or c["status"] in ("pending", "running", "existing"):
                continue
            rows = _benchmark_load(_benchmark_case_dir(campaign, c) / "validated_rows.json") if c["status"] == "verified" else [_benchmark_missing_row(c)]
            writer.writerows(rows)
        temp = path.with_suffix(".tmp")
        temp.write_text(buffer.getvalue())
        temp.replace(path)
    for c in manifest["cases"]:
        counts[c["status"]] = counts.get(c["status"], 0) + 1
    _benchmark_save(campaign / "progress.json", {"updated": _benchmark_utc(), "counts": counts})
    with (campaign / "status.csv").open("w", newline="") as stream:
        columns = ["id", "pcs", "rate", "threads", "log_d", "status", "attempted", "reason"]
        writer = csv.DictWriter(stream, fieldnames=columns, lineterminator="\n", extrasaction="ignore")
        writer.writeheader()
        writer.writerows(manifest["cases"])


def _benchmark_execute_one(campaign, manifest, c):
    if c["status"] not in ("pending", "running"):
        return
    d = _benchmark_case_dir(campaign, c)
    # Never overwrite artifacts from an interrupted attempt. Controller crashes
    # must be inspected, not mistaken for an OOM or silently duplicated.
    if c["status"] == "running":
        raise RuntimeError(f"Interrupted running case {c['id']}; inspect worker/processes before resuming")
    c.update(status="running", attempted=True, started=_benchmark_utc())
    _benchmark_save(campaign / "manifest.json", manifest)
    _benchmark_stage(campaign, manifest)
    print(f"START {c['id']}", flush=True)
    helper = [sys.executable, str(REPOSITORY_ROOT / "scripts/plot_results.py"), "benchmark", "bounded-exec", "--campaign", str(campaign), "--case-id", c["id"]]
    code = subprocess.call(helper, cwd=REPOSITORY_ROOT)
    (d / "exit_code").write_text(str(code) + "\n")
    if code == 0:
        try:
            _benchmark_convert(campaign, c)
        except Exception as error:
            c.update(status="validation failure", reason=str(error))
        else:
            c.update(status="verified", reason="all original-count trials verified and normalized")
    else:
        text = (d / "stderr.log").read_text(errors="replace") + (d / "stdout.log").read_text(errors="replace")
        c.update(status=_benchmark_classify_failure(text), reason=f"actual bounded execution exit={code}; see logs")
    c["finished"] = _benchmark_utc()
    _benchmark_save(campaign / "manifest.json", manifest)
    _benchmark_stage(campaign, manifest)
    print(f"FINISH {c['id']}: {c['status']}", flush=True)


def _benchmark_run(args):
    import fcntl
    campaign = args.campaign.resolve()
    with (campaign / "controller.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        manifest = _benchmark_load(campaign / "manifest.json")
        if not (campaign / "builds.json").exists():
            raise RuntimeError("build must succeed before actual measurements")
        selected = [c for c in manifest["cases"] if not args.case_id or c["id"] == args.case_id]
        if not selected:
            raise ValueError("unknown case id")
        for c in selected:
            if c["status"] not in ("pending", "running"):
                continue
            failures = [f for f in manifest["cases"] if f["series"] == c["series"] and f["log_d"] < c["log_d"] and f["status"] == "memory limit" and f["attempted"]]
            if failures:
                c.update(status="skipped after memory failure", reason="larger than actual failure: " + failures[0]["id"], attempted=False)
                _benchmark_save(campaign / "manifest.json", manifest)
                _benchmark_stage(campaign, manifest)
                continue
            # execute-case does not allow bypassing the ascending memory-failure policy.
            if args.case_id and any(f["series"] == c["series"] and f["log_d"] < c["log_d"] and f["status"] in ("pending", "running") for f in manifest["cases"]):
                raise RuntimeError("run smaller pending sizes in this series first")
            _benchmark_execute_one(campaign, manifest, c)
        if all(c["status"] not in ("pending", "running") for c in manifest["cases"]):
            (campaign / "complete").write_text(_benchmark_utc() + "\n")
            if args.finalize:
                _benchmark_merge(args)
                _benchmark_plot(args)


def _benchmark_merge(args):
    campaign = args.campaign.resolve()
    manifest = _benchmark_load(campaign / "manifest.json")
    if not (campaign / "complete").exists() or any(c["status"] in ("pending", "running") for c in manifest["cases"]):
        raise RuntimeError("measurement campaign incomplete; refusing to append placeholders for unrun cases")
    # Validate all cases and all original prefixes before any append.
    prepared = []
    for p in BENCHMARK_PROTOCOLS:
        source = manifest["sources"][p]
        path = Path(source["path"])
        original = (campaign / "baseline" / p / "goldilocks.csv").read_bytes()
        assert hashlib.sha256(original).hexdigest() == source["sha256"]
        extension = campaign / manifest.get("staged_directory", "extension") / p / "goldilocks.csv"
        header, rows = _benchmark_read_csv(extension)
        assert header == source["header"]
        expected = sum(5 if c["status"] == "verified" and p not in ("Shockwave", "Brakedown") else 1 for c in manifest["cases"] if c["pcs"] == p and c["status"] != "existing")
        assert len(rows) == expected
        body = extension.read_bytes().split(b"\n", 1)[1]
        if manifest.get("rerun", False):
            # A full rerun is a fresh result set, never duplicate rows in main CSVs.
            path = campaign / "results" / p / "goldilocks.csv"
            contents = extension.read_bytes()
            if path.exists() and path.read_bytes() != contents:
                raise RuntimeError(f"{path}: refusing to overwrite conflicting fresh results")
            prepared.append((path, contents))
            continue
        current = path.read_bytes()
        if current == original + body:
            continue  # Idempotent finalize/resume.
        if current != original:
            raise RuntimeError(f"{path}: baseline changed or conflicting append; refusing overwrite")
        assert original.endswith(b"\n") and body.endswith(b"\n")
        prepared.append((path, body))
    for path, body in prepared:
        path.parent.mkdir(parents=True, exist_ok=True)
        if manifest.get("rerun", False) and path.exists():
            continue
        with path.open("xb" if manifest.get("rerun", False) else "ab") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
    (campaign / "merged").write_text(_benchmark_utc() + "\n")
    print("Validated results published; original CSV bytes preserved.")


def _benchmark_plot(args):
    campaign = args.campaign.resolve()
    manifest = _benchmark_load(campaign / "manifest.json")
    if not (campaign / "merged").exists():
        raise RuntimeError("merge first")
    results = str(campaign / "results") if manifest.get("rerun", False) else manifest["results"]
    min_log = manifest["min_log"] if manifest.get("rerun", False) else 20
    for rate in ("1/2", "1/4"):
        with (campaign / ("plot_" + rate.replace("/", "_") + ".log")).open("w") as log:
            subprocess.run([sys.executable, str(REPOSITORY_ROOT / "scripts/plot_results.py"), "--results", results, "--log-d", f"{min_log}..{manifest['max_log']}", "--rate", rate, "--threads", "1,32"], cwd=REPOSITORY_ROOT, stdout=log, stderr=log, check=True)
    (campaign / "plotted").write_text(_benchmark_utc() + "\n")


def _benchmark_main(argv=None):
    parser = argparse.ArgumentParser(prog="plot_results.py benchmark", description="Unified PCS measurement workflow (default 20..34); existing cases are reused.")
    parser.add_argument("action", choices=("plan", "build", "run", "execute-case", "bounded-exec", "merge", "plot"))
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--results", type=Path, default=REPOSITORY_ROOT / "results")
    parser.add_argument("--basefold", type=Path, default=Path.home() / "gkr-backend")
    parser.add_argument("--lcpc", type=Path, default=Path.home() / "lcpc")
    parser.add_argument("--min-log", type=int, default=20)
    parser.add_argument("--max-log", type=int, default=34)
    parser.add_argument("--memory-limit-gib", type=int, default=480)
    parser.add_argument("--case-id")
    parser.add_argument("--rerun", action="store_true", help="plan fresh measurements including existing cases; publish only to <campaign>/results")
    parser.add_argument("--finalize", action="store_true", help="after the last actual case, append validated data and overwrite figures")
    args = parser.parse_args(argv)
    if not 20 <= args.min_log <= args.max_log <= 34 or not 1 <= args.memory_limit_gib <= 480:
        parser.error("require 20<=min-log<=max-log<=34 and 1<=memory-limit-gib<=480")
    os.chdir(REPOSITORY_ROOT)
    actions = {"plan": _benchmark_plan, "build": _benchmark_build, "run": _benchmark_run, "execute-case": _benchmark_run, "merge": _benchmark_merge, "plot": _benchmark_plot}
    if args.action == "bounded-exec":
        raise SystemExit(_benchmark_bounded_exec(args))
    actions[args.action](args)



def _run_self_tests():
    """Disposable checks only; never launch a large measurement."""
    import tempfile
    import unittest
    from types import SimpleNamespace

    class WorkflowTests(unittest.TestCase):
        def test_classify_actual_errors_not_estimates(self):
            self.assertEqual(_benchmark_classify_failure("memory allocation of 123 bytes failed"), "memory limit")
            self.assertEqual(_benchmark_classify_failure("could not allocate the padded coefficient matrix"), "memory limit")
            self.assertEqual(_benchmark_classify_failure("algebraic security budget 99 < 100"), BENCHMARK_SECURITY)
            self.assertEqual(_benchmark_classify_failure("initial domain exceeds base-field two-adicity"), "domain limit")
            self.assertEqual(_benchmark_classify_failure("estimated peak exceeds admission budget"), "runtime failure")
            self.assertEqual(_benchmark_classify_failure("assertion failed: proof verification"), "runtime failure")

        def test_plot_missing_rows_are_nan_not_zero(self):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                for protocol, header in (("FRI", PCS_HEADER), ("ReedWeave_JB", JB_HEADER), ("Brakedown", PCS_HEADER)):
                    directory = root / protocol
                    directory.mkdir()
                    with (directory / "goldilocks.csv").open("w", newline="") as stream:
                        writer = csv.DictWriter(stream, fieldnames=header)
                        writer.writeheader()
                        for n, marker in ((28, None), (29, "-"), (30, BENCHMARK_SECURITY)):
                            if protocol == "ReedWeave_JB":
                                row = dict(base_field="goldilocks", extension_degree="3", log_d=str(n), m="64", blowup="2", terminal_coefficients="256", num_queries="201" if marker is None else "-", agreement_numerator="177", agreement_denominator="250", threads="32")
                            else:
                                row = dict(log_n=str(n), rho="-" if protocol == "Brakedown" and marker else "1/2", threads="32")
                            row.update({metric: marker or "1.000" for metric in BENCHMARK_METRICS})
                            writer.writerow(row)
                data = load_means(root, protocols=("fri", "reedweave_jb", "brakedown"), repetitions=1,
                                        threads=(32,), log_sizes=(28, 29, 30))
                for protocol in ("fri", "reedweave_jb", "brakedown"):
                    self.assertEqual(data["goldilocks", 32, 28, protocol]["commit_time_ms"], 1.0)
                    self.assertTrue(math.isnan(data["goldilocks", 32, 29, protocol]["commit_time_ms"]))
                    self.assertTrue(math.isnan(data["goldilocks", 32, 30, protocol]["commit_time_ms"]))
                self.assertGreater(axis_limits(data, "goldilocks", "commit_time_ms")[0], 0)
                path = plot_profile(data, "goldilocks", 32, root / "figures", 60,
                                          protocols=("fri", "reedweave_jb", "brakedown"), log_sizes=(28, 29, 30))
                self.assertTrue(path.exists())

        def test_append_preserves_bytes_and_is_idempotent(self):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                campaign = root / "campaign"
                main = root / "main"
                sources, cases = {}, []
                for p in BENCHMARK_PROTOCOLS:
                    header = JB_HEADER if p == "ReedWeave_JB" else HEADER if p in BENCHMARK_RW else PCS_HEADER
                    template = dict(base_field="goldilocks", extension_degree="3", log_d="28", m="64", blowup="2", terminal_coefficients="256", num_queries="201", threads="32") if p in BENCHMARK_RW else dict(log_n="28", rho="1/2", threads="32")
                    if p == "ReedWeave_JB":
                        template.update(agreement_numerator="177", agreement_denominator="250")
                    template.update({k: "1.000" for k in BENCHMARK_METRICS})
                    path = main / p / "goldilocks.csv"
                    path.parent.mkdir(parents=True)
                    with path.open("w", newline="") as stream:
                        writer = csv.DictWriter(stream, fieldnames=header)
                        writer.writeheader()
                        writer.writerow(template)
                    original = path.read_bytes()
                    backup = campaign / "baseline" / p / "goldilocks.csv"
                    backup.parent.mkdir(parents=True)
                    backup.write_bytes(original)
                    sources[p] = {"path": str(path), "sha256": hashlib.sha256(original).hexdigest(), "header": header}
                    c = dict(id=p + "/case", pcs=p, rate="1/2", threads=32, log_d=29, status="memory limit", attempted=True)
                    if p in BENCHMARK_RW:
                        c["pp"] = {k: v for k, v in template.items() if k not in BENCHMARK_METRICS and k != "threads"}
                        c["pp"]["log_d"] = "29"
                    cases.append(c)
                manifest = {"sources": sources, "cases": cases}
                _benchmark_save(campaign / "manifest.json", manifest)
                _benchmark_stage(campaign, manifest)
                args = SimpleNamespace(campaign=campaign)
                with self.assertRaises(RuntimeError):
                    _benchmark_merge(args)
                (campaign / "complete").write_text("complete\n")
                _benchmark_merge(args)
                first = {p: Path(sources[p]["path"]).read_bytes() for p in BENCHMARK_PROTOCOLS}
                _benchmark_merge(args)
                for p in BENCHMARK_PROTOCOLS:
                    self.assertEqual(first[p], Path(sources[p]["path"]).read_bytes())
                    self.assertTrue(first[p].startswith((campaign / "baseline" / p / "goldilocks.csv").read_bytes()))
                    self.assertEqual(len(_benchmark_read_csv(sources[p]["path"])[1]), 2)

                # Explicit reruns publish only the selected fresh data, not a
                # second copy of old/main rows. Existing main files stay intact.
                manifest["rerun"] = True
                _benchmark_save(campaign / "manifest.json", manifest)
                _benchmark_merge(args)
                _benchmark_merge(args)
                for p in BENCHMARK_PROTOCOLS:
                    self.assertEqual(first[p], Path(sources[p]["path"]).read_bytes())
                    fresh = _benchmark_read_csv(campaign / "results" / p / "goldilocks.csv")[1]
                    self.assertEqual(len(fresh), 1)
                    self.assertEqual(fresh[0]["commit_time_ms"], "-")

        def test_normal_plan_reuses_entire_range_without_measurements(self):
            from unittest import mock
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                results = root / "results"
                before = {}
                for p in BENCHMARK_PROTOCOLS:
                    header = JB_HEADER if p == "ReedWeave_JB" else HEADER if p in BENCHMARK_RW else PCS_HEADER
                    path = results / p / "goldilocks.csv"
                    path.parent.mkdir(parents=True)
                    with path.open("w", newline="") as stream:
                        writer = csv.DictWriter(stream, fieldnames=header, lineterminator="\n")
                        writer.writeheader()
                        for rate in (("native",) if p == "Brakedown" else ("1/2", "1/4")):
                            for threads in (1, 32):
                                for n in range(20, 35):
                                    if p in BENCHMARK_RW:
                                        row = dict(base_field="goldilocks", extension_degree="3",
                                                   log_d=str(n), m="32" if n < 26 else "64",
                                                   blowup="2" if rate == "1/2" else "4",
                                                   terminal_coefficients="256", num_queries="201",
                                                   threads=str(threads))
                                        if p == "ReedWeave_JB":
                                            row.update(agreement_numerator="177" if rate == "1/2" else "501",
                                                       agreement_denominator="250" if rate == "1/2" else "1000")
                                    else:
                                        row = dict(log_n=str(n), rho="42432/64540" if rate == "native" else rate, threads=str(threads))
                                    missing = p in BENCHMARK_P3 and n > 32
                                    row.update({k: "-" if missing else "1.000" for k in BENCHMARK_METRICS})
                                    count = 1 if missing or p in ("Shockwave", "Brakedown") else 5
                                    for _ in range(count):
                                        writer.writerow(row)
                    before[p] = path.read_bytes()
                args = SimpleNamespace(campaign=root / "work", results=results, basefold=root / "gkr",
                                       lcpc=root / "lcpc", min_log=20, max_log=34, memory_limit_gib=480,
                                       rerun=False, case_id=None, finalize=False)
                with mock.patch.object(subprocess, "run", side_effect=AssertionError("no measurement/build allowed")):
                    _benchmark_plan(args)
                    m = _benchmark_load(args.campaign / "manifest.json")
                    self.assertEqual(len(m["cases"]), 450)
                    self.assertTrue(all(c["status"] == "existing" for c in m["cases"]))
                    self.assertEqual(next(c for c in m["cases"] if c["id"] == "ReedWeave_JB/1_2/t32/d20")["pp"]["m"], 32)
                    self.assertEqual(next(c for c in m["cases"] if c["id"] == "ReedWeave_JB/1_2/t32/d34")["pp"]["m"], 64)
                    _benchmark_build(args)
                    _benchmark_run(args)
                    _benchmark_merge(args)
                for p in BENCHMARK_PROTOCOLS:
                    self.assertEqual((results / p / "goldilocks.csv").read_bytes(), before[p])
                    self.assertFalse(_benchmark_read_csv(args.campaign / "staged" / p / "goldilocks.csv")[1])
                commands = (args.campaign / "commands.sh").read_text()
                self.assertIn("plot_results.py benchmark execute-case", commands)
                self.assertNotIn("extend_benchmarks", commands)

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(WorkflowTests)
    return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "benchmark":
        _benchmark_main(sys.argv[2:])
    elif len(sys.argv) > 1 and sys.argv[1] == "self-test":
        raise SystemExit(_run_self_tests())
    else:
        main()
