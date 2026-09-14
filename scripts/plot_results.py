#!/usr/bin/env python3
"""Compare Goldilocks PCS benchmarks (default size exponents 20..28).

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
LOG_SIZES = tuple(range(20, 29))
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
                        thread_count = int(row["threads"])
                        if protocol in REEDWEAVE_PROTOCOLS:
                            validator = validate_reedweave_jb if protocol == "reedweave_jb" else validate_reedweave_ub
                            log_n, identity = validator(row)
                            row_rate = Fraction(1, int(row["blowup"]))
                            if thread_count <= 0:
                                raise ValueError("threads must be positive")
                        else:
                            log_n = int(row["log_n"])
                            max_log_n = 28 if protocol == "whir" else 30
                            if not 20 <= log_n <= max_log_n or thread_count not in (1, 32):
                                raise ValueError("unexpected size/thread configuration")
                            try:
                                row_rate = Fraction(row["rho"])
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
                        if protocol in REEDWEAVE_PROTOCOLS and log_n in log_sizes:
                            if identities.setdefault(log_n, identity) != identity:
                                raise ValueError(f"ambiguous {PROTOCOLS[protocol][0]} pp: parameters must be fixed at each log_d "
                                                 "across trials and thread counts")
                        if log_n not in log_sizes or (threads is not None and thread_count not in threads):
                            continue
                        for column, _, _ in METRICS:
                            value = float(row[column])
                            if not math.isfinite(value) or value < 0:
                                raise ValueError(f"invalid {column}")
                        if float(row["proof_size_KiB"]) <= 32.0 / 1024.0:
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
    values = [metrics[metric] for key, metrics in data.items() if key[0] == profile]
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
                        help="Size exponent list or inclusive range, e.g. 1,2,3 or 1..3 (default: 20..28); ReedWeave UB/JB log_d, others native log_n")
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
    records = sum(expected_repetitions(p, args.repetitions) for _, _, _, p in data)
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


if __name__ == "__main__":
    main()
