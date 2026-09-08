#!/usr/bin/env python3
"""Compare BrakeFRI, FRI and STIR: one four-panel PNG per base field/thread count.

Select protocols with --protocols (default: brakefri,fri,stir). --results supplies
BrakeFRI CSVs; --plonky3-results supplies FRI/STIR CSVs. Each selected protocol
must cover log_n=20..30 with matching thread counts and the requested repetitions.
Plots medians, converting seconds to milliseconds and proof bytes to KiB.
"""
from __future__ import annotations

import argparse
import csv
import math
from pathlib import Path
from statistics import median

FIELDS = {"goldilocks": "Goldilocks", "f128": "F128"}
BRAKEFRI_PROFILES = {"goldilocks": "goldilocks_quadratic", "f128": "f128_base"}
EXTENSIONS = {
    "brakefri": {"goldilocks": 2, "f128": 1},
    "fri": {"goldilocks": 3, "f128": 2},
    "stir": {"goldilocks": 3, "f128": 2},
}
# Okabe-Ito colors, shared by every figure and metric.
PROTOCOLS = {
    "brakefri": ("BrakeFRI", "#009E73"),
    "fri": ("FRI", "#0072B2"),
    "stir": ("STIR", "#D55E00"),
}
PCS_HEADER = (
    "protocol,base_field,extension_degree,log_n,rate,queries_by_round,radii_by_round,"
    "terminal_coefficients,target_bits,algebraic_bound_bits,pow_bits,threads,seed,"
    "repetition,commit_time,prove_time,verify_time,commitment_size,opening_proof_size,"
    "proof_size,plonky3_revision"
).split(",")
LOG_SIZES = tuple(range(20, 31))
HEADER = "log_n,m,k,rho,threads,commit_time,prove_time,verify_time,proof_size".split(",")
REPETITIONS = 5
# Column, y-axis label, y-axis unit, conversion.
METRICS = (
    ("commit_time", "Commit time", "ms", 1000.0),
    ("prove_time", "Eval time", "ms", 1000.0),
    ("verify_time", "Verifier time", "ms", 1000.0),
    ("proof_size", "Proof size", "KiB", 1.0 / 1024.0),
)
Key = tuple[str, int, int, str]  # base field, threads, log_n, protocol


def validate_pcs_row(row, protocol: str, field: str, log_n: int, path: Path):
    terminal = 128 if protocol == "fri" else 1 << (log_n % 2)
    if (row["protocol"], row["base_field"], int(row["extension_degree"]),
            float(row["rate"]), int(row["terminal_coefficients"]),
            int(row["target_bits"]), int(row["pow_bits"])) != (
            protocol, field, EXTENSIONS[protocol][field], 0.5, terminal, 100, 0):
        raise ValueError(f"{path}: incompatible protocol/field parameters")
    bound = float(row["algebraic_bound_bits"])
    if not math.isfinite(bound) or bound < 100:
        raise ValueError(f"{path}: invalid algebraic security bound")
    queries = [int(value) for value in row["queries_by_round"].split(";")]
    radii = [float(value) for value in row["radii_by_round"].split(";")]
    rounds = 1 if protocol == "fri" else log_n // 2
    if (len(queries) != rounds or len(radii) != rounds
            or any(q <= 0 for q in queries)
            or any(not math.isfinite(r) or not 0 < r < 1 for r in radii)
            or (protocol == "fri" and queries != [244])):
        raise ValueError(f"{path}: invalid query/radius schedule")
    commitment, opening, total = (int(row[key]) for key in (
        "commitment_size", "opening_proof_size", "proof_size"))
    if commitment != (33 if protocol == "fri" else 34) or opening <= 0 or total != commitment + opening:
        raise ValueError(f"{path}: inconsistent serialized proof sizes")
    revision = row["plonky3_revision"]
    if len(revision) != 40 or any(c not in "0123456789abcdef" for c in revision):
        raise ValueError(f"{path}: invalid Plonky3 revision")
    seed = int(row["seed"])
    if not 0 <= seed < 1 << 64:
        raise ValueError(f"{path}: invalid fixture seed")
    return seed, revision


def load_medians(results: Path, plonky3_results: Path | None = None,
                 protocols=("brakefri",), repetitions: int = REPETITIONS
                 ) -> dict[Key, dict[str, float]]:
    """Validate each input independently, then require matching comparison coverage."""
    data: dict[Key, dict[str, float]] = {}
    campaigns: dict[str, set[tuple[int, str]]] = {field: set() for field in FIELDS}
    for protocol in protocols:
        for field in FIELDS:
            if protocol == "brakefri":
                path = results / "blake3" / f"{BRAKEFRI_PROFILES[field]}.csv"
                header = HEADER
            else:
                if plonky3_results is None:
                    raise ValueError("FRI/STIR input requires --plonky3-results")
                path = (plonky3_results / protocol / "blake3"
                        / f"{field}_extension{EXTENSIONS[protocol][field]}.csv")
                header = PCS_HEADER
            groups: dict[tuple[int, int], list[dict[str, str]]] = {}
            with path.open(newline="") as stream:
                reader = csv.DictReader(stream)
                if reader.fieldnames != header:
                    raise ValueError(f"{path}: unexpected CSV header")
                for row in reader:
                    if None in row or any(value is None for value in row.values()):
                        raise ValueError(f"{path}: row must have exactly {len(header)} columns")
                    try:
                        log_n, threads = int(row["log_n"]), int(row["threads"])
                        if log_n not in LOG_SIZES or threads <= 0:
                            raise ValueError("unexpected size/thread configuration")
                        if protocol == "brakefri":
                            if (int(row["m"]), int(row["k"]), float(row["rho"])) != (
                                    64, 1 << (log_n - 6), 0.5):
                                raise ValueError("incompatible BrakeFRI protocol parameters")
                        else:
                            campaigns[field].add(validate_pcs_row(row, protocol, field, log_n, path))
                            if threads not in (1, 32):
                                raise ValueError("FRI/STIR threads must be 1 or 32")
                        for column, _, _, _ in METRICS:
                            value = float(row[column])
                            if not math.isfinite(value) or value <= 0:
                                raise ValueError(f"invalid {column}")
                        if int(row["proof_size"]) <= 32:
                            raise ValueError("invalid protocol byte count")
                    except ValueError as error:
                        raise ValueError(f"{path}:{reader.line_num}: {error}") from error
                    groups.setdefault((threads, log_n), []).append(row)
            if not groups:
                raise ValueError(f"{path}: no measurements")
            for threads in sorted({threads for threads, _ in groups}):
                for log_n in LOG_SIZES:
                    rows = groups.get((threads, log_n), [])
                    if len(rows) != repetitions:
                        raise ValueError(
                            f"{path}: log_n={log_n}, threads={threads}: "
                            f"expected {repetitions} trials, got {len(rows)}")
                    if protocol != "brakefri":
                        if sorted(int(row["repetition"]) for row in rows) != list(range(1, repetitions + 1)):
                            raise ValueError(f"{path}: duplicate or missing repetition IDs at {threads=}, {log_n=}")
                        settings = {tuple(row[key] for key in (
                            "queries_by_round", "radii_by_round", "algebraic_bound_bits")) for row in rows}
                        if len(settings) != 1:
                            raise ValueError(f"{path}: mixed parameters within a configuration")
                    data[field, threads, log_n, protocol] = {
                        column: median(float(row[column]) for row in rows) * conversion
                        for column, _, _, conversion in METRICS
                    }
    for field in FIELDS:
        if len(campaigns[field]) > 1:
            raise ValueError(f"{field}: FRI/STIR files mix fixture seeds or Plonky3 revisions")
        coverage = [{(t, n) for f, t, n, p in data if f == field and p == protocol}
                    for protocol in protocols]
        if any(cases != coverage[0] for cases in coverage[1:]):
            raise ValueError(f"{field}: selected protocols have different thread/size coverage")
    return data


def axis_limits(data: dict[Key, dict[str, float]], profile: str, metric: str):
    # Share limits across all selected protocols and threads for this base field/metric.
    values = [metrics[metric] for key, metrics in data.items() if key[0] == profile]
    low, high = math.log2(min(values)), math.log2(max(values))
    padding = max((high - low) * 0.07, math.log2(1.035))
    # Outer powers give even narrow verifier/proof ranges at least two ticks.
    return 2.0 ** math.floor(low - padding), 2.0 ** math.ceil(high + padding)


def configure_y_axis(ax, title: str, unit: str, limits):
    from matplotlib.ticker import FixedLocator, FuncFormatter, NullFormatter

    ax.set_yscale("log", base=2)
    ax.set_ylim(*limits)
    ax.set_ylabel(f"{title} ({unit})")
    low, high = (round(math.log2(bound)) for bound in limits)
    step = max(1, math.ceil((high - low) / 8))
    exponents = sorted(set(range(low, high + 1, step)) | {high})
    ax.yaxis.set_major_locator(FixedLocator([2.0 ** exponent for exponent in exponents]))
    ax.yaxis.set_major_formatter(FuncFormatter(
        lambda value, _position: rf"$2^{{{round(math.log2(value))}}}$"
    ))
    ax.yaxis.set_minor_locator(FixedLocator([]))
    ax.yaxis.set_minor_formatter(NullFormatter())
    ax.grid(axis="both", which="major", color="#D9DEE5", linewidth=0.7)
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)


def plot_profile(data, profile: str, threads: int, out: Path, dpi: int,
                 protocols=("brakefri",)) -> Path:
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(2, 2, figsize=(13.2, 9.0))
    fig.subplots_adjust(left=0.095, right=0.98, top=0.86, bottom=0.09, hspace=0.30, wspace=0.30)
    for ax, (metric, title, unit, _) in zip(axes.flat, METRICS):
        for protocol in protocols:
            name, color = PROTOCOLS[protocol]
            values = [data[profile, threads, n, protocol][metric] for n in LOG_SIZES]
            ax.plot(LOG_SIZES, values, color=color, label=name, linestyle="-", linewidth=1.8)
        configure_y_axis(ax, title, unit, axis_limits(data, profile, metric))
        # Coordinates are log2(n), so label them with the corresponding counts.
        ax.set_xlim(19.7, 30.3)
        ax.set_xticks(LOG_SIZES, [rf"$2^{{{n}}}$" for n in LOG_SIZES])
        ax.set_xlabel("Number of coefficients", labelpad=7)
    handles, labels = axes.flat[0].get_legend_handles_labels()
    # One shared protocol legend centered above all four panels.
    fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 0.99),
               bbox_transform=fig.transFigure, ncol=len(protocols), frameon=False,
               fontsize=10, handlelength=3, columnspacing=2)
    # Keep the original output layout for BrakeFRI-only campaigns.
    directory = BRAKEFRI_PROFILES[profile] if tuple(protocols) == ("brakefri",) else profile
    path = out / directory / f"threads_{threads}.png"
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=dpi, facecolor="white", metadata={"Software": "PCS plot_results.py"})
    plt.close(fig)
    return path


def parse_protocols(value: str) -> tuple[str, ...]:
    protocols = tuple(part.strip() for part in value.split(","))
    if any(p not in PROTOCOLS for p in protocols) or len(set(protocols)) != len(protocols):
        raise argparse.ArgumentTypeError("choose distinct protocols from brakefri,fri,stir")
    return protocols


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=root / "results",
                        help="BrakeFRI CSV root (contains blake3/)")
    parser.add_argument("--plonky3-results", type=Path, default=root / "results" / "plonky3",
                        help="FRI/STIR CSV root (contains fri/blake3/ and stir/blake3/)")
    parser.add_argument("--protocols", type=parse_protocols, default=parse_protocols("brakefri,fri,stir"),
                        help="Comma-separated protocols to overlay (default: brakefri,fri,stir)")
    parser.add_argument("--repetitions", type=int, default=REPETITIONS,
                        help="Required measured trials per configuration (default: 5)")
    parser.add_argument("--out", type=Path,
                        help="Default: <plonky3-results>/figures; <results>/figures for BrakeFRI only")
    parser.add_argument("--dpi", type=int, default=220)
    parser.add_argument("--validate-only", action="store_true",
                        help="Validate CSV completeness without importing Matplotlib or plotting")
    args = parser.parse_args()
    if args.dpi <= 0 or args.repetitions <= 0:
        parser.error("--dpi and --repetitions must be positive")
    try:
        data = load_medians(args.results, args.plonky3_results, args.protocols, args.repetitions)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    configurations = sorted({(profile, threads) for profile, threads, _, _ in data})
    print(f"Validated {len(data)} configurations, {len(data) * args.repetitions} measured trials "
          f"in {len(FIELDS) * len(args.protocols)} BLAKE3 CSVs; "
          f"protocols={','.join(args.protocols)}.")
    if args.validate_only:
        return

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11, "axes.labelsize": 10.5,
                         "xtick.labelsize": 10, "ytick.labelsize": 10})
    default_root = args.results if args.protocols == ("brakefri",) else args.plonky3_results
    for profile, threads in configurations:
        path = plot_profile(data, profile, threads, args.out or default_root / "figures",
                            args.dpi, args.protocols)
        print(path)
    print(f"Generated {len(configurations)} figures; raw CSV files were not modified.")


if __name__ == "__main__":
    main()
