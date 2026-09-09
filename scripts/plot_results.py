#!/usr/bin/env python3
"""Compare PCS benchmarks over log_n=20..28 (rows for 29..30 are ignored).

Read <root>/<protocol>/<base_field>.csv and plot medians of measured trials.
Write figures directly to <out>/<base_field>/threads_<count>.png;
the default output root is results/figures, with no comparison subdirectory.
Overlay selected protocols at matching base fields, sizes and thread counts.
By default, use thread counts shared by all selected protocols for each field;
--threads selects explicit counts and requires every protocol to cover them.
Every included thread count must have complete log_n=20..28 coverage.
Compact CSVs do not record seeds/revisions or trial IDs: use separate directories
for independent campaigns and retain benchmark logs for reproducibility.
"""
from __future__ import annotations

import argparse
import csv
import math
from pathlib import Path
from statistics import median

FIELDS = {"goldilocks": "Goldilocks", "f128": "F128"}
PROTOCOLS = {
    "brakefri": ("BrakeFRI", "#009E73"),
    "fri": ("FRI", "#0072B2"),
    "stir": ("STIR", "#D55E00"),
}
PCS_HEADER = "log_n,rho,threads,commit_time,prove_time,verify_time,proof_size".split(",")
HEADER = "log_n,m,k,rho,threads,commit_time,prove_time,verify_time,proof_size".split(",")
LOG_SIZES = tuple(range(20, 29))
REPETITIONS = 5
METRICS = (
    ("commit_time", "Commit time", "ms", 1000.0),
    ("prove_time", "Open time", "ms", 1000.0),
    ("verify_time", "Verify time", "ms", 1000.0),
    ("proof_size", "Proof size", "KiB", 1.0 / 1024.0),
)
Key = tuple[str, int, int, str]


def load_medians(results: Path, plonky3_results: Path | None = None,
                 protocols=("brakefri",), repetitions: int = REPETITIONS,
                 threads: tuple[int, ...] | None = None
                 ) -> dict[Key, dict[str, float]]:
    data: dict[Key, dict[str, float]] = {}
    for protocol in protocols:
        root = results if protocol == "brakefri" else plonky3_results
        if root is None:
            raise ValueError("FRI/STIR input requires --plonky3-results")
        for field in FIELDS:
            path = root / PROTOCOLS[protocol][0] / f"{field}.csv"
            header = HEADER if protocol == "brakefri" else PCS_HEADER
            groups: dict[tuple[int, int], list[dict[str, str]]] = {}
            with path.open(newline="") as stream:
                reader = csv.DictReader(stream)
                if reader.fieldnames != header:
                    raise ValueError(f"{path}: unexpected CSV header")
                for row in reader:
                    if None in row or any(value is None for value in row.values()):
                        raise ValueError(f"{path}:{reader.line_num}: row must have exactly {len(header)} columns")
                    try:
                        log_n, thread_count = int(row["log_n"]), int(row["threads"])
                        if not 20 <= log_n <= 30 or thread_count not in (1, 32):
                            raise ValueError("unexpected size/thread configuration")
                        if log_n not in LOG_SIZES or (threads is not None and thread_count not in threads):
                            continue
                        if float(row["rho"]) != 0.5:
                            raise ValueError("incompatible rate")
                        if protocol == "brakefri" and (int(row["m"]), int(row["k"])) != (
                                64, 1 << (log_n - 6)):
                            raise ValueError("incompatible BrakeFRI protocol parameters")
                        for column, _, _, _ in METRICS:
                            value = float(row[column])
                            if not math.isfinite(value) or value <= 0:
                                raise ValueError(f"invalid {column}")
                        if int(row["proof_size"]) <= 32:
                            raise ValueError("invalid protocol byte count")
                    except ValueError as error:
                        raise ValueError(f"{path}:{reader.line_num}: {error}") from error
                    groups.setdefault((thread_count, log_n), []).append(row)
            if not groups:
                raise ValueError(f"{path}: no measurements")
            counts = set(threads) if threads is not None else {t for t, _ in groups}
            for thread_count in sorted(counts):
                for log_n in LOG_SIZES:
                    rows = groups.get((thread_count, log_n), [])
                    if len(rows) != repetitions:
                        raise ValueError(
                            f"{path}: log_n={log_n}, threads={thread_count}: "
                            f"expected {repetitions} trials, got {len(rows)}")
                    data[field, thread_count, log_n, protocol] = {
                        column: median(float(row[column]) for row in rows) * conversion
                        for column, _, _, conversion in METRICS
                    }
    for field in FIELDS:
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


def axis_limits(data: dict[Key, dict[str, float]], profile: str, metric: str):
    values = [metrics[metric] for key, metrics in data.items() if key[0] == profile]
    low, high = math.log2(min(values)), math.log2(max(values))
    padding = max((high - low) * 0.07, math.log2(1.035))
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
        ax.set_xlim(LOG_SIZES[0] - 0.3, LOG_SIZES[-1] + 0.3)
        ax.set_xticks(LOG_SIZES, [rf"$2^{{{n}}}$" for n in LOG_SIZES])
        ax.set_xlabel("Number of coefficients", labelpad=7)
    handles, labels = axes.flat[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 0.99),
               bbox_transform=fig.transFigure, ncol=len(protocols), frameon=False,
               fontsize=10, handlelength=3, columnspacing=2)
    path = out / profile / f"threads_{threads}.png"
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=dpi, facecolor="white", metadata={"Software": "PCS plot_results.py"})
    plt.close(fig)
    return path


def parse_protocols(value: str) -> tuple[str, ...]:
    protocols = tuple(part.strip() for part in value.split(","))
    if any(p not in PROTOCOLS for p in protocols) or len(set(protocols)) != len(protocols):
        raise argparse.ArgumentTypeError("choose distinct protocols from brakefri,fri,stir")
    return protocols


def parse_threads(value: str) -> tuple[int, ...]:
    try:
        counts = tuple(int(part.strip()) for part in value.split(","))
    except ValueError as error:
        raise argparse.ArgumentTypeError("choose thread counts from 1,32") from error
    if not counts or any(t not in (1, 32) for t in counts) or len(set(counts)) != len(counts):
        raise argparse.ArgumentTypeError("choose distinct thread counts from 1,32")
    return counts


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=root / "results",
                        help="BrakeFRI CSV root (contains BrakeFRI/)")
    parser.add_argument("--plonky3-results", type=Path, default=root / "results",
                        help="FRI/STIR CSV root (contains FRI/ and STIR/)")
    parser.add_argument("--protocols", type=parse_protocols, default=parse_protocols("brakefri,fri,stir"),
                        help="Comma-separated protocols to overlay (default: brakefri,fri,stir)")
    parser.add_argument("--threads", type=parse_threads,
                        help="Thread counts, e.g. 32 or 1,32 (default: shared counts per field)")
    parser.add_argument("--repetitions", type=int, default=REPETITIONS,
                        help="Required measured trials per configuration (default: 5)")
    parser.add_argument("--out", type=Path,
                        help="Figure root; writes <out>/<base_field>/threads_<count>.png directly. "
                             "Default: <plonky3-results>/figures; <results>/figures for BrakeFRI only")
    parser.add_argument("--dpi", type=int, default=220)
    parser.add_argument("--validate-only", action="store_true",
                        help="Validate CSV completeness without importing Matplotlib or plotting")
    args = parser.parse_args()
    if args.dpi <= 0 or args.repetitions <= 0:
        parser.error("--dpi and --repetitions must be positive")
    try:
        data = load_medians(args.results, args.plonky3_results, args.protocols,
                            args.repetitions, args.threads)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    configurations = sorted({(profile, threads) for profile, threads, _, _ in data})
    print(f"Validated {len(data)} configurations, {len(data) * args.repetitions} measured trials "
          f"in {len(FIELDS) * len(args.protocols)} CSVs; protocols={','.join(args.protocols)}.")
    if args.validate_only:
        return
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11, "axes.labelsize": 10.5,
                         "xtick.labelsize": 10, "ytick.labelsize": 10})
    default_root = args.results if args.protocols == ("brakefri",) else args.plonky3_results
    for profile, threads in configurations:
        print(plot_profile(data, profile, threads, args.out or default_root / "figures",
                           args.dpi, args.protocols))
    print(f"Generated {len(configurations)} figures; raw CSV files were not modified.")


if __name__ == "__main__":
    main()
