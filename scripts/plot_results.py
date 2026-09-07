#!/usr/bin/env python3
"""Plot the measured BrakeFRI campaign: one four-panel PNG per profile/thread count.

Plots BLAKE3 for both field profiles, log_n=20..30, discovering thread counts
from each profile's CSV.
Requires matplotlib for plotting. Reads raw CSVs without modifying them; uses
per-configuration medians, converts all times from seconds to milliseconds and proof
bytes to KiB.
"""
from __future__ import annotations

import argparse
import csv
import math
from pathlib import Path
from statistics import median

PROFILES = {
    "goldilocks_quadratic": "Goldilocks base field · quadratic challenges",
    "f128_base": "F128 base field · base-field challenges",
}
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
Key = tuple[str, int, int]  # profile, threads, log_n


def load_medians(results: Path) -> dict[Key, dict[str, float]]:
    """Require exact columns and complete size coverage for each recorded thread count."""
    data: dict[Key, dict[str, float]] = {}
    for profile in PROFILES:
        path = results / "blake3" / f"{profile}.csv"
        groups: dict[tuple[int, int], list[dict[str, str]]] = {}
        with path.open(newline="") as stream:
            reader = csv.DictReader(stream)
            if reader.fieldnames != HEADER:
                raise ValueError(f"{path}: unexpected CSV header")
            for row in reader:
                if None in row or any(value is None for value in row.values()):
                    raise ValueError(f"{path}: row must have exactly {len(HEADER)} columns")
                log_n, threads = int(row["log_n"]), int(row["threads"])
                if log_n not in LOG_SIZES or threads <= 0:
                    raise ValueError(f"{path}: unexpected size/thread configuration")
                if (int(row["m"]), int(row["k"]), float(row["rho"])) != (
                    1024, 1 << (log_n - 10), 0.5
                ):
                    raise ValueError(f"{path}: incompatible protocol parameters")
                for column, _, _, _ in METRICS:
                    value = float(row[column])
                    if not math.isfinite(value) or value <= 0:
                        raise ValueError(f"{path}: invalid {column}")
                if int(row["proof_size"]) <= 32:
                    raise ValueError(f"{path}: invalid protocol byte count")
                groups.setdefault((threads, log_n), []).append(row)
        if not groups:
            raise ValueError(f"{path}: no measurements")
        for threads in sorted({threads for threads, _ in groups}):
            for log_n in LOG_SIZES:
                rows = groups.get((threads, log_n), [])
                if len(rows) != REPETITIONS:
                    raise ValueError(
                        f"{path}: log_n={log_n}, threads={threads}: "
                        f"expected {REPETITIONS} trials, got {len(rows)}"
                    )
                data[profile, threads, log_n] = {
                    column: median(float(row[column]) for row in rows) * conversion
                    for column, _, _, conversion in METRICS
                }
    return data


def axis_limits(data: dict[Key, dict[str, float]], profile: str, metric: str):
    # Reuse limits across the selected thread figures for this profile/metric.
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


def plot_profile(data, profile: str, threads: int, out: Path, dpi: int) -> Path:
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(2, 2, figsize=(13.2, 9.0))
    fig.subplots_adjust(left=0.095, right=0.98, top=0.92, bottom=0.09, hspace=0.30, wspace=0.30)
    for ax, (metric, title, unit, _) in zip(axes.flat, METRICS):
        values = [data[profile, threads, n][metric] for n in LOG_SIZES]
        ax.plot(LOG_SIZES, values, color="#009E73", linestyle="-", linewidth=1.8)
        configure_y_axis(ax, title, unit, axis_limits(data, profile, metric))
        # Coordinates are log2(n), so label them with the corresponding counts.
        ax.set_xlim(19.7, 30.3)
        ax.set_xticks(LOG_SIZES, [rf"$2^{{{n}}}$" for n in LOG_SIZES])
        ax.set_xlabel("Number of coefficients", labelpad=7)
    path = out / profile / f"threads_{threads}.png"
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=dpi, facecolor="white", metadata={"Software": "BrakeFRI plot_results.py"})
    plt.close(fig)
    return path


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=root / "results")
    parser.add_argument("--out", type=Path, help="Default: <results>/figures")
    parser.add_argument("--dpi", type=int, default=220)
    parser.add_argument("--validate-only", action="store_true",
                        help="Validate CSV completeness without importing Matplotlib or plotting")
    args = parser.parse_args()
    if args.dpi <= 0:
        parser.error("--dpi must be positive")
    data = load_medians(args.results)
    configurations = sorted({(profile, threads) for profile, threads, _ in data})
    print(f"Validated {len(data)} configurations, {len(data) * REPETITIONS} measured trials "
          f"in {len(PROFILES)} BLAKE3 CSVs ({len(HEADER)} columns).")
    if args.validate_only:
        return

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11, "axes.labelsize": 10.5,
                         "xtick.labelsize": 10, "ytick.labelsize": 10})
    for profile, threads in configurations:
        path = plot_profile(data, profile, threads, args.out or args.results / "figures",
                            args.dpi)
        print(path)
    print(f"Generated {len(configurations)} figures; raw CSV files were not modified.")


if __name__ == "__main__":
    main()
