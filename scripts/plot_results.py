#!/usr/bin/env python3
"""Plot the measured BrakeFRI campaign: one four-panel PNG per profile/thread count.

Requires matplotlib. Reads raw CSVs without modifying them; uses per-configuration
medians, converts verifier seconds to milliseconds and proof bytes to KiB.
"""
from __future__ import annotations

import argparse
import csv
import math
from pathlib import Path
from statistics import median

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import FixedLocator, FuncFormatter, LogLocator, NullFormatter

PROFILES = {
    "goldilocks_quadratic": "Goldilocks base field · quadratic challenges",
    "f128_base": "F128 base field · base-field challenges",
}
HASHES = {
    "keccak256": ("Keccak-256", "#0072B2", "o", "-"),
    "sha256": ("SHA-256", "#D55E00", "s", "--"),
    "blake3": ("BLAKE3", "#009E73", "^", "-."),
}
THREADS = (1, 2, 4, 8, 16)
LOG_SIZES = tuple(range(20, 31))
HEADER = "log_n,m,k,rho,threads,commit_time,prove_time,verify_time,proof_size".split(",")
# Column, displayed panel title, y-axis unit, conversion, logarithmic base.
METRICS = (
    ("commit_time", "Commit time", "s", 1.0, 10),
    ("prove_time", "Prover time", "s", 1.0, 10),
    ("verify_time", "Verifier time", "ms", 1000.0, 10),
    ("proof_size", "Proof size", "KiB", 1.0 / 1024.0, 2),
)
Key = tuple[str, int, str, int]  # profile, threads, hash, log_n


def load_medians(results: Path) -> dict[Key, dict[str, float]]:
    """Require the complete current campaign before plotting it."""
    data: dict[Key, dict[str, float]] = {}
    for profile in PROFILES:
        for hash_name in HASHES:
            path = results / hash_name / f"{profile}.csv"
            groups: dict[tuple[int, int], list[dict[str, str]]] = {}
            with path.open(newline="") as stream:
                reader = csv.DictReader(stream)
                if reader.fieldnames != HEADER:
                    raise ValueError(f"{path}: unexpected CSV header")
                for row in reader:
                    log_n, threads = int(row["log_n"]), int(row["threads"])
                    if log_n not in LOG_SIZES or threads not in THREADS:
                        raise ValueError(f"{path}: unexpected size/thread configuration")
                    if (int(row["m"]), int(row["k"]), float(row["rho"])) != (
                        1024, 1 << (log_n - 10), 0.5
                    ):
                        raise ValueError(f"{path}: incompatible protocol parameters")
                    for column, _, _, _, _ in METRICS:
                        value = float(row[column])
                        if not math.isfinite(value) or value <= 0:
                            raise ValueError(f"{path}: invalid {column}")
                    if int(row["proof_size"]) <= 32:
                        raise ValueError(f"{path}: invalid protocol byte count")
                    groups.setdefault((threads, log_n), []).append(row)
            for threads in THREADS:
                for log_n in LOG_SIZES:
                    rows = groups.get((threads, log_n), [])
                    expected = 5 if log_n <= 24 else 3 if log_n <= 27 else 1
                    if len(rows) != expected:
                        raise ValueError(
                            f"{path}: log_n={log_n}, threads={threads}: "
                            f"expected {expected} trials, got {len(rows)}"
                        )
                    data[profile, threads, hash_name, log_n] = {
                        column: median(float(row[column]) for row in rows) * conversion
                        for column, _, _, conversion, _ in METRICS
                    }
    return data


def axis_limits(data: dict[Key, dict[str, float]], profile: str, metric: str):
    # Reuse limits across the five thread figures for this profile/metric.
    values = [metrics[metric] for key, metrics in data.items() if key[0] == profile]
    low, high = min(values), max(values)
    padding = max(math.log(high / low) * 0.07, math.log(1.035))
    return low / math.exp(padding), high * math.exp(padding)


def format_number(value: float, _position: int) -> str:
    return f"{value:,.0f}" if value >= 1000 else f"{value:g}"


def configure_y_axis(ax, metric: str, title: str, unit: str, base: int, limits):
    ax.set_yscale("log", base=base)
    ax.set_ylim(*limits)
    ax.set_title(title, fontsize=14, fontweight="semibold", loc="left", pad=11)
    ax.set_ylabel(f"{title} ({unit}) · log{str(base).translate(str.maketrans('0123456789', '₀₁₂₃₄₅₆₇₈₉'))} scale")
    if metric == "proof_size":
        # Half-MiB ticks keep labels readable on the narrow logarithmic range.
        step = 512
        ticks = range(math.ceil(limits[0] / step) * step, math.floor(limits[1] / step) * step + 1, step)
        ax.yaxis.set_major_locator(FixedLocator(list(ticks)))
        ax.yaxis.set_minor_locator(FixedLocator([]))
    elif metric == "verify_time":
        ticks = [m * 10.0**e for e in range(-3, 6) for m in (1, 2, 3, 4, 5, 6, 8)]
        ax.yaxis.set_major_locator(FixedLocator([t for t in ticks if limits[0] <= t <= limits[1]]))
        ax.yaxis.set_minor_locator(FixedLocator([]))
    else:
        ax.yaxis.set_major_locator(LogLocator(base=10, subs=(1.0,)))
        ax.yaxis.set_minor_locator(LogLocator(base=10, subs=(2.0, 5.0)))
    ax.yaxis.set_major_formatter(FuncFormatter(format_number))
    ax.yaxis.set_minor_formatter(NullFormatter())
    ax.grid(axis="both", which="major", color="#D9DEE5", linewidth=0.7)
    ax.grid(axis="y", which="minor", color="#EAECEF", linewidth=0.5)
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)


def plot_profile(data, profile: str, threads: int, out: Path, dpi: int) -> Path:
    fig, axes = plt.subplots(2, 2, figsize=(13.2, 9.0))
    fig.subplots_adjust(left=0.095, right=0.98, top=0.82, bottom=0.13, hspace=0.43, wspace=0.30)
    fig.suptitle(f"BrakeFRI — {PROFILES[profile]}\nThreads: {threads}", fontsize=18, fontweight="semibold", y=0.98)
    handles = [
        Line2D([], [], label=label, color=color, marker=marker, linestyle=style,
               linewidth=2, markersize=5)
        for label, color, marker, style in HASHES.values()
    ]
    fig.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, 0.89),
               ncol=3, frameon=False, columnspacing=3.0)
    for ax, (metric, title, unit, _, base) in zip(axes.flat, METRICS):
        for hash_name, (label, color, marker, style) in HASHES.items():
            values = [data[profile, threads, hash_name, n][metric] for n in LOG_SIZES]
            ax.plot(LOG_SIZES, values, label=label, color=color, marker=marker,
                    linestyle=style, linewidth=1.8, markersize=4.5,
                    markeredgewidth=0.7, markeredgecolor="white")
        configure_y_axis(ax, metric, title, unit, base, axis_limits(data, profile, metric))
        # log_n already is log2(n); a second logarithmic transform would be incorrect.
        ax.set_xlim(19.7, 30.3)
        ax.set_xticks(LOG_SIZES)
        ax.set_xlabel("log₂(# of constraints), log₂ n", labelpad=7)
    fig.text(0.5, 0.049,
             "Median per configuration · Repetitions: 5 (log₂ n = 20–24), 3 (25–27), 1 (28–30)",
             ha="center", fontsize=10, color="#424B57")
    fig.text(0.5, 0.026,
             "For this standalone PCS, n is the coefficient count. Proof size includes commitment + evaluation proof.",
             ha="center", fontsize=9.5, color="#59636F")
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
    args = parser.parse_args()
    if args.dpi <= 0:
        parser.error("--dpi must be positive")
    data = load_medians(args.results)
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11, "axes.labelsize": 10.5,
                         "xtick.labelsize": 10, "ytick.labelsize": 10})
    for profile in PROFILES:
        for threads in THREADS:
            path = plot_profile(data, profile, threads, args.out or args.results / "figures", args.dpi)
            print(path)
    print("Generated 10 figures from 1,110 measured trials; raw CSV files were not modified.")


if __name__ == "__main__":
    main()
