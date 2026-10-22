"""Turn benchmark runs into tables (and optional charts) for the paper.

Run from the backend folder:
    python -m benchmarks.analyze_results
    python -m benchmarks.analyze_results --hardware-note "ASUS ROG Strix G713RC, ..."
    python -m benchmarks.analyze_results --runs benchmarks/results/RUN1 benchmarks/results/RUN2

RULES (written down here so the paper can quote them)
  1. By default only COMPLETE runs are used: preset "standard", every
     algorithm and cipher, at least 30 trials. Practice runs and the order
     tests are skipped automatically and listed with the reason.
  2. Each run gives one median per measurement. We report the median of
     those run medians, plus the lowest and highest run (the "range").
     A value is marked * when its range is wider than 25% of the median.
  3. Full-encrypt comparisons between ALGORITHMS use files up to 100 KB only.
     Larger files are excluded because the order test and the diagnostic
     showed their timings change by 40% or more with the state of the
     process and machine, not with the algorithm.
  4. 1 MB and 10 MB results appear only as CIPHER throughput (MiB/s), with
     their range. Sizes written "MB" here mean 1,048,576 bytes.

Charts need the optional library matplotlib. Without it, tables are still
written and the charts are skipped.
"""

import argparse
import csv
import json
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

from app import crypto_lab

SMALL_FULL_ENCRYPT_MAX = 100 * 1024
FULL_ENCRYPT_CIPHER = "AES-256-GCM"
UNSTABLE_PERCENT = 25.0
MIN_TRIALS = 30
MIB = 1024 * 1024
MIN_THROUGHPUT_TABLE_SIZE = 100 * 1024

KEY_OPERATIONS = [
    ("kem_keygen", "key generation"),
    ("kem_load_public", "load public key"),
    ("kem_load_private", "load private key"),
    ("kem_encapsulate", "encapsulate"),
    ("kem_decapsulate", "decapsulate"),
]


# ---------------------------------------------------------------------------
# Reading runs
# ---------------------------------------------------------------------------
def read_csv(path):
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


class Run:
    """One benchmark result folder."""

    def __init__(self, path):
        self.path = Path(path)
        self.name = self.path.name
        self.env = json.loads((self.path / "environment.json").read_text(encoding="utf-8"))
        self.summary = {}
        for row in read_csv(self.path / "summary.csv"):
            key = (row["category"], row["kem"], row["aead"], int(row["size_bytes"]))
            self.summary[key] = float(row["median_us"])
        self.sizes = read_csv(self.path / "sizes.csv")
        self.correctness = read_csv(self.path / "correctness.csv")
        self.memory = read_csv(self.path / "memory.csv")


def skip_reason(env):
    """None if the run is complete enough to use, otherwise the reason."""
    settings = env.get("settings", {})
    if settings.get("preset") != "standard":
        return "not the standard preset"
    if settings.get("trials", 0) < MIN_TRIALS:
        return f"fewer than {MIN_TRIALS} trials"
    if set(settings.get("kems", [])) != {kem.name for kem in crypto_lab.KEMS}:
        return "does not include every key-establishment algorithm"
    if set(settings.get("aeads", [])) != {aead.name for aead in crypto_lab.AEADS}:
        return "does not include every cipher"
    return None


def discover_runs(root):
    """Return (usable runs, [(folder name, reason skipped)])."""
    used, skipped = [], []
    root = Path(root)
    folders = sorted(path for path in root.iterdir() if path.is_dir()) if root.is_dir() else []
    for folder in folders:
        try:
            run = Run(folder)
        except (OSError, KeyError, ValueError) as error:
            skipped.append((folder.name, f"unreadable ({type(error).__name__}: {error})"))
            continue
        reason = skip_reason(run.env)
        if reason:
            skipped.append((folder.name, reason))
        else:
            used.append(run)
    return used, skipped


# ---------------------------------------------------------------------------
# Numbers
# ---------------------------------------------------------------------------
def size_label(size):
    if size % MIB == 0:
        return f"{size // MIB} MB"
    if size % 1024 == 0:
        return f"{size // 1024} KB"
    return f"{size} B"


def throughput_mib_per_s(size, microseconds):
    return size / MIB / (microseconds / 1e6)


def aggregate(runs, category, kem, aead, size):
    """Median of the run medians, with the lowest and highest run."""
    key = (category, kem, aead, size)
    values = [run.summary[key] for run in runs if key in run.summary]
    if not values:
        return None
    median = statistics.median(values)
    spread = (max(values) - min(values)) / median * 100 if median else 0.0
    return {
        "median": median,
        "min": min(values),
        "max": max(values),
        "runs": len(values),
        "spread_percent": spread,
        "unstable": spread > UNSTABLE_PERCENT,
    }


def cell(agg, digits=1):
    if agg is None:
        return "n/a"
    star = "*" if agg["unstable"] else ""
    return (f"{agg['median']:,.{digits}f} "
            f"({agg['min']:,.{digits}f}-{agg['max']:,.{digits}f}){star}")


def markdown_table(headers, rows):
    lines = ["| " + " | ".join(headers) + " |",
             "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(str(value) for value in row) + " |" for row in rows]
    return "\n".join(lines) + "\n"


def write_csv(path, headers, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        writer.writerows(rows)


def _round(value):
    return f"{value:.3f}"


def _flag(agg):
    return "yes" if agg["unstable"] else "no"


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------
def kem_names(runs):
    return [kem.name for kem in crypto_lab.KEMS]


def table_key_operations(runs):
    tidy, wide = [], []
    for kem in kem_names(runs):
        row = [kem]
        for category, label in KEY_OPERATIONS:
            agg = aggregate(runs, category, kem, "", 0)
            row.append(cell(agg))
            if agg:
                tidy.append([kem, label, _round(agg["median"]), _round(agg["min"]),
                             _round(agg["max"]), agg["runs"],
                             f"{agg['spread_percent']:.1f}", _flag(agg)])
        wide.append(row)
    tidy_headers = ["kem", "operation", "median_us", "min_us", "max_us", "runs",
                    "spread_percent", "unstable"]
    wide_headers = ["Algorithm"] + [label for _, label in KEY_OPERATIONS]
    return tidy_headers, tidy, markdown_table(wide_headers, wide)


FIXED_SIZE_COLUMNS = ("public_key_bytes", "kem_ciphertext_bytes",
                      "qshare02_file_overhead_bytes")


def sizes_by_kem(runs):
    """{kem: {column: [value in each run]}}"""
    table = {}
    for run in runs:
        for row in run.sizes:
            entry = table.setdefault(row["kem"], {})
            for column in FIXED_SIZE_COLUMNS + ("private_key_bytes_as_stored",):
                entry.setdefault(column, []).append(int(row[column]))
    return table


def table_sizes(runs):
    """Private-key size is a range: an RSA key's encoding length depends on
    its random primes, so it changes by a byte or two from key to key."""
    table = sizes_by_kem(runs)
    tidy, wide = [], []
    for kem in kem_names(runs):
        if kem not in table:
            continue
        entry = table[kem]
        low = min(entry["private_key_bytes_as_stored"])
        high = max(entry["private_key_bytes_as_stored"])
        tidy.append([kem, entry["public_key_bytes"][0], low, high,
                     entry["kem_ciphertext_bytes"][0],
                     entry["qshare02_file_overhead_bytes"][0]])
        wide.append([kem, entry["public_key_bytes"][0],
                     f"{low:,}" if low == high else f"{low:,}-{high:,}",
                     entry["kem_ciphertext_bytes"][0],
                     entry["qshare02_file_overhead_bytes"][0]])
    headers = ["kem", "public_key_bytes", "private_key_bytes_min",
               "private_key_bytes_max", "kem_ciphertext_bytes",
               "qshare02_file_overhead_bytes"]
    md_headers = ["Algorithm", "Public key", "Private key (as stored)",
                  "KEM ciphertext", "File overhead (QSHARE02)"]
    return headers, tidy, markdown_table(md_headers, wide)


def fixed_sizes_consistent(runs):
    """True if the sizes that must never change are identical in every run."""
    for entry in sizes_by_kem(runs).values():
        for column in FIXED_SIZE_COLUMNS:
            if len(set(entry[column])) != 1:
                return False
    return True


def small_sizes(runs):
    found = {size for run in runs for (cat, _, _, size) in run.summary
             if cat == "e2e_encrypt" and size <= SMALL_FULL_ENCRYPT_MAX}
    return sorted(found)


def table_full_encrypt_small(runs):
    sizes = small_sizes(runs)
    tidy, wide = [], []
    for kem in kem_names(runs):
        row = [kem]
        for size in sizes:
            for category, label in (("e2e_encrypt", "encrypt"), ("e2e_decrypt", "decrypt")):
                agg = aggregate(runs, category, kem, FULL_ENCRYPT_CIPHER, size)
                row.append(cell(agg))
                if agg:
                    tidy.append([kem, FULL_ENCRYPT_CIPHER, label, size,
                                 _round(agg["median"]), _round(agg["min"]),
                                 _round(agg["max"]), agg["runs"],
                                 f"{agg['spread_percent']:.1f}", _flag(agg)])
        wide.append(row)
    tidy_headers = ["kem", "cipher", "operation", "size_bytes", "median_us", "min_us",
                    "max_us", "runs", "spread_percent", "unstable"]
    wide_headers = ["Algorithm"] + [f"{size_label(size)} {label}"
                                    for size in sizes for label in ("encrypt", "decrypt")]
    return tidy_headers, tidy, markdown_table(wide_headers, wide)


def cipher_sizes(runs):
    return sorted({size for run in runs for (cat, _, _, size) in run.summary
                   if cat == "aead_encrypt"})


def table_cipher_throughput(runs):
    sizes = [size for size in cipher_sizes(runs) if size >= MIN_THROUGHPUT_TABLE_SIZE]
    tidy, wide = [], []
    for aead in (a.name for a in crypto_lab.AEADS):
        row = [aead]
        for size in sizes:
            for category, label in (("aead_encrypt", "encrypt"), ("aead_decrypt", "decrypt")):
                agg = aggregate(runs, category, "", aead, size)
                if agg is None:
                    row.append("n/a")
                    continue
                speed = {
                    "median": throughput_mib_per_s(size, agg["median"]),
                    "min": throughput_mib_per_s(size, agg["max"]),  # slowest run
                    "max": throughput_mib_per_s(size, agg["min"]),  # fastest run
                    "unstable": agg["unstable"],
                }
                row.append(cell(speed, 0))
                tidy.append([aead, label, size, _round(agg["median"]), _round(agg["min"]),
                             _round(agg["max"]), _round(speed["median"]), _round(speed["min"]),
                             _round(speed["max"]), agg["runs"],
                             f"{agg['spread_percent']:.1f}", _flag(agg)])
        wide.append(row)
    tidy_headers = ["cipher", "operation", "size_bytes", "median_us", "min_us", "max_us",
                    "median_mib_per_s", "slowest_run_mib_per_s", "fastest_run_mib_per_s",
                    "runs", "spread_percent", "unstable"]
    wide_headers = ["Cipher"] + [f"{size_label(size)} {label} (MiB/s)"
                                 for size in sizes for label in ("encrypt", "decrypt")]
    return tidy_headers, tidy, markdown_table(wide_headers, wide)


def table_memory(runs):
    by_key = {}
    for run in runs:
        for row in run.memory:
            key = (int(row["size_bytes"]), row["operation"])
            by_key.setdefault(key, []).append(int(row["peak_extra_python_bytes"]))
    tidy, wide = [], []
    for (size, operation), values in sorted(by_key.items()):
        median = statistics.median(values)
        tidy.append([size, operation, int(median), min(values), max(values),
                     len(values), f"{median / size:.2f}"])
        wide.append([size_label(size), operation, f"{int(median):,}",
                     f"{median / size:.2f}x"])
    headers = ["size_bytes", "operation", "median_peak_bytes", "min_peak_bytes",
               "max_peak_bytes", "measurements", "peak_over_file_size"]
    md = markdown_table(["File size", "Operation", "Peak extra Python memory (bytes)",
                         "Peak / file size"], wide)
    return headers, tidy, md


def correctness_report(runs):
    problems, checks = [], 0
    for run in runs:
        for row in run.correctness:
            for column in ("round_trip_ok", "tamper_detected", "wrong_key_rejected"):
                checks += 1
                if row[column] != "True":
                    problems.append(f"{run.name}: {row['kem']} / {row['aead']}: {column} = {row[column]}")
    return checks, problems


# ---------------------------------------------------------------------------
# Charts (optional)
# ---------------------------------------------------------------------------
def make_charts(out_dir, runs):
    """Write PNG charts if matplotlib is installed. Returns the file names."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return None

    written = []

    def grouped_bars(filename, title, ylabel, groups, series, log=True):
        """series: {label: [(median, low, high) or None per group]}"""
        figure, axis = plt.subplots(figsize=(11, 5))
        width = 0.8 / max(len(series), 1)
        for index, (label, points) in enumerate(series.items()):
            xs, heights, low, high = [], [], [], []
            for position, point in enumerate(points):
                if point is None:
                    continue
                xs.append(position + index * width)
                heights.append(point[0])
                low.append(point[0] - point[1])
                high.append(point[2] - point[0])
            axis.bar(xs, heights, width, yerr=[low, high], capsize=2, label=label)
        axis.set_xticks([p + 0.4 - width / 2 for p in range(len(groups))])
        axis.set_xticklabels(groups, rotation=20, ha="right")
        axis.set_ylabel(ylabel)
        axis.set_title(title)
        if log:
            axis.set_yscale("log")
        axis.legend(fontsize=8)
        axis.grid(axis="y", alpha=0.3)
        figure.tight_layout()
        figure.savefig(out_dir / filename, dpi=150)
        plt.close(figure)
        written.append(filename)

    def points(category, kem, aead, size):
        agg = aggregate(runs, category, kem, aead, size)
        return None if agg is None else (agg["median"], agg["min"], agg["max"])

    kems = kem_names(runs)
    grouped_bars(
        "chart_key_operations.png",
        "Key-establishment operations (median of runs, bars show lowest-highest run)",
        "microseconds (log scale)", kems,
        {label: [points(cat, kem, "", 0) for kem in kems] for cat, label in KEY_OPERATIONS},
    )

    sizes_rows = runs[0].sizes
    column_labels = [("public_key_bytes", "public key"),
                     ("kem_ciphertext_bytes", "KEM ciphertext"),
                     ("qshare02_file_overhead_bytes", "file overhead")]
    series = {}
    for column, label in column_labels:
        series[label] = [(float(r[column]),) * 3 for r in sizes_rows]
    grouped_bars("chart_sizes.png", "Sizes in bytes", "bytes (log scale)",
                 [r["kem"] for r in sizes_rows], series)

    small = small_sizes(runs)
    series = {}
    for size in small:
        for category, label in (("e2e_encrypt", "encrypt"), ("e2e_decrypt", "decrypt")):
            series[f"{size_label(size)} {label}"] = [
                points(category, kem, FULL_ENCRYPT_CIPHER, size) for kem in kems]
    grouped_bars("chart_full_encrypt_small_files.png",
                 f"Full encrypt/decrypt of small files ({FULL_ENCRYPT_CIPHER})",
                 "microseconds (log scale)", kems, series)

    ciphers = [a.name for a in crypto_lab.AEADS]
    series = {}
    for size in (s for s in cipher_sizes(runs) if s >= MIB):
        for category, label in (("aead_encrypt", "encrypt"), ("aead_decrypt", "decrypt")):
            values = []
            for aead in ciphers:
                agg = aggregate(runs, category, "", aead, size)
                values.append(None if agg is None else (
                    throughput_mib_per_s(size, agg["median"]),
                    throughput_mib_per_s(size, agg["max"]),
                    throughput_mib_per_s(size, agg["min"])))
            series[f"{size_label(size)} {label}"] = values
    if series:
        grouped_bars("chart_cipher_throughput.png", "Cipher throughput (higher is faster)",
                     "MiB per second", ciphers, series, log=False)
    return written


# ---------------------------------------------------------------------------
# Run summary and main
# ---------------------------------------------------------------------------
def run_summary_text(runs, skipped, hardware_note, charts, checks, problems):
    env = runs[0].env
    lines = ["# Benchmark analysis: run summary", "",
             f"Generated (UTC): {datetime.now(timezone.utc).isoformat(timespec='seconds')}", "",
             "## Runs used", ""]
    rows = [[run.name, run.env.get("started_utc", ""),
             run.env.get("settings", {}).get("trials", ""),
             run.env.get("settings", {}).get("warmup", ""),
             run.env.get("note_from_user", "")] for run in runs]
    lines.append(markdown_table(["Folder", "Started (UTC)", "Trials", "Warm-up", "Note"], rows))
    if skipped:
        lines += ["## Runs skipped", ""]
        lines += [f"- {name}: {reason}" for name, reason in skipped]
        lines.append("")
    lines += ["## Machine and software (from the first run)", "",
              f"- Hardware (typed in by the researcher): {hardware_note or 'not provided'}",
              f"- Python: {env.get('python_implementation', '')} {str(env.get('python', '')).split()[0]}",
              f"- Platform: {env.get('platform', '')}",
              f"- Processor string: {env.get('processor', '')}",
              f"- Logical CPUs: {env.get('cpu_count_logical', '')}",
              f"- cryptography library: {env.get('cryptography_version', '')}",
              f"- OpenSSL: {env.get('openssl_version', '')}",
              f"- Timer: {env.get('timer', {}).get('name', '')}"
              f" (resolution {env.get('timer', {}).get('resolution_seconds', '')} s)",
              f"- Git commit of the code: {env.get('git', {}).get('commit')}", ""]
    consistent = fixed_sizes_consistent(runs)
    lines += ["## Checks", "",
              f"- Correctness checks run: {checks}. "
              + ("All passed." if not problems else f"FAILURES: {len(problems)}"),
              f"- Public-key, ciphertext and file-overhead sizes identical in every run: {consistent}",
              "- RSA private-key size varies by a byte or two between keys (encoding length "
              "depends on the random primes), so it is reported as a range.", ""]
    lines += [f"  - {problem}" for problem in problems]
    lines += ["## Rules used", "",
              "1. Only complete standard runs are used (every algorithm and cipher, at least 30 trials).",
              "2. Each cell is the median of the run medians, with the lowest and highest run in brackets. "
              f"A * means the range is wider than {UNSTABLE_PERCENT:.0f}% of the median.",
              f"3. Full-encrypt comparisons between algorithms use files up to "
              f"{size_label(SMALL_FULL_ENCRYPT_MAX)} only ({FULL_ENCRYPT_CIPHER}). Larger files are excluded: "
              "their timings changed by 40% or more with process and machine state, not with the algorithm.",
              "4. 1 MB and 10 MB appear only as cipher throughput. MB here means 1,048,576 bytes.", ""]
    lines += ["## Known limits", "",
              "- This library has no ML-KEM-512, so only ML-KEM-768 and ML-KEM-1024 are compared.",
              "- The hybrid X25519+ML-KEM-768 joins the two secrets simply. It is not byte-identical to the TLS construction.",
              "- Memory numbers come from tracemalloc and cover Python allocations only, not memory inside OpenSSL.",
              "- Key loading time is reported separately. RSA validates the private key on load, which dominates its cost.",
              "- Results come from one laptop. Speeds depend on the CPU, power mode and library versions.", ""]
    if charts is None:
        lines.append("Charts were skipped because matplotlib is not installed.\n")
    elif charts:
        lines += ["## Charts", ""] + [f"- {name}" for name in charts] + [""]
    return "\n".join(lines)


def build_parser():
    parser = argparse.ArgumentParser(description="Analyze QShare benchmark runs")
    parser.add_argument("--results-root", default="benchmarks/results")
    parser.add_argument("--runs", nargs="*", help="use exactly these result folders")
    parser.add_argument("--out", default="benchmarks/analysis_output")
    parser.add_argument("--hardware-note", default="", help="describe the machine")
    parser.add_argument("--no-charts", action="store_true")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    skipped = []
    if args.runs:
        try:
            runs = [Run(path) for path in args.runs]
        except (OSError, KeyError, ValueError) as error:
            raise SystemExit(f"Could not read a run folder: {error}")
    else:
        runs, skipped = discover_runs(args.results_root)
    if not runs:
        raise SystemExit(
            "No complete benchmark runs found. Run: python -m benchmarks.run_benchmarks "
            "--preset standard"
        )

    print(f"Using {len(runs)} run(s):")
    for run in runs:
        print(f"  {run.name}   {run.env.get('note_from_user', '')}")
    for name, reason in skipped:
        print(f"  skipped {name}: {reason}")
    if len(runs) < 3:
        print("NOTE: fewer than 3 runs. Ranges are less meaningful; the plan is 3 or more.")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    tables = {
        "key_operations": table_key_operations(runs),
        "sizes": table_sizes(runs),
        "full_encrypt_small_files": table_full_encrypt_small(runs),
        "cipher_throughput": table_cipher_throughput(runs),
        "memory_peak": table_memory(runs),
    }
    for name, (headers, rows, markdown) in tables.items():
        write_csv(out_dir / f"{name}.csv", headers, rows)
        (out_dir / f"{name}.md").write_text(markdown, encoding="utf-8")

    charts = [] if args.no_charts else make_charts(out_dir, runs)
    checks, problems = correctness_report(runs)
    (out_dir / "run_summary.md").write_text(
        run_summary_text(runs, skipped, args.hardware_note, charts, checks, problems),
        encoding="utf-8",
    )
    print(f"\nWrote tables to {out_dir}")
    if charts is None:
        print("Charts skipped: matplotlib is not installed (optional).")
    elif charts:
        print("Charts: " + ", ".join(charts))
    if problems:
        print(f"WARNING: {len(problems)} correctness problem(s). See run_summary.md.")
    return 0


if __name__ == "__main__":
    sys.exit(main())