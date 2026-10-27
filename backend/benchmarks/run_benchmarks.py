"""Benchmark runner for the QShare crypto lab (app/crypto_lab.py).

Run from the backend folder:
    python -m benchmarks.run_benchmarks --preset quick      (about a minute)
    python -m benchmarks.run_benchmarks --preset standard   (the real run)

WHAT IT MEASURES (time.perf_counter_ns, after thrown-away warm-up runs)
  kem_keygen                                       per key-establishment algorithm
  kem_load_public / kem_load_private               turning key bytes into a key object
  kem_encapsulate / kem_decapsulate                the real operation, key already loaded
  aead_encrypt / aead_decrypt                      per cipher and file size
  e2e_encrypt / e2e_decrypt                        the full QSHARE02 flow,
                                                   per (algorithm, cipher, size)
  It also records key / ciphertext / file-overhead sizes, peak Python memory
  (tracemalloc), correctness checks, and a full description of the machine.

FILES WRITTEN (in <out>/<UTC timestamp>/)
  raw_results.csv   one row per timed trial (nothing is averaged away)
  summary.csv       mean, median, stdev, min, max, p95, 95% CI, per group
  sizes.csv         key, ciphertext and file-overhead sizes in bytes
  memory.csv        peak extra Python memory per operation
  correctness.csv   round trip, tamper detection, wrong-key rejection
  environment.json  Python, OS, CPU, library versions, git commit, settings

FAIRNESS NOTES
  * Setup work (making test input) is never inside the timed region.
  * Garbage collection is switched off while a group is timed.
  * kem_encapsulate / kem_decapsulate time ONLY the operation on an already
    loaded key. Loading is timed separately (kem_load_*), because it differs a
    lot between algorithms (RSA validates the key, ML-KEM expands its seed).
  * e2e_* include key loading, because the app loads the key for every request.
  * kem_keygen includes writing the new key out as bytes.
  * tracemalloc sees Python allocations only, not memory used inside OpenSSL.
  * Close other programs, plug in the laptop, and run it 3 times.

Every number in the output is measured on the machine that runs this script.
"""

import argparse
import csv
import gc
import json
import math
import os
import platform
import random
import statistics
import subprocess
import sys
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path

import cryptography
from cryptography.exceptions import InvalidTag

from app import crypto_lab

PRESETS = {
    "quick": {"trials": 5, "warmup": 2, "sizes": "1KB,100KB"},
    "standard": {"trials": 30, "warmup": 5, "sizes": "1KB,100KB,1MB,10MB"},
}
BAD_INPUT = (ValueError, InvalidTag)

# Two-sided 95% Student-t critical values for 1..30 degrees of freedom.
T_95 = [
    12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228,
    2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086,
    2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042,
]


# ---------------------------------------------------------------------------
# Small helpers (these are unit-tested)
# ---------------------------------------------------------------------------
def parse_size(text: str) -> int:
    """'1KB' -> 1024, '2MB' -> 2097152, '500' -> 500 (KB/MB/GB mean 1024-based)."""
    cleaned = text.strip().upper()
    multiplier = 1
    for suffix, factor in (("KB", 1024), ("MB", 1024**2), ("GB", 1024**3)):
        if cleaned.endswith(suffix):
            cleaned = cleaned[: -len(suffix)]
            multiplier = factor
            break
    try:
        value = int(cleaned) * multiplier
    except ValueError:
        raise ValueError(f"Not a valid size: {text!r} (examples: 1KB, 10MB, 4096)")
    if value <= 0:
        raise ValueError(f"Size must be greater than zero: {text!r}")
    return value


def t_critical(degrees_of_freedom: int) -> float:
    if degrees_of_freedom < 1:
        return float("nan")
    if degrees_of_freedom <= 30:
        return T_95[degrees_of_freedom - 1]
    return 2.0 if degrees_of_freedom <= 120 else 1.96


def percentile(sorted_values, percent: float) -> float:
    """Percentile with linear interpolation between the closest ranks."""
    if not sorted_values:
        return float("nan")
    position = (len(sorted_values) - 1) * percent / 100
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return float(sorted_values[low])
    fraction = position - low
    return sorted_values[low] + (sorted_values[high] - sorted_values[low]) * fraction


def summarize(samples_ns) -> dict:
    """Statistics for one group, converted from nanoseconds to microseconds."""
    values = sorted(samples_ns)
    n = len(values)
    mean = statistics.fmean(values)
    stdev = statistics.stdev(values) if n > 1 else 0.0
    half_width = t_critical(n - 1) * stdev / math.sqrt(n) if n > 1 else float("nan")
    return {
        "n": n,
        "mean_us": mean / 1000,
        "median_us": statistics.median(values) / 1000,
        "stdev_us": stdev / 1000,
        "min_us": values[0] / 1000,
        "max_us": values[-1] / 1000,
        "p95_us": percentile(values, 95) / 1000,
        "ci95_half_width_us": half_width / 1000,
        "cv_percent": (stdev / mean * 100) if mean else 0.0,
    }


def measure(operation, trials: int, warmup: int, setup=None) -> list[int]:
    """Time operation(*args) `trials` times; `warmup` extra runs are discarded.

    setup() (optional) builds fresh arguments for every run, OUTSIDE the timer.
    """
    samples = []
    gc.collect()
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        for run in range(warmup + trials):
            arguments = setup() if setup else ()
            start = time.perf_counter_ns()
            operation(*arguments)
            elapsed = time.perf_counter_ns() - start
            if run >= warmup:
                samples.append(elapsed)
    finally:
        if gc_was_enabled:
            gc.enable()
    return samples


def measure_kem_operations(kem, public_key, private_key, trials: int, warmup: int) -> dict:
    """Time each key-establishment step on its own. Returns {category: samples_ns}.

    Loading the key and doing the real operation are timed SEPARATELY, so one
    algorithm's expensive key loading cannot hide inside its operation time.
    """
    loaded_public = kem.load_public_key(public_key)
    loaded_private = kem.load_private_key(private_key)
    return {
        "kem_keygen": measure(kem.generate_keypair, trials, warmup),
        "kem_load_public": measure(
            lambda: kem.load_public_key(public_key), trials, warmup
        ),
        "kem_load_private": measure(
            lambda: kem.load_private_key(private_key), trials, warmup
        ),
        "kem_encapsulate": measure(
            lambda: kem.encapsulate_with(loaded_public), trials, warmup
        ),
        "kem_decapsulate": measure(
            lambda ciphertext: kem.decapsulate_with(loaded_private, ciphertext),
            trials,
            warmup,
            setup=lambda: (kem.encapsulate_with(loaded_public)[1],),
        ),
    }


def peak_memory(operation, *arguments) -> int:
    """Peak EXTRA Python memory (bytes) used while running operation."""
    gc.collect()
    tracemalloc.start()
    baseline, _ = tracemalloc.get_traced_memory()
    try:
        operation(*arguments)
    finally:
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    return peak - baseline


def _fails(function) -> bool:
    try:
        function()
    except BAD_INPUT:
        return True
    return False


def _fmt(value) -> str:
    if isinstance(value, float):
        return "" if math.isnan(value) else f"{value:.3f}"
    return str(value)


def _openssl_version() -> str:
    try:
        from cryptography.hazmat.backends.openssl import backend

        return backend.openssl_version_text()
    except Exception:
        return "unknown"


def _git_info() -> dict:
    here = Path(__file__).resolve().parent
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True,
            timeout=5, cwd=here,
        ).stdout.strip()
        if not commit:
            return {"commit": None, "uncommitted_changes": None}
        dirty = bool(subprocess.run(
            ["git", "status", "--porcelain"], capture_output=True, text=True,
            timeout=5, cwd=here,
        ).stdout.strip())
        return {"commit": commit, "uncommitted_changes": dirty}
    except Exception:
        return {"commit": None, "uncommitted_changes": None}


def environment_info(args, settings, started, finished) -> dict:
    clock = time.get_clock_info("perf_counter")
    return {
        "started_utc": started.isoformat(),
        "finished_utc": finished.isoformat(),
        "python": sys.version,
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count_logical": os.cpu_count(),
        "cryptography_version": cryptography.__version__,
        "openssl_version": _openssl_version(),
        "timer": {
            "name": "time.perf_counter_ns",
            "implementation": clock.implementation,
            "resolution_seconds": clock.resolution,
        },
        "garbage_collection_during_timing": "disabled",
        "git": _git_info(),
        "settings": settings,
        "note_from_user": args.note,
        "command_line": sys.argv,
    }


# ---------------------------------------------------------------------------
# The benchmark run
# ---------------------------------------------------------------------------
def _select(all_items, wanted_text, label):
    if not wanted_text:
        return list(all_items)
    by_name = {item.name: item for item in all_items}
    chosen = []
    for name in (part.strip() for part in wanted_text.split(",") if part.strip()):
        if name not in by_name:
            raise SystemExit(
                f"Unknown {label}: {name!r}. Choose from: {', '.join(by_name)}"
            )
        chosen.append(by_name[name])
    return chosen


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="QShare crypto benchmark runner")
    parser.add_argument("--preset", choices=PRESETS, default="standard")
    parser.add_argument("--trials", type=int, help="timed runs per group (min 2)")
    parser.add_argument("--warmup", type=int, help="discarded runs per group")
    parser.add_argument("--sizes", help="comma list, e.g. 1KB,100KB,1MB,10MB")
    parser.add_argument("--kems", help="comma list of key-establishment names")
    parser.add_argument("--aeads", help="comma list of cipher names")
    parser.add_argument("--memory-reps", type=int, default=3)
    parser.add_argument("--no-memory", action="store_true")
    parser.add_argument("--seed", type=int, default=12345)
    parser.add_argument("--out", default="benchmarks/results")
    parser.add_argument("--note", default="", help="free text saved with the results")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    preset = PRESETS[args.preset]
    trials = args.trials if args.trials is not None else preset["trials"]
    warmup = args.warmup if args.warmup is not None else preset["warmup"]
    try:
        sizes = [parse_size(part) for part in (args.sizes or preset["sizes"]).split(",")]
    except ValueError as error:
        raise SystemExit(str(error))
    if trials < 2:
        raise SystemExit("--trials must be at least 2 (needed for the statistics).")
    if warmup < 0:
        raise SystemExit("--warmup cannot be negative.")

    kems = _select(crypto_lab.KEMS, args.kems, "key-establishment algorithm")
    aeads = _select(crypto_lab.AEADS, args.aeads, "cipher")

    started = datetime.now(timezone.utc)
    out_dir = Path(args.out) / started.strftime("%Y%m%dT%H%M%SZ")
    out_dir.mkdir(parents=True, exist_ok=False)

    rng = random.Random(args.seed)
    plaintexts = {size: rng.randbytes(size) for size in sizes}
    aes_256 = crypto_lab.get_aead("AES-256-GCM")

    print(f"Output folder : {out_dir}")
    print(f"Trials/warmup : {trials} / {warmup}    sizes: {sizes}")
    print("Preparing keys (not timed) ...")
    keys = {kem.name: kem.generate_keypair() for kem in kems}
    other_keys = {kem.name: kem.generate_keypair() for kem in kems}

    total_groups = (
        len(kems) * 5
        + len(aeads) * len(sizes) * 2
        + len(kems) * len(aeads) * len(sizes) * 2
    )
    done = 0
    summary_rows = []
    medians = {}

    with open(out_dir / "raw_results.csv", "w", newline="", encoding="utf-8") as raw_file:
        raw = csv.writer(raw_file)
        raw.writerow(["category", "kem", "aead", "size_bytes", "trial", "time_ns"])

        def record(category, kem_name, aead_name, size, samples):
            nonlocal done
            done += 1
            for trial, nanoseconds in enumerate(samples, start=1):
                raw.writerow([category, kem_name, aead_name, size, trial, nanoseconds])
            stats = summarize(samples)
            summary_rows.append(
                {"category": category, "kem": kem_name, "aead": aead_name,
                 "size_bytes": size, **stats}
            )
            medians[(category, kem_name, aead_name, size)] = stats["median_us"]
            label = " ".join(part for part in (kem_name, aead_name) if part)
            print(f"[{done:>3}/{total_groups}] {category:<16} {label:<34} "
                  f"size={size:<9} median={stats['median_us']:>12.1f} us")

        # 1) key-establishment operations (loading and the operation apart)
        for kem in kems:
            public_key, private_key = keys[kem.name]
            steps = measure_kem_operations(kem, public_key, private_key, trials, warmup)
            for category, samples in steps.items():
                record(category, kem.name, "", 0, samples)

        # 2) cipher-only operations (independent of the key establishment)
        aad = b"benchmark-aad"
        for aead in aeads:
            key = rng.randbytes(aead.key_size)
            for size in sizes:
                data = plaintexts[size]
                record("aead_encrypt", "", aead.name, size,
                       measure(aead.encrypt, trials, warmup,
                               setup=lambda: (key, os.urandom(12), data, aad)))
                nonce = os.urandom(12)
                blob = aead.encrypt(key, nonce, data, aad)
                record("aead_decrypt", "", aead.name, size,
                       measure(lambda: aead.decrypt(key, nonce, blob, aad), trials, warmup))

        # 3) the complete QSHARE02 flow
        for kem in kems:
            public_key, private_key = keys[kem.name]
            for aead in aeads:
                for size in sizes:
                    data = plaintexts[size]
                    payload = crypto_lab.encrypt(data, public_key, kem, aead)
                    if crypto_lab.decrypt(payload, private_key) != data:
                        raise RuntimeError(
                            f"Round trip FAILED for {kem.name}/{aead.name}/{size}. "
                            "Benchmark results would be meaningless."
                        )
                    record("e2e_encrypt", kem.name, aead.name, size,
                           measure(lambda: crypto_lab.encrypt(data, public_key, kem, aead),
                                   trials, warmup))
                    record("e2e_decrypt", kem.name, aead.name, size,
                           measure(lambda: crypto_lab.decrypt(payload, private_key),
                                   trials, warmup))

    # summary.csv
    summary_columns = ["category", "kem", "aead", "size_bytes", "n", "mean_us",
                       "median_us", "stdev_us", "min_us", "max_us", "p95_us",
                       "ci95_half_width_us", "cv_percent", "throughput_mb_per_s"]
    with open(out_dir / "summary.csv", "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(summary_columns)
        for row in summary_rows:
            speed = ""
            if row["category"].startswith(("aead_", "e2e_")) and row["median_us"] > 0:
                speed = row["size_bytes"] / (row["median_us"] / 1e6) / 1e6
            row["throughput_mb_per_s"] = speed
            writer.writerow([_fmt(row[column]) for column in summary_columns])

    # sizes.csv
    with open(out_dir / "sizes.csv", "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["kem", "public_key_bytes", "private_key_bytes_as_stored",
                         "kem_ciphertext_bytes", "qshare02_file_overhead_bytes"])
        for kem in kems:
            public_key, private_key = keys[kem.name]
            overhead = len(crypto_lab.encrypt(b"", public_key, kem, aes_256))
            writer.writerow([kem.name, len(public_key), len(private_key),
                             kem.ciphertext_size, overhead])

    # correctness.csv (failure handling)
    with open(out_dir / "correctness.csv", "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["kem", "aead", "round_trip_ok", "tamper_detected",
                         "wrong_key_rejected"])
        for kem in kems:
            public_key, private_key = keys[kem.name]
            for aead in aeads:
                sample = rng.randbytes(1024)
                payload = crypto_lab.encrypt(sample, public_key, kem, aead)
                round_trip = crypto_lab.decrypt(payload, private_key) == sample
                damaged = bytearray(payload)
                damaged[-1] ^= 1
                tamper = _fails(lambda: crypto_lab.decrypt(bytes(damaged), private_key))
                wrong_key = _fails(
                    lambda: crypto_lab.decrypt(payload, other_keys[kem.name][1])
                )
                writer.writerow([kem.name, aead.name, round_trip, tamper, wrong_key])

    # memory.csv
    with open(out_dir / "memory.csv", "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["kem", "aead", "size_bytes", "repetition", "operation",
                         "peak_extra_python_bytes"])
        if not args.no_memory:
            print("Measuring peak memory (tracemalloc) ...")
            for kem in kems:
                public_key, private_key = keys[kem.name]
                for aead in aeads:
                    for size in sizes:
                        data = plaintexts[size]
                        payload = crypto_lab.encrypt(data, public_key, kem, aead)
                        for repetition in range(1, args.memory_reps + 1):
                            writer.writerow([
                                kem.name, aead.name, size, repetition, "encrypt",
                                peak_memory(crypto_lab.encrypt, data, public_key, kem, aead),
                            ])
                            writer.writerow([
                                kem.name, aead.name, size, repetition, "decrypt",
                                peak_memory(crypto_lab.decrypt, payload, private_key),
                            ])

    finished = datetime.now(timezone.utc)
    settings = {"preset": args.preset, "trials": trials, "warmup": warmup,
                "sizes_bytes": sizes, "kems": [k.name for k in kems],
                "aeads": [a.name for a in aeads], "seed": args.seed,
                "memory_reps": 0 if args.no_memory else args.memory_reps}
    with open(out_dir / "environment.json", "w", encoding="utf-8") as handle:
        json.dump(environment_info(args, settings, started, finished), handle, indent=2)

    print("\nMedian times in microseconds (key operations):")
    print(f"{'algorithm':<20}{'keygen':>13}{'load private':>14}"
          f"{'encapsulate':>13}{'decapsulate':>13}")
    for kem in kems:
        print(f"{kem.name:<20}"
              f"{medians[('kem_keygen', kem.name, '', 0)]:>13.1f}"
              f"{medians[('kem_load_private', kem.name, '', 0)]:>14.1f}"
              f"{medians[('kem_encapsulate', kem.name, '', 0)]:>13.1f}"
              f"{medians[('kem_decapsulate', kem.name, '', 0)]:>13.1f}")
    print(f"\nDone in {(finished - started).total_seconds():.1f} s. Results: {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())