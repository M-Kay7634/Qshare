"""Diagnostic: why do 10 MB timings change so much between runs?

Your order test showed that even the cipher ALONE (no key exchange at all)
took 3.5 to 5.2 ms for the same 10 MB job in different launches. This script
repeats a few simple controls in several SEPARATE Python processes and prints
them side by side:

  cpu_control             a small pure-CPU loop (no memory traffic)
  allocate_and_fill_10MB  make a fresh 10 MB block and write to it
  concatenate_10MB        join a header and a 10 MB block (one big copy)
  cipher_AES128GCM_10MB   the real AES-128-GCM encryption of 10 MB

How to read the result:
  * Only the CPU control moves between processes   -> CPU speed / power state.
  * The memory controls move as much as the cipher -> memory handling
    (fresh large blocks), not the cryptography.

Run from the backend folder:   python -m benchmarks.diag_large_buffers
"""

import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SIZE = 10 * 1024 * 1024
TRIALS = 30
WARMUP = 5
PROCESSES = 5


def median_us(function, trials=TRIALS, warmup=WARMUP):
    samples = []
    for run in range(warmup + trials):
        start = time.perf_counter_ns()
        function()
        elapsed = time.perf_counter_ns() - start
        if run >= warmup:
            samples.append(elapsed)
    return statistics.median(samples) / 1000


def child():
    data = os.urandom(SIZE)
    aes = AESGCM(AESGCM.generate_key(bit_length=128))
    nonce = os.urandom(12)  # fixed nonce is fine here: this is only a timing test
    header = b"h" * 1200
    blob = aes.encrypt(nonce, data, b"")

    def cpu_loop():
        total = 0
        for number in range(200_000):
            total += number
        return total

    results = {}
    results["cpu_control_us"] = median_us(cpu_loop)
    results["allocate_and_fill_10MB_us"] = median_us(lambda: b"\x01" * SIZE)
    results["concatenate_10MB_us"] = median_us(lambda: header + blob)
    results["cipher_AES128GCM_10MB_us"] = median_us(lambda: aes.encrypt(nonce, data, b""))

    for _ in range(20):  # churn through big blocks, then measure the cipher again
        scratch = b"\x02" * SIZE
        del scratch
    results["cipher_after_memory_churn_us"] = median_us(lambda: aes.encrypt(nonce, data, b""))
    results["cpu_control_after_us"] = median_us(cpu_loop)
    print(json.dumps(results))


def parent():
    backend_dir = Path(__file__).resolve().parent.parent
    runs = []
    for number in range(1, PROCESSES + 1):
        print(f"process {number}/{PROCESSES} ...", flush=True)
        done = subprocess.run(
            [sys.executable, "-m", "benchmarks.diag_large_buffers", "--child"],
            cwd=backend_dir, capture_output=True, text=True, timeout=300,
        )
        if done.returncode != 0:
            raise SystemExit(f"Child process failed:\n{done.stderr}")
        runs.append(json.loads(done.stdout.strip().splitlines()[-1]))

    names = list(runs[0])
    print("\nMedian microseconds, one column per separate process:")
    header = f"{'measurement':<32}" + "".join(f"{'proc ' + str(i):>10}" for i in range(1, PROCESSES + 1))
    print(header + f"{'max/min':>9}")
    for name in names:
        values = [run[name] for run in runs]
        print(f"{name:<32}" + "".join(f"{value:>10.1f}" for value in values)
              + f"{max(values) / min(values):>9.2f}")
    print("\nmax/min close to 1.00 = steady. Much larger = that measurement")
    print("depends on the state of the process or machine at that moment.")


if __name__ == "__main__":
    if "--child" in sys.argv:
        child()
    else:
        parent()