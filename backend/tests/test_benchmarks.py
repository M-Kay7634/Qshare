"""Tests for benchmarks/run_benchmarks.py.

These check the statistics, the timing rules and the file pipeline. They do
NOT check how fast anything is: speed depends on the machine.
"""

import csv
import gc
import json
import math
import statistics
import tracemalloc

import cryptography
import pytest

from benchmarks import run_benchmarks as rb


# --- helpers -----------------------------------------------------------------
@pytest.mark.parametrize(
    "text, expected",
    [("1KB", 1024), ("2MB", 2 * 1024**2), ("500", 500), (" 10mb ", 10 * 1024**2),
     ("1GB", 1024**3)],
)
def test_parse_size_accepts_normal_values(text, expected):
    assert rb.parse_size(text) == expected


@pytest.mark.parametrize("text", ["", "abc", "0", "-5KB", "1.5MB", "MB"])
def test_parse_size_rejects_bad_values(text):
    with pytest.raises(ValueError):
        rb.parse_size(text)


def test_t_critical_values():
    assert rb.t_critical(1) == 12.706
    assert rb.t_critical(4) == 2.776
    assert rb.t_critical(29) == 2.045
    assert rb.t_critical(30) == 2.042
    assert rb.t_critical(60) == 2.0
    assert rb.t_critical(1000) == 1.96
    assert math.isnan(rb.t_critical(0))


def test_percentile_matches_the_standard_library_method():
    values = [1, 2, 3, 4, 5]
    assert rb.percentile(values, 50) == 3
    assert rb.percentile(values, 95) == pytest.approx(4.8)
    assert rb.percentile(values, 0) == 1
    assert rb.percentile(values, 100) == 5
    data = sorted([7, 1, 9, 4, 4, 12, 30, 2, 8, 5])
    expected = statistics.quantiles(data, n=100, method="inclusive")[94]
    assert rb.percentile(data, 95) == pytest.approx(expected)


def test_summarize_matches_hand_calculation():
    # nanoseconds in -> microseconds out
    stats = rb.summarize([10_000, 12_000, 14_000, 16_000, 18_000, 20_000])

    assert stats["n"] == 6
    assert stats["mean_us"] == pytest.approx(15.0)
    assert stats["median_us"] == pytest.approx(15.0)
    assert stats["stdev_us"] == pytest.approx(math.sqrt(14))  # sample stdev
    assert stats["min_us"] == pytest.approx(10.0)
    assert stats["max_us"] == pytest.approx(20.0)
    # 95% CI half-width = t(df=5) * stdev / sqrt(n) = 2.571 * sqrt(14) / sqrt(6)
    assert stats["ci95_half_width_us"] == pytest.approx(
        2.571 * math.sqrt(14) / math.sqrt(6)
    )
    assert stats["cv_percent"] == pytest.approx(math.sqrt(14) / 15 * 100)


# --- timing rules -------------------------------------------------------------
def test_measure_discards_warmup_and_keeps_setup_outside_timer():
    calls = {"setup": 0, "operation": 0}

    def setup():
        calls["setup"] += 1
        return (calls["setup"],)

    def operation(number):
        calls["operation"] += 1

    samples = rb.measure(operation, trials=4, warmup=3, setup=setup)

    assert len(samples) == 4  # warm-up runs are thrown away
    assert calls == {"setup": 7, "operation": 7}
    assert all(sample >= 0 for sample in samples)


def test_measure_times_only_the_operation_not_the_setup(monkeypatch):
    """Uses a fake clock, so the result is exact and never flaky."""
    clock = {"now": 0}

    class FakeTime:
        @staticmethod
        def perf_counter_ns():
            return clock["now"]

    monkeypatch.setattr(rb, "time", FakeTime)

    def setup():
        clock["now"] += 5_000_000  # slow setup: must NOT be counted
        return ()

    def operation():
        clock["now"] += 1_000  # the only thing that should be counted

    assert rb.measure(operation, trials=3, warmup=1, setup=setup) == [1_000] * 3


def test_key_loading_is_timed_apart_from_the_key_operation(monkeypatch):
    """Fake clock + fake algorithm: loading must NOT leak into encap/decap."""
    clock = {"now": 0}

    class FakeTime:
        @staticmethod
        def perf_counter_ns():
            return clock["now"]

    monkeypatch.setattr(rb, "time", FakeTime)

    class FakeKem:
        def generate_keypair(self):
            clock["now"] += 1_000
            return b"public", b"private"

        def load_public_key(self, data):
            clock["now"] += 2_000
            return "loaded-public"

        def load_private_key(self, data):
            clock["now"] += 3_000
            return "loaded-private"

        def encapsulate_with(self, loaded_public):
            clock["now"] += 4_000
            return b"secret", b"ciphertext"

        def decapsulate_with(self, loaded_private, ciphertext):
            clock["now"] += 5_000
            return b"secret"

    steps = rb.measure_kem_operations(FakeKem(), b"public", b"private", trials=2, warmup=1)

    assert steps == {
        "kem_keygen": [1_000, 1_000],
        "kem_load_public": [2_000, 2_000],
        "kem_load_private": [3_000, 3_000],
        "kem_encapsulate": [4_000, 4_000],
        "kem_decapsulate": [5_000, 5_000],  # no loading, no setup time inside
    }


def test_measure_restores_garbage_collection_even_after_an_error():
    assert gc.isenabled()

    def broken():
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        rb.measure(broken, trials=2, warmup=0)

    assert gc.isenabled()


def test_peak_memory_sees_a_big_allocation_and_stops_tracing():
    peak = rb.peak_memory(lambda: bytes(5_000_000))

    assert peak >= 4_000_000
    assert not tracemalloc.is_tracing()


# --- the whole pipeline on a tiny configuration ------------------------------
@pytest.fixture(scope="module")
def tiny_run(tmp_path_factory):
    out = tmp_path_factory.mktemp("bench")
    code = rb.main([
        "--preset", "quick", "--trials", "3", "--warmup", "1", "--sizes", "1KB",
        "--kems", "X25519,ML-KEM-768", "--aeads", "AES-256-GCM",
        "--memory-reps", "1", "--out", str(out), "--note", "unit test",
    ])
    assert code == 0
    (run_dir,) = list(out.iterdir())
    return run_dir


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_all_result_files_are_written(tiny_run):
    names = {path.name for path in tiny_run.iterdir()}
    assert names == {"raw_results.csv", "summary.csv", "sizes.csv", "memory.csv",
                     "correctness.csv", "environment.json"}


def test_raw_results_have_one_row_per_timed_trial(tiny_run):
    rows = read_csv(tiny_run / "raw_results.csv")
    # key ops: 2 kems x 5 ops x 3 trials = 30
    # cipher ops: 1 aead x 1 size x 2 ops x 3 trials = 6
    # full flow: 2 kems x 1 aead x 1 size x 2 ops x 3 trials = 12
    assert len(rows) == 30 + 6 + 12
    assert all(int(row["time_ns"]) > 0 for row in rows)
    categories = {row["category"] for row in rows}
    assert categories == {"kem_keygen", "kem_load_public", "kem_load_private",
                          "kem_encapsulate", "kem_decapsulate",
                          "aead_encrypt", "aead_decrypt",
                          "e2e_encrypt", "e2e_decrypt"}


def test_summary_has_one_row_per_group_and_sane_numbers(tiny_run):
    rows = read_csv(tiny_run / "summary.csv")
    assert len(rows) == 10 + 2 + 4
    for row in rows:
        assert int(row["n"]) == 3
        assert float(row["min_us"]) <= float(row["median_us"]) <= float(row["max_us"])
        is_data_op = row["category"].startswith(("aead_", "e2e_"))
        assert (row["throughput_mb_per_s"] != "") == is_data_op


def test_sizes_match_the_published_ml_kem_768_sizes(tiny_run):
    rows = {row["kem"]: row for row in read_csv(tiny_run / "sizes.csv")}
    ml_kem = rows["ML-KEM-768"]
    assert int(ml_kem["public_key_bytes"]) == 1184
    assert int(ml_kem["kem_ciphertext_bytes"]) == 1088
    assert int(ml_kem["qshare02_file_overhead_bytes"]) == 1144
    assert int(rows["X25519"]["qshare02_file_overhead_bytes"]) == 88


def test_correctness_checks_all_pass(tiny_run):
    rows = read_csv(tiny_run / "correctness.csv")
    assert len(rows) == 2
    for row in rows:
        assert row["round_trip_ok"] == "True"
        assert row["tamper_detected"] == "True"
        assert row["wrong_key_rejected"] == "True"


def test_memory_file_has_rows_for_encrypt_and_decrypt(tiny_run):
    rows = read_csv(tiny_run / "memory.csv")
    assert len(rows) == 2 * 1 * 1 * 1 * 2
    assert {row["operation"] for row in rows} == {"encrypt", "decrypt"}
    assert all(int(row["peak_extra_python_bytes"]) > 0 for row in rows)


def test_environment_file_records_the_setup(tiny_run):
    info = json.loads((tiny_run / "environment.json").read_text(encoding="utf-8"))
    assert info["cryptography_version"] == cryptography.__version__
    assert info["note_from_user"] == "unit test"
    assert info["settings"]["trials"] == 3
    assert info["settings"]["kems"] == ["X25519", "ML-KEM-768"]
    assert info["garbage_collection_during_timing"] == "disabled"
    assert info["timer"]["name"] == "time.perf_counter_ns"
    assert info["python"] and info["platform"] and info["openssl_version"]


# --- bad command-line input stops early with a clear message ------------------
def test_unknown_algorithm_name_is_rejected(tmp_path):
    out = tmp_path / "bench_out"
    with pytest.raises(SystemExit) as error:
        rb.main(["--kems", "NOT-REAL", "--out", str(out)])
    assert "Unknown key-establishment algorithm" in str(error.value)
    assert not out.exists()  # nothing was created


def test_too_few_trials_and_bad_sizes_are_rejected(tmp_path):
    out = tmp_path / "bench_out"
    with pytest.raises(SystemExit):
        rb.main(["--trials", "1", "--out", str(out)])
    with pytest.raises(SystemExit):
        rb.main(["--sizes", "banana", "--out", str(out)])
    assert not out.exists()


def test_correctness_file_reports_failures_instead_of_hiding_them(tmp_path, monkeypatch):
    """If tampering or a wrong key were NOT detected, the CSV must say False."""
    monkeypatch.setattr(rb, "_fails", lambda function: False)
    out = tmp_path / "bench_out"
    rb.main([
        "--trials", "2", "--warmup", "0", "--sizes", "1KB", "--kems", "X25519",
        "--aeads", "AES-256-GCM", "--no-memory", "--out", str(out),
    ])
    (run_dir,) = list(out.iterdir())
    (row,) = read_csv(run_dir / "correctness.csv")

    assert row["round_trip_ok"] == "True"
    assert row["tamper_detected"] == "False"
    assert row["wrong_key_rejected"] == "False"


def test_fails_helper_only_catches_expected_errors():
    def raises(error):
        def function():
            raise error
        return function

    assert rb._fails(raises(ValueError("bad"))) is True
    assert rb._fails(raises(rb.InvalidTag())) is True
    assert rb._fails(lambda: None) is False
    with pytest.raises(RuntimeError):  # unexpected errors are NOT swallowed
        rb._fails(raises(RuntimeError("unexpected")))