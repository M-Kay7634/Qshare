"""Tests for benchmarks/analyze_results.py.

They build small made-up result folders with numbers that are easy to check
by hand, so every figure the analysis prints can be verified.
"""

import csv
import json
import sys

import pytest

from app import crypto_lab
from benchmarks import analyze_results as ar

KEM_NAMES = [kem.name for kem in crypto_lab.KEMS]
AEAD_NAMES = [aead.name for aead in crypto_lab.AEADS]
SIZES = [1024, 102400, 1048576, 10485760]
MIB = 1024 * 1024
KEM_BASE = {"kem_keygen": 100.0, "kem_load_public": 10.0, "kem_load_private": 50.0,
            "kem_encapsulate": 20.0, "kem_decapsulate": 30.0}


def write_csv_file(path, headers, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        writer.writerows(rows)


def make_run(root, name, *, scale=1.0, preset="standard", trials=30, kems=None,
             aeads=None, note="", rsa_private_extra=0, public_extra=0,
             bad_correctness=False):
    """One fake result folder. Every timing = a simple number x scale."""
    folder = root / name
    folder.mkdir(parents=True)
    kems = kems or KEM_NAMES
    aeads = aeads or AEAD_NAMES
    env = {
        "started_utc": "2026-01-01T00:00:00+00:00", "python": "3.13.7 (test)",
        "python_implementation": "CPython", "platform": "test-os",
        "processor": "test-cpu", "cpu_count_logical": 4,
        "cryptography_version": "50.0.2", "openssl_version": "OpenSSL test",
        "timer": {"name": "time.perf_counter_ns", "resolution_seconds": 1e-09},
        "git": {"commit": None}, "note_from_user": note,
        "settings": {"preset": preset, "trials": trials, "warmup": 5,
                     "kems": kems, "aeads": aeads},
    }
    (folder / "environment.json").write_text(json.dumps(env), encoding="utf-8")

    summary = []
    for kem in kems:
        for category, base in KEM_BASE.items():
            summary.append([category, kem, "", 0, base * scale])
    for aead in aeads:
        for size in SIZES:
            speed_time = size / MIB * 1000 * scale  # 1 MiB takes 1000 us at scale 1
            summary.append(["aead_encrypt", "", aead, size, speed_time])
            summary.append(["aead_decrypt", "", aead, size, speed_time])
    for kem in kems:
        for aead in aeads:
            for size in SIZES:
                summary.append(["e2e_encrypt", kem, aead, size, (50 + size / MIB * 1000) * scale])
                summary.append(["e2e_decrypt", kem, aead, size, (60 + size / MIB * 1000) * scale])
    write_csv_file(folder / "summary.csv",
                   ["category", "kem", "aead", "size_bytes", "median_us"], summary)

    sizes = []
    for index, kem in enumerate(KEM_NAMES):
        private = 64 + index
        if kem == "RSA-2048":
            private = 1217 + rsa_private_extra
        public = 1000 + index + (public_extra if kem == "X25519" else 0)
        sizes.append([kem, public, private, 500 + index, 600 + index])
    write_csv_file(folder / "sizes.csv",
                   ["kem", "public_key_bytes", "private_key_bytes_as_stored",
                    "kem_ciphertext_bytes", "qshare02_file_overhead_bytes"], sizes)

    correctness = []
    for kem in kems:
        for aead in aeads:
            correctness.append([kem, aead, "True", "True", "True"])
    if bad_correctness:
        correctness[0][3] = "False"
    write_csv_file(folder / "correctness.csv",
                   ["kem", "aead", "round_trip_ok", "tamper_detected",
                    "wrong_key_rejected"], correctness)

    memory = []
    for size in (1024, MIB):
        for operation in ("encrypt", "decrypt"):
            memory.append([KEM_NAMES[0], AEAD_NAMES[0], size, 1, operation, 2 * size + 100])
    write_csv_file(folder / "memory.csv",
                   ["kem", "aead", "size_bytes", "repetition", "operation",
                    "peak_extra_python_bytes"], memory)
    return folder


def load(tmp_path, scales=(1.0, 1.0, 1.0), **options):
    return [ar.Run(make_run(tmp_path, f"run{i}", scale=scale, **options))
            for i, scale in enumerate(scales, start=1)]


def tidy_rows(table):
    headers, rows, _ = table
    return [dict(zip(headers, row)) for row in rows]


# --- numbers ------------------------------------------------------------------
def test_size_labels_and_throughput_formula():
    assert ar.size_label(1024) == "1 KB"
    assert ar.size_label(102400) == "100 KB"
    assert ar.size_label(MIB) == "1 MB"
    assert ar.size_label(10 * MIB) == "10 MB"
    assert ar.size_label(1500) == "1500 B"
    assert ar.throughput_mib_per_s(MIB, 1000) == pytest.approx(1000.0)
    assert ar.throughput_mib_per_s(10 * MIB, 10_000) == pytest.approx(1000.0)


def test_aggregate_takes_the_median_of_the_runs_not_the_mean(tmp_path):
    runs = load(tmp_path, scales=(1.0, 1.1, 1.5))
    agg = ar.aggregate(runs, "kem_decapsulate", "X25519", "", 0)

    assert agg["median"] == pytest.approx(33.0)  # mean would be 34.67
    assert agg["min"] == pytest.approx(30.0)
    assert agg["max"] == pytest.approx(45.0)
    assert agg["runs"] == 3
    assert agg["spread_percent"] == pytest.approx(15 / 33 * 100)
    assert agg["unstable"] is True


def test_a_narrow_range_is_not_marked_unstable(tmp_path):
    runs = load(tmp_path, scales=(1.0, 1.05, 1.1))
    agg = ar.aggregate(runs, "kem_decapsulate", "X25519", "", 0)
    assert agg["spread_percent"] < 25
    assert agg["unstable"] is False


def test_aggregate_of_a_missing_measurement_is_none(tmp_path):
    runs = load(tmp_path)
    assert ar.aggregate(runs, "kem_keygen", "NOT-AN-ALGORITHM", "", 0) is None
    assert ar.cell(None) == "n/a"


def test_cell_formatting_and_markdown_table():
    agg = {"median": 1234.56, "min": 1000.0, "max": 2000.0, "unstable": True}
    assert ar.cell(agg) == "1,234.6 (1,000.0-2,000.0)*"
    agg["unstable"] = False
    assert ar.cell(agg, 0) == "1,235 (1,000-2,000)"
    text = ar.markdown_table(["A", "B"], [[1, 2], [3, 4]])
    assert text == "| A | B |\n|---|---|\n| 1 | 2 |\n| 3 | 4 |\n"


# --- choosing which runs to use -------------------------------------------------
def test_skip_reason_rules():
    good = {"settings": {"preset": "standard", "trials": 30,
                         "kems": KEM_NAMES, "aeads": AEAD_NAMES}}
    assert ar.skip_reason(good) is None
    assert "standard" in ar.skip_reason(
        {"settings": {**good["settings"], "preset": "quick"}})
    assert "trials" in ar.skip_reason(
        {"settings": {**good["settings"], "trials": 10}})
    assert "key-establishment" in ar.skip_reason(
        {"settings": {**good["settings"], "kems": KEM_NAMES[:2]}})
    assert "cipher" in ar.skip_reason(
        {"settings": {**good["settings"], "aeads": AEAD_NAMES[:1]}})
    assert ar.skip_reason({}) is not None


def test_discover_runs_uses_complete_runs_and_explains_every_skip(tmp_path):
    root = tmp_path / "results"
    make_run(root, "good1")
    make_run(root, "good2")
    make_run(root, "practice", preset="quick")
    make_run(root, "few_trials", trials=10)
    make_run(root, "order_test", kems=["X25519"])
    (root / "broken").mkdir()
    (root / "stray_file.txt").write_text("not a run", encoding="utf-8")

    used, skipped = ar.discover_runs(root)

    assert [run.name for run in used] == ["good1", "good2"]
    reasons = dict(skipped)
    assert set(reasons) == {"practice", "few_trials", "order_test", "broken"}
    assert "unreadable" in reasons["broken"]


def test_discover_runs_with_a_missing_folder_finds_nothing(tmp_path):
    assert ar.discover_runs(tmp_path / "does_not_exist") == ([], [])


# --- the tables -------------------------------------------------------------------
def test_key_operations_table_values_and_unstable_marker(tmp_path):
    runs = load(tmp_path, scales=(1.0, 1.0, 1.0))
    headers, rows, markdown = ar.table_key_operations(runs)
    tidy = tidy_rows((headers, rows, markdown))

    assert len(tidy) == len(KEM_NAMES) * 5
    keygen = [r for r in tidy if r["kem"] == "ML-KEM-768" and r["operation"] == "key generation"][0]
    assert float(keygen["median_us"]) == pytest.approx(100.0)
    assert keygen["runs"] == 3 and keygen["unstable"] == "no"
    assert "| ML-KEM-768 | 100.0 (100.0-100.0) |" in markdown
    assert "*" not in markdown

    noisy = load(tmp_path / "noisy", scales=(1.0, 1.1, 2.0))
    assert "*" in ar.table_key_operations(noisy)[2]


def test_full_encrypt_table_only_has_small_files_and_one_cipher(tmp_path):
    runs = load(tmp_path)
    headers, rows, markdown = ar.table_full_encrypt_small(runs)
    tidy = tidy_rows((headers, rows, markdown))

    assert {int(r["size_bytes"]) for r in tidy} == {1024, 102400}
    assert {r["cipher"] for r in tidy} == {"AES-256-GCM"}
    assert len(tidy) == len(KEM_NAMES) * 2 * 2
    assert "10 MB" not in markdown and "1 MB" not in markdown
    assert "100 KB encrypt" in markdown


def test_cipher_throughput_numbers_and_slowest_fastest_runs(tmp_path):
    runs = load(tmp_path, scales=(1.0, 1.25, 2.0))
    headers, rows, markdown = ar.table_cipher_throughput(runs)
    tidy = tidy_rows((headers, rows, markdown))

    one_mb = [r for r in tidy if r["cipher"] == "AES-128-GCM"
              and r["operation"] == "encrypt" and int(r["size_bytes"]) == MIB][0]
    assert float(one_mb["median_us"]) == pytest.approx(1250.0)
    assert float(one_mb["median_mib_per_s"]) == pytest.approx(800.0)
    assert float(one_mb["slowest_run_mib_per_s"]) == pytest.approx(500.0)
    assert float(one_mb["fastest_run_mib_per_s"]) == pytest.approx(1000.0)
    assert any(int(r["size_bytes"]) == 10 * MIB for r in tidy)
    assert "1 KB" not in markdown  # 1 KB speed mostly measures fixed overhead
    assert "10 MB encrypt (MiB/s)" in markdown


def test_sizes_table_reports_the_rsa_private_key_as_a_range(tmp_path):
    runs = [ar.Run(make_run(tmp_path, "r1", rsa_private_extra=0)),
            ar.Run(make_run(tmp_path, "r2", rsa_private_extra=2)),
            ar.Run(make_run(tmp_path, "r3", rsa_private_extra=1))]
    headers, rows, markdown = ar.table_sizes(runs)
    tidy = {r["kem"]: r for r in tidy_rows((headers, rows, markdown))}

    assert tidy["RSA-2048"]["private_key_bytes_min"] == 1217
    assert tidy["RSA-2048"]["private_key_bytes_max"] == 1219
    assert "| RSA-2048 | 1004 | 1,217-1,219 |" in markdown
    assert tidy["ML-KEM-768"]["private_key_bytes_min"] == tidy["ML-KEM-768"]["private_key_bytes_max"]
    assert ar.fixed_sizes_consistent(runs) is True


def test_a_changing_fixed_size_is_detected(tmp_path):
    runs = [ar.Run(make_run(tmp_path, "r1")),
            ar.Run(make_run(tmp_path, "r2", public_extra=5))]
    assert ar.fixed_sizes_consistent(runs) is False


def test_memory_table_uses_the_median_and_the_ratio_to_file_size(tmp_path):
    runs = load(tmp_path)
    headers, rows, markdown = ar.table_memory(runs)
    tidy = {(int(r["size_bytes"]), r["operation"]): r for r in tidy_rows((headers, rows, markdown))}

    row = tidy[(MIB, "encrypt")]
    assert int(row["median_peak_bytes"]) == 2 * MIB + 100
    assert row["measurements"] == 3
    assert row["peak_over_file_size"] == "2.00"
    assert "1 MB" in markdown


def test_correctness_report_finds_failures(tmp_path):
    good = load(tmp_path / "good")
    checks, problems = ar.correctness_report(good)
    assert checks == 3 * len(KEM_NAMES) * len(AEAD_NAMES) * 3
    assert problems == []

    bad = load(tmp_path / "bad", bad_correctness=True)
    checks, problems = ar.correctness_report(bad)
    assert len(problems) == 3
    assert "tamper_detected = False" in problems[0]


# --- the whole command ---------------------------------------------------------------
def run_main(tmp_path, extra=(), scales=(1.0, 1.1, 1.2), **options):
    results = tmp_path / "results"
    for index, scale in enumerate(scales, start=1):
        make_run(results, f"run{index}", scale=scale, **options)
    out = tmp_path / "out"
    code = ar.main(["--results-root", str(results), "--out", str(out), *extra])
    return code, out


def test_main_writes_every_table_and_the_summary(tmp_path):
    code, out = run_main(tmp_path, ["--no-charts", "--hardware-note", "Test laptop, 16 GB"])

    assert code == 0
    names = {path.name for path in out.iterdir()}
    for table in ("key_operations", "sizes", "full_encrypt_small_files",
                  "cipher_throughput", "memory_peak"):
        assert f"{table}.csv" in names and f"{table}.md" in names
    assert "run_summary.md" in names
    assert not any(name.endswith(".png") for name in names)

    summary = (out / "run_summary.md").read_text(encoding="utf-8")
    assert "Test laptop, 16 GB" in summary
    assert "All passed." in summary
    assert "run1" in summary and "run3" in summary
    assert "Rules used" in summary and "Known limits" in summary


def test_main_with_explicit_run_folders(tmp_path):
    first = make_run(tmp_path / "somewhere", "a")
    second = make_run(tmp_path / "somewhere", "b", scale=1.2)
    out = tmp_path / "out"

    code = ar.main(["--runs", str(first), str(second), "--out", str(out), "--no-charts"])

    assert code == 0
    summary = (out / "run_summary.md").read_text(encoding="utf-8")
    assert "| a |" in summary and "| b |" in summary
    assert (out / "key_operations.csv").is_file()


def test_main_stops_clearly_when_there_is_no_complete_run(tmp_path):
    results = tmp_path / "results"
    make_run(results, "practice", preset="quick")
    out = tmp_path / "out"

    with pytest.raises(SystemExit) as error:
        ar.main(["--results-root", str(results), "--out", str(out)])

    assert "No complete benchmark runs" in str(error.value)
    assert not out.exists()


def test_main_warns_loudly_about_correctness_failures(tmp_path, capsys):
    code, out = run_main(tmp_path, ["--no-charts"], bad_correctness=True)

    assert code == 0
    assert "WARNING" in capsys.readouterr().out
    assert "FAILURES" in (out / "run_summary.md").read_text(encoding="utf-8")


def test_main_says_when_fewer_than_three_runs_are_used(tmp_path, capsys):
    run_main(tmp_path, ["--no-charts"], scales=(1.0,))
    assert "fewer than 3 runs" in capsys.readouterr().out


# --- charts (optional library) --------------------------------------------------------
def test_charts_are_real_png_files_when_matplotlib_is_installed(tmp_path):
    pytest.importorskip("matplotlib")
    runs = load(tmp_path / "runs")
    out = tmp_path / "charts"
    out.mkdir()

    written = ar.make_charts(out, runs)

    assert set(written) == {"chart_key_operations.png", "chart_sizes.png",
                            "chart_full_encrypt_small_files.png",
                            "chart_cipher_throughput.png"}
    for name in written:
        assert (out / name).read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


def test_charts_are_skipped_cleanly_without_matplotlib(tmp_path, monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "matplotlib", None)  # makes the import fail
    code, out = run_main(tmp_path)

    assert code == 0
    assert ar.make_charts(out, load(tmp_path / "again")) is None
    assert "Charts skipped" in capsys.readouterr().out
    assert "matplotlib is not installed" in (out / "run_summary.md").read_text(encoding="utf-8")
    assert (out / "key_operations.md").is_file()