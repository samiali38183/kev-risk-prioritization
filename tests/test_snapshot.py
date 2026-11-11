"""Tests for the pinned snapshot, the snapshot scripts and the no-CVSS scoring path.

Run: python -m unittest discover -s tests
"""
import csv
import gzip
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import kev_prioritize as kp  # noqa: E402

SNAP = os.path.join(ROOT, "data", "snapshot")
GOLDEN = os.path.join(ROOT, "tests", "golden")


def _load_script(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, "scripts", name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


fetch = _load_script("fetch_snapshot")
analyze = _load_script("analyze_snapshot")


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


class SnapshotIntegrityTests(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(SNAP, "SNAPSHOT.json"), encoding="utf-8") as fh:
            self.meta = json.load(fh)

    def test_kev_file_matches_recorded_hash_and_header(self):
        path = os.path.join(SNAP, "known_exploited_vulnerabilities.json")
        self.assertEqual(_sha(path), self.meta["kev"]["sha256"])
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["catalogVersion"], self.meta["kev"]["catalogVersion"])
        self.assertEqual(data["count"], len(data["vulnerabilities"]))
        self.assertEqual(data["count"], self.meta["kev"]["count"])

    def test_subset_matches_recorded_hash_and_counts(self):
        path = os.path.join(SNAP, "epss_subset.csv")
        self.assertEqual(_sha(path), self.meta["subset"]["sha256"])
        with open(path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), self.meta["subset"]["rows"])
        kev = [r for r in rows if r["in_kev"] == "1"]
        self.assertEqual(len(kev), self.meta["subset"]["kev_rows"])
        self.assertEqual(len(rows) - len(kev), self.meta["subset"]["non_kev_sampled"])
        self.assertTrue(all(0.0 <= float(r["epss"]) <= 1.0 for r in rows))

    def test_subset_kev_flag_agrees_with_catalog(self):
        ids = kp.load_kev(os.path.join(SNAP, "known_exploited_vulnerabilities.json"))
        with open(os.path.join(SNAP, "epss_subset.csv"), newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                self.assertEqual(r["cve"] in ids, r["in_kev"] == "1", r["cve"])

    def test_snapshot_is_small(self):
        total = sum(os.path.getsize(os.path.join(SNAP, f)) for f in os.listdir(SNAP))
        self.assertLess(total, 5 * 1024 * 1024)


class GoldenTests(unittest.TestCase):
    """The tool's output on the snapshot must not drift unnoticed."""

    def _run(self, fmt, extra=()):
        kev = os.path.join(SNAP, "known_exploited_vulnerabilities.json")
        findings = os.path.join(SNAP, "mixed_findings.csv")
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "out")
            rc = kp.main([findings, "--kev", kev, "--format", fmt, "-o", out, *extra])
            self.assertEqual(rc, 0)
            with open(out, "rb") as fh:
                return fh.read()

    def test_text_top25_matches_golden(self):
        got = self._run("text", ["--top", "25"])
        with open(os.path.join(GOLDEN, "snapshot_top25.txt"), "rb") as fh:
            self.assertEqual(got, fh.read())

    def test_full_csv_matches_golden_hash(self):
        got = hashlib.sha256(self._run("csv")).hexdigest()
        with open(os.path.join(GOLDEN, "snapshot_ranked_csv.sha256"), encoding="utf-8") as fh:
            self.assertEqual(got, fh.read().strip())

    def test_analysis_files_are_up_to_date(self):
        self.assertEqual(analyze.main(["--check"]), 0)


class NoCvssScoringTests(unittest.TestCase):
    def test_missing_cvss_drops_term_and_renormalizes(self):
        self.assertEqual(kp.risk_score(True, 8, 1.0, None), 100.0)
        self.assertEqual(kp.risk_score(False, 0, 0.0, None), 0.0)
        # KEV only: 0.40 / (0.40 + 0.25 + 0.20) = 47.06
        self.assertAlmostEqual(kp.risk_score(True, 0, 0.0, None), 47.1, places=1)

    def test_blank_cvss_cell_loads_as_none(self):
        rows = [{"cve": "cve-2021-44228", "asset": "a", "acr": "4", "cvss": "", "epss": "0.5", "days_open": "3"},
                {"cve": "CVE-2020-0001", "asset": "b", "acr": "4", "epss": "0.5", "days_open": "3"}]
        findings = kp.load_findings_from_rows(rows)
        self.assertEqual([f.cvss for f in findings], [None, None])
        ranked = kp.score_all(findings, {"CVE-2021-44228"})
        self.assertTrue(ranked[0].kev)
        self.assertIsNone(kp.population_compare(ranked)["kev"]["avg_cvss"])

    def test_mixed_cvss_and_missing_cvss_rank_without_error(self):
        rows = [{"cve": "CVE-1", "asset": "a", "acr": "4", "cvss": "9.0", "epss": "0.5", "days_open": "3"},
                {"cve": "CVE-2", "asset": "b", "acr": "4", "cvss": "", "epss": "0.5", "days_open": "3"}]
        ranked = kp.score_all(kp.load_findings_from_rows(rows), set())
        self.assertEqual(len(ranked), 2)


class FetchScriptTests(unittest.TestCase):
    ROWS = [("CVE-2020-%04d" % i, "0.%03d" % (i % 1000), "0.5") for i in range(1, 301)]

    def test_subset_contains_all_kev_and_fixed_sample_size(self):
        kev = {"CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003"}
        subset, kev_rows, non_kev = fetch.build_subset(self.ROWS, kev, "seed", 50)
        self.assertEqual(len(kev_rows), 3)
        self.assertEqual(len(non_kev), 297)
        self.assertEqual(len(subset), 53)
        self.assertEqual({r[0] for r in subset if r[3] == "1"}, kev)
        self.assertEqual([r[0] for r in subset], sorted(r[0] for r in subset))

    def test_sampling_is_deterministic_and_input_order_independent(self):
        kev = {"CVE-2020-0001"}
        a = fetch.build_subset(self.ROWS, kev, "seed", 40)[0]
        b = fetch.build_subset(list(reversed(self.ROWS)), kev, "seed", 40)[0]
        c = fetch.build_subset(self.ROWS, kev, "other-seed", 40)[0]
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_parse_epss_reads_header_comment_and_rows(self):
        raw = gzip.compress(b"#model_version:v9,score_date:2026-01-02T00:00:00Z\n"
                            b"cve,epss,percentile\nCVE-2020-0001,0.5,0.9\ncve-2020-0002,0.01,0.1\n")
        meta, rows = fetch.parse_epss(raw)
        self.assertEqual(meta["model_version"], "v9")
        self.assertEqual(rows, [("CVE-2020-0001", "0.5", "0.9"), ("CVE-2020-0002", "0.01", "0.1")])

    def test_parse_epss_rejects_unexpected_header(self):
        with self.assertRaises(ValueError):
            fetch.parse_epss(gzip.compress(b"a,b,c\n1,2,3\n"))

    def test_population_stats_counts_thresholds(self):
        kev_rows = [("A", "0.95", "1"), ("B", "0.05", "1")]
        non_rows = [("C", "0.6", "1"), ("D", "0.2", "1"), ("E", "0.01", "1")]
        stats = fetch.population_stats(kev_rows, non_rows)
        self.assertEqual(stats["0.1"], {"kev_ge": 1, "non_kev_ge": 2})
        self.assertEqual(stats["0.5"], {"kev_ge": 1, "non_kev_ge": 1})
        self.assertEqual(stats["0.9"], {"kev_ge": 1, "non_kev_ge": 0})


class AnalysisMathTests(unittest.TestCase):
    def test_auc_perfect_reversed_and_tied(self):
        self.assertEqual(analyze.auc([0.9, 0.8], [0.1, 0.2]), 1.0)
        self.assertEqual(analyze.auc([0.1, 0.2], [0.8, 0.9]), 0.0)
        self.assertEqual(analyze.auc([0.5, 0.5], [0.5, 0.5]), 0.5)

    def test_auc_known_value(self):
        # pos [1.5, 4], neg [1, 2]: 3 of 4 pairs win (1.5 loses to 2)
        self.assertAlmostEqual(analyze.auc([1.5, 4.0], [1.0, 2.0]), 0.75)

    def test_quantile_interpolates(self):
        self.assertEqual(analyze.quantile([0.0, 10.0], 0.5), 5.0)
        self.assertEqual(analyze.quantile([1.0, 2.0, 3.0], 0.5), 2.0)


if __name__ == "__main__":
    unittest.main()
