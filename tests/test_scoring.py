"""Unit tests for kev_prioritize.py. Run: python -m pytest -q  (or python -m unittest)"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import kev_prioritize as kp  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")


class ScoreTests(unittest.TestCase):
    def test_bounds(self):
        self.assertEqual(kp.risk_score(False, 0, 0.0, 0.0), 0.0)
        self.assertEqual(kp.risk_score(True, 8, 1.0, 10.0), 100.0)

    def test_score_is_normalized_by_weight_total(self):
        # Documented weights sum to 1.05; normalization keeps the scale 0-100 and
        # preserves ordering. Any re-tuned weight set must still give 100 at the max.
        custom = {"kev": 0.5, "acr": 0.3, "epss": 0.3, "cvss": 0.1}
        self.assertEqual(kp.risk_score(True, 8, 1.0, 10.0, custom), 100.0)
        self.assertAlmostEqual(kp.risk_score(True, 0, 0.0, 0.0), 100 * 0.40 / 1.05, places=1)

    def test_kev_outranks_severity_alone(self):
        # The KEV-first point: a KEV CVSS-7.5 outranks a non-KEV CVSS-9.8 on identical assets.
        kev_moderate = kp.risk_score(True, acr=5, epss=0.5, cvss=7.5)
        nonkev_critical = kp.risk_score(False, acr=5, epss=0.05, cvss=9.8)
        self.assertGreater(kev_moderate, nonkev_critical)

    def test_inputs_are_clamped(self):
        self.assertEqual(kp.risk_score(True, 99, 5.0, 50.0), 100.0)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.kev = kp.load_kev(os.path.join(DATA, "sample_kev.json"))
        self.findings = kp.load_findings(os.path.join(DATA, "sample_findings.csv"))

    def test_sample_data_loads(self):
        self.assertEqual(len(self.findings), 20)
        self.assertEqual(len(self.kev), 12)

    def test_kev_matching_is_case_insensitive(self):
        self.assertIn("CVE-2021-44228", self.kev)
        f = kp.Finding(cve="cve-2021-44228", asset="x", acr=1, cvss=1, epss=0, days_open=1)
        kp.score_all([f], self.kev)
        self.assertTrue(f.kev)

    def test_ranked_queue_is_descending_and_kev_heavy(self):
        ranked = kp.score_all(self.findings, self.kev)
        scores = [f.risk_score for f in ranked]
        self.assertEqual(scores, sorted(scores, reverse=True))
        top10 = ranked[:10]
        self.assertTrue(all(f.kev for f in top10))

    def test_population_compare_shows_epss_gap(self):
        ranked = kp.score_all(self.findings, self.kev)
        comp = kp.population_compare(ranked)
        self.assertEqual(comp["kev"]["count"] + comp["non_kev"]["count"], 20)
        self.assertGreater(comp["kev"]["avg_epss"], comp["non_kev"]["avg_epss"])

    def test_cli_runs_json(self):
        import io
        import json
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = kp.main(
                [
                    os.path.join(DATA, "sample_findings.csv"),
                    "--kev",
                    os.path.join(DATA, "sample_kev.json"),
                    "--format",
                    "json",
                ]
            )
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertEqual(len(out["ranked"]), 20)


if __name__ == "__main__":
    unittest.main()
