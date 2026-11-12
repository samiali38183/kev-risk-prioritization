"""Regression tests for the defects found in review (v0.3.0): mixed CVSS scales, deterministic order,
unscored inputs, and input error handling. Run: python -m unittest discover -s tests"""

import contextlib
import io
import json
import os
import random
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import kev_prioritize as kp  # noqa: E402

DATA = os.path.join(ROOT, "data")
SNAP = os.path.join(DATA, "snapshot")
HEADER = "cve,asset,acr,epss,days_open"


def F(cve="CVE-2020-0001", asset="a", acr=4.0, cvss=None, epss=0.5, days=3, **kw):
    return kp.Finding(cve=cve, asset=asset, acr=acr, cvss=cvss, epss=epss, days_open=days, **kw)


def run_cli(args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = kp.main(args)
    return rc, out.getvalue(), err.getvalue()


class TempFiles(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name

    def write(self, name, text):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        return path


class MixedCvssTests(TempFiles):
    KEV = {"CVE-2020-0001"}

    def test_pure_with_cvss_uses_all_four_terms(self):
        ranked = kp.score_all([F(cvss=0.0)], self.KEV)
        self.assertEqual(ranked[0].risk_score, 59.5)
        self.assertEqual(ranked[0].score_basis, kp.BASIS_FULL)

    def test_pure_without_cvss_renormalizes(self):
        ranked = kp.score_all([F(), F(cve="CVE-2020-0002")], self.KEV)
        self.assertEqual([f.risk_score for f in ranked], [73.5, 26.5])
        self.assertTrue(all(f.score_basis == kp.BASIS_NO_CVSS for f in ranked))

    def test_all_missing_equals_no_cvss_column(self):
        # blank cells in every row behave exactly like a missing column
        blank = [{"cve": "CVE-2020-0001", "asset": "a", "acr": "4", "cvss": "", "epss": "0.5", "days_open": "3"}]
        nocol = [{"cve": "CVE-2020-0001", "asset": "a", "acr": "4", "epss": "0.5", "days_open": "3"}]
        a = kp.score_all(kp.load_findings_from_rows(blank), self.KEV)[0]
        b = kp.score_all(kp.load_findings_from_rows(nocol), self.KEV)[0]
        self.assertEqual((a.risk_score, a.score_basis), (b.risk_score, b.score_basis))

    def test_mixed_list_is_refused_with_counts(self):
        with self.assertRaises(kp.InputError) as cm:
            kp.score_all([F(cvss=0.0), F(cve="CVE-2020-0002")], self.KEV)
        self.assertIn("1 row(s) with CVSS and 1 without", str(cm.exception))
        self.assertIn("--allow-mixed", str(cm.exception))

    def test_allow_mixed_scores_every_row_on_one_scale(self):
        # The reported defect: same finding scored 73.5 without CVSS but 59.5 with CVSS 0.0.
        ranked = kp.score_all([F(cvss=0.0), F(asset="b")], self.KEV, allow_mixed=True)
        self.assertEqual([f.risk_score for f in ranked], [73.5, 73.5])
        self.assertTrue(all(f.score_basis == kp.BASIS_NO_CVSS for f in ranked))

    def test_allow_mixed_rank_does_not_depend_on_which_rows_have_cvss(self):
        a = [F(cve="CVE-2020-0001", cvss=10.0), F(cve="CVE-2020-0002", epss=0.9)]
        b = [F(cve="CVE-2020-0001", cvss=None), F(cve="CVE-2020-0002", epss=0.9, cvss=1.0)]
        ra = [f.cve for f in kp.score_all(a, self.KEV, allow_mixed=True)]
        rb = [f.cve for f in kp.score_all(b, self.KEV, allow_mixed=True)]
        self.assertEqual(ra, rb)

    def test_cli_refuses_mixed_with_exit_2_and_one_line(self):
        csv_path = self.write("m.csv", HEADER + ",cvss\nCVE-2020-0001,a,4,0.5,3,9.0\nCVE-2020-0002,b,4,0.5,3,\n")
        kev = os.path.join(DATA, "sample_kev.json")
        rc, out, err = run_cli([csv_path, "--kev", kev])
        self.assertEqual((rc, out), (2, ""))
        self.assertEqual(len(err.strip().splitlines()), 1)
        self.assertIn("--allow-mixed", err)

    def test_cli_allow_mixed_warns_and_flags_rows(self):
        csv_path = self.write("m.csv", HEADER + ",cvss\nCVE-2020-0001,a,4,0.5,3,9.0\nCVE-2020-0002,b,4,0.5,3,\n")
        kev = os.path.join(DATA, "sample_kev.json")
        rc, out, err = run_cli([csv_path, "--kev", kev, "--allow-mixed", "--format", "json"])
        self.assertEqual(rc, 0)
        self.assertIn("warning: mixed list", err)
        ranked = json.loads(out)["ranked"]
        self.assertEqual({r["score_basis"] for r in ranked}, {kp.BASIS_NO_CVSS})
        rc, out, _ = run_cli([csv_path, "--kev", kev, "--allow-mixed"])
        self.assertIn("NOTE: mixed list", out)


class DeterminismTests(unittest.TestCase):
    @staticmethod
    def _tied():
        # identical scores; only identity differs
        return [F(cve="CVE-2020-%04d" % (i % 5 + 1), asset="asset-%d" % (i % 3)) for i in range(15)]

    def test_shuffled_input_gives_identical_order(self):
        expected = [(f.cve, f.asset) for f in kp.score_all(self._tied(), set())]
        rng = random.Random(7)
        for _ in range(25):
            items = self._tied()
            rng.shuffle(items)
            self.assertEqual([(f.cve, f.asset) for f in kp.score_all(items, set())], expected)

    def test_tie_order_is_by_cve_then_asset(self):
        ranked = kp.score_all(
            [F(cve="CVE-2020-0002"), F(cve="CVE-2020-0001", asset="z"), F(cve="CVE-2020-0001", asset="b")], set()
        )
        self.assertEqual(
            [(f.cve, f.asset) for f in ranked], [("CVE-2020-0001", "b"), ("CVE-2020-0001", "z"), ("CVE-2020-0002", "a")]
        )

    def test_days_open_precedes_identity(self):
        ranked = kp.score_all([F(cve="CVE-2020-0001", days=1), F(cve="CVE-2020-0002", days=9)], set())
        self.assertEqual([f.cve for f in ranked], ["CVE-2020-0002", "CVE-2020-0001"])

    def test_kev_precedes_epss_at_equal_score(self):
        # Custom weights make a KEV row and a non-KEV row tie on score; KEV must come first.
        w = {"kev": 0.5, "acr": 0.0, "epss": 0.5, "cvss": 0.0}
        ranked = kp.score_all(
            [F(cve="CVE-2020-0002", epss=1.0), F(cve="CVE-2020-0001", epss=0.0)], {"CVE-2020-0001"}, weights=w
        )
        self.assertEqual([f.risk_score for f in ranked], [50.0, 50.0])
        self.assertEqual([f.cve for f in ranked], ["CVE-2020-0001", "CVE-2020-0002"])

    def test_snapshot_list_is_order_independent(self):
        kev = kp.load_kev(os.path.join(SNAP, "known_exploited_vulnerabilities.json"))
        base = kp.load_findings(os.path.join(SNAP, "mixed_findings.csv"))
        expected = [(f.cve, f.asset) for f in kp.score_all(list(base), kev)]
        shuffled = list(base)
        random.Random(11).shuffle(shuffled)
        self.assertEqual([(f.cve, f.asset) for f in kp.score_all(shuffled, kev)], expected)


class UnscoredInputTests(unittest.TestCase):
    """internet_exposed and days_open are carried through but do not change the score. These tests
    document that limitation (README and docs/bod-26-04.md say so); if scoring ever uses them they
    must fail here so the documentation is updated with the change."""

    def test_internet_exposed_does_not_change_score(self):
        ra = kp.score_all([F(internet_exposed=True)], set())[0]
        rb = kp.score_all([F(internet_exposed=False)], set())[0]
        self.assertNotEqual(ra.internet_exposed, rb.internet_exposed)
        self.assertEqual(ra.risk_score, rb.risk_score)

    def test_days_open_does_not_change_score(self):
        scores = {kp.score_all([F(days=d)], set())[0].risk_score for d in (0, 30, 4000)}
        self.assertEqual(len(scores), 1)

    def test_exposure_column_is_parsed_and_carried_to_output(self):
        rows = [
            {"cve": "CVE-2020-0001", "asset": "a", "acr": "4", "epss": "0.1", "days_open": "3", "internet_exposed": v}
            for v in ("true", "no")
        ]
        out = kp.score_all(kp.load_findings_from_rows(rows), set())
        self.assertEqual(sorted(f.internet_exposed for f in out), [False, True])


class InputErrorTests(TempFiles):
    def setUp(self):
        super().setUp()
        self.kev = os.path.join(DATA, "sample_kev.json")

    def fails(self, args, *needles):
        rc, out, err = run_cli(args)
        self.assertEqual(rc, 2, err)
        self.assertEqual(out, "")
        lines = err.strip().splitlines()
        self.assertEqual(len(lines), 1, err)
        self.assertTrue(lines[0].startswith("kev_prioritize: error: "), err)
        for n in needles:
            self.assertIn(n, err)

    def csv_fails(self, body, *needles, header=HEADER):
        path = self.write("f.csv", header + "\n" + body)
        self.fails([path, "--kev", self.kev], *needles)

    def good(self):
        return self.write("good.csv", HEADER + "\nCVE-2020-0001,a,4,0.1,3\n")

    def test_missing_columns(self):
        self.csv_fails("CVE-2020-0001,a,4\n", "missing required column(s): epss, days_open", header="cve,asset,acr")

    def test_blank_epss_reports_row(self):
        self.csv_fails("CVE-2020-0001,a,4,0.1,3\nCVE-2020-0002,a,4,,3\n", "row 3", "'epss' is empty")

    def test_non_numeric(self):
        self.csv_fails("CVE-2020-0001,a,high,0.1,3\n", "row 2", "'acr' is not a number: 'high'")

    def test_out_of_range_values(self):
        self.csv_fails("CVE-2020-0001,a,9,0.1,3\n", "row 2", "'acr' = 9 is out of range")
        self.csv_fails("CVE-2020-0001,a,0,0.1,3\n", "'acr' = 0 is out of range")
        self.csv_fails("CVE-2020-0001,a,4,1.5,3\n", "'epss' = 1.5 is out of range")
        self.csv_fails("CVE-2020-0001,a,4,0.1,3,11\n", "'cvss' = 11 is out of range", header=HEADER + ",cvss")
        self.csv_fails("CVE-2020-0001,a,4,nan,3\n", "'epss' = nan is out of range")

    def test_days_open_must_be_non_negative_integer(self):
        self.csv_fails("CVE-2020-0001,a,4,0.1,3.5\n", "'days_open' is not a whole number")
        self.csv_fails("CVE-2020-0001,a,4,0.1,-2\n", "'days_open' = -2 is negative")

    def test_bad_cve_asset_and_exposure(self):
        self.csv_fails("CVE-1,a,4,0.1,3\n", "row 2", "not a CVE id")
        self.csv_fails("CVE-2020-0001,,4,0.1,3\n", "'asset' is empty")
        self.csv_fails("CVE-2020-0001,a,4,0.1,3,maybe\n", "'internet_exposed'", header=HEADER + ",internet_exposed")

    def test_short_row_reports_row(self):
        self.csv_fails("CVE-2020-0001,a,4,0.1,3\nCVE-2020-0002,a\n", "row 3")

    def test_empty_and_header_only_findings(self):
        self.fails([self.write("e.csv", ""), "--kev", self.kev], "empty")
        self.fails([self.write("w.csv", "  \n"), "--kev", self.kev], "empty")
        self.fails([self.write("h.csv", HEADER + "\n"), "--kev", self.kev], "no data rows")

    def test_missing_findings_file(self):
        self.fails([os.path.join(self.dir, "nope.csv"), "--kev", self.kev], "findings file not found")

    def test_malformed_kev_json(self):
        self.fails([self.good(), "--kev", self.write("k.json", "{")], "malformed KEV JSON")

    def test_kev_wrong_shape(self):
        good = self.good()
        for i, doc in enumerate(["[]", '{"vulnerabilities": 3}', "{}"]):
            self.fails([good, "--kev", self.write("k%d.json" % i, doc)], "not a KEV catalog")
        self.fails([good, "--kev", self.write("k5.json", '{"vulnerabilities":[{"cve":"x"}]}')], "entry 1", "cveID")
        self.fails([good, "--kev", self.write("k6.json", '{"vulnerabilities":[]}')], "no vulnerabilities")

    def test_empty_and_missing_kev_file(self):
        good = self.good()
        self.fails([good, "--kev", self.write("k.json", "")], "KEV file is empty")
        self.fails([good, "--kev", os.path.join(self.dir, "none.json")], "KEV file not found")

    def test_kev_source_required(self):
        self.fails([self.good()], "--kev")

    def test_utf8_bom_and_header_whitespace_are_accepted(self):
        path = self.write("b.csv", "﻿ cve , asset,acr,epss,days_open\nCVE-2020-0001,a,4,0.1,3\n")
        self.assertEqual(len(kp.load_findings(path)), 1)

    def test_unwritable_output_exits_1(self):
        rc, _, err = run_cli([self.good(), "--kev", self.kev, "-o", os.path.join(self.dir, "no", "such", "o.txt")])
        self.assertEqual(rc, 1)
        self.assertIn("cannot write", err)

    def test_valid_demo_still_passes(self):
        rc, out, err = run_cli([os.path.join(DATA, "sample_findings.csv"), "--kev", self.kev])
        self.assertEqual((rc, err), (0, ""))
        self.assertIn("CVE-2021-44228", out)


if __name__ == "__main__":
    unittest.main()
