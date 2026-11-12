"""Tests for scripts/refresh_goldens.py: stale goldens must fail loudly with an explanation."""

import contextlib
import importlib.util
import io
import os
import re
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load():
    spec = importlib.util.spec_from_file_location(
        "refresh_goldens", os.path.join(ROOT, "scripts", "refresh_goldens.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class RefreshGoldensTests(unittest.TestCase):
    def test_committed_goldens_are_current(self):
        rg = _load()
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = rg.main(["--check"])
        self.assertEqual(rc, 0, err.getvalue())

    def test_stale_golden_fails_with_explanation(self):
        rg = _load()
        with tempfile.TemporaryDirectory() as d:
            stale = os.path.join(d, "snapshot_top25.txt")
            with open(stale, "w", encoding="utf-8") as fh:
                fh.write("not the real output\n")
            rg.TOP25 = stale
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                rc = rg.main(["--check"])
        self.assertEqual(rc, 1)
        self.assertIn("STALE GOLDEN FILES", err.getvalue())
        self.assertIn("snapshot_top25.txt", err.getvalue())
        self.assertIn("python scripts/refresh_goldens.py", err.getvalue())

    def test_write_mode_restores_a_stale_golden(self):
        rg = _load()
        with tempfile.TemporaryDirectory() as d:
            rg.TOP25 = os.path.join(d, "snapshot_top25.txt")
            rg.CSV_SHA = os.path.join(d, "snapshot_ranked_csv.sha256")
            rg.GOLDEN = d
            # analyze.main([]) would rewrite committed files with identical bytes; point it at a no-op
            rg._load_analyze = lambda: type("A", (), {"main": staticmethod(lambda argv: 0)})
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(rg.main([]), 0)
                self.assertEqual(rg.main(["--check"]), 0)
            with open(rg.TOP25, "rb") as fh:
                got = fh.read()
            with open(os.path.join(ROOT, "tests", "golden", "snapshot_top25.txt"), "rb") as ref:
                self.assertEqual(got, ref.read())


class ReadmeFigureTests(unittest.TestCase):
    def test_readme_figures_match_analysis(self):
        # The README quotes figures by hand; this fails when a snapshot refresh leaves them stale.
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as fh:
            readme = fh.read()
        with open(os.path.join(ROOT, "docs", "real_data_analysis.md"), encoding="utf-8") as fh:
            doc = fh.read()
        m_doc = re.search(r"\*\*AUC of EPSS[^*]*?: ([0-9.]+)\*\* \(95% bootstrap interval ([0-9.]+) to ([0-9.]+)", doc)
        m_readme = re.search(r"AUC ([0-9.]+) \(95% bootstrap interval ([0-9.]+) to ([0-9.]+)\)", readme)
        self.assertIsNotNone(m_doc)
        self.assertIsNotNone(m_readme)
        self.assertEqual(m_doc.groups(), m_readme.groups())


if __name__ == "__main__":
    unittest.main()
