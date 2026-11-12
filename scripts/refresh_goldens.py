#!/usr/bin/env python3
"""Regenerate (or check) everything derived from the pinned snapshot. Standard library only.

    python scripts/refresh_goldens.py           # rewrite the generated analysis, the mixed list and both goldens
    python scripts/refresh_goldens.py --check   # exit 1 with an explanation if any of them is stale

Derived files, all produced by running the real tool on data/snapshot/:
  docs/real_data_analysis.md, data/snapshot/mixed_findings.csv   (scripts/analyze_snapshot.py)
  tests/golden/snapshot_top25.txt                                (kev_prioritize.py --top 25)
  tests/golden/snapshot_ranked_csv.sha256                        (sha256 of kev_prioritize.py --format csv)

See docs/REFRESHING_SNAPSHOT.md for when and how to use this.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import sys
import tempfile
from typing import Any, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import kev_prioritize as kp  # noqa: E402

SNAP = os.path.join(ROOT, "data", "snapshot")
GOLDEN = os.path.join(ROOT, "tests", "golden")
TOP25 = os.path.join(GOLDEN, "snapshot_top25.txt")
CSV_SHA = os.path.join(GOLDEN, "snapshot_ranked_csv.sha256")

EXPLANATION = """\
STALE GOLDEN FILES: {stale}

The tool's output on the pinned snapshot (or the generated analysis) no longer matches the committed copy.
This is expected after a deliberate change to scoring, sort order, output columns or the snapshot itself,
and it is a bug otherwise. To resolve:
  1. If the change was NOT intended, fix the code; do not regenerate.
  2. If it was intended, run:  python scripts/refresh_goldens.py
  3. Review `git diff` on the regenerated files (a pure re-ordering of tied rows is the only change you
     should see from sort-order work), update README/docs figures that quote them, add a CHANGELOG line,
     and commit the regenerated files together with the code change.
Procedure for a new snapshot: docs/REFRESHING_SNAPSHOT.md
"""


def _load_analyze() -> Any:
    spec = importlib.util.spec_from_file_location(
        "analyze_snapshot", os.path.join(ROOT, "scripts", "analyze_snapshot.py")
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run_tool(fmt: str, extra: tuple[str, ...] = ()) -> bytes:
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "out")
        rc = kp.main(
            [
                os.path.join(SNAP, "mixed_findings.csv"),
                "--kev",
                os.path.join(SNAP, "known_exploited_vulnerabilities.json"),
                "--format",
                fmt,
                "-o",
                out,
                *extra,
            ]
        )
        if rc != 0:
            raise SystemExit("kev_prioritize failed on the snapshot (exit %d)" % rc)
        with open(out, "rb") as fh:
            return fh.read()


def _read(path: str) -> Optional[bytes]:
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except FileNotFoundError:
        return None


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    p.add_argument("--check", action="store_true", help="compare with the committed files, write nothing")
    args = p.parse_args(argv)

    analyze = _load_analyze()
    if not args.check:
        analyze.main([])  # first: the mixed list is the input of the golden runs
    top25 = _run_tool("text", ("--top", "25"))
    csv_hash = (hashlib.sha256(_run_tool("csv")).hexdigest() + "\n").encode("ascii")

    if args.check:
        stale = []
        if analyze.main(["--check"]) != 0:
            stale.append("docs/real_data_analysis.md or data/snapshot/mixed_findings.csv")
        for path, want in ((TOP25, top25), (CSV_SHA, csv_hash)):
            if _read(path) != want:
                stale.append(os.path.relpath(path, ROOT).replace(os.sep, "/"))
        if stale:
            print(EXPLANATION.format(stale=", ".join(stale)), file=sys.stderr)
            return 1
        print("golden files are up to date")
        return 0

    os.makedirs(GOLDEN, exist_ok=True)
    for path, data in ((TOP25, top25), (CSV_SHA, csv_hash)):
        if _read(path) != data:
            with open(path, "wb") as fh:
                fh.write(data)
            print("updated %s" % os.path.relpath(path, ROOT))
    print("done; review `git diff` before committing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
