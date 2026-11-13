#!/usr/bin/env python3
"""Risk-based vulnerability prioritization: KEV + ACR + EPSS + CVSS.

Reference implementation of the weighted model described in docs/methodology.md. This is a simple
weighted score of my own design that puts known-exploited vulnerabilities first. It is NOT
an implementation of CISA BOD 26-04 (see docs/methodology.md section 8).
Standard library only. Runs on the synthetic data in data/ or on your own CSV.

    python kev_prioritize.py data/sample_findings.csv --kev data/sample_kev.json
    python kev_prioritize.py findings.csv --kev-live --format csv -o ranked.csv

Input CSV columns (header required):
    cve, asset, acr, epss, days_open  [optional: cvss, system_group, vendor, internet_exposed]

If the cvss column is missing or a cell is blank, the CVSS term is left out of that finding's score and
the remaining weights are renormalized to 0-100. Scores computed from different signal sets are on
different scales, so a list that mixes rows with and without CVSS is refused unless --allow-mixed is
given (then every row is scored without CVSS); see docs/methodology.md section 6.

Exit codes: 0 ok; 2 bad input or usage (one-line message on stderr); 1 network or output-file failure.

Scoring (0-100):
    risk = 100 * (0.40*kev + 0.25*(acr/8) + 0.20*epss + 0.20*(cvss/10)) / 1.05
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import math
import re
import statistics
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any, Iterable, Optional

__version__ = "0.3.0"

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

DEFAULT_WEIGHTS = {"kev": 0.40, "acr": 0.25, "epss": 0.20, "cvss": 0.20}

REQUIRED_COLUMNS = ("cve", "asset", "acr", "epss", "days_open")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
TRUE_VALUES = {"1", "true", "yes"}
FALSE_VALUES = {"0", "false", "no", ""}

BASIS_FULL = "kev+acr+epss+cvss"
BASIS_NO_CVSS = "kev+acr+epss"


class InputError(ValueError):
    """Bad user input (file contents or arguments). The CLI prints the message and exits 2."""


class NetworkError(RuntimeError):
    """The live KEV feed could not be fetched. The CLI prints the message and exits 1."""


@dataclass
class Finding:
    cve: str
    asset: str
    acr: float  # asset criticality rating, 1-8
    cvss: Optional[float]  # 0-10, None when the input has no CVSS
    epss: float  # 0-1
    days_open: int
    system_group: str = ""
    vendor: str = ""
    internet_exposed: bool = False
    kev: bool = False
    risk_score: float = 0.0
    score_basis: str = ""  # signals the score used: BASIS_FULL or BASIS_NO_CVSS


def risk_score(
    kev: bool, acr: float, epss: float, cvss: Optional[float], weights: dict[str, float] = DEFAULT_WEIGHTS
) -> float:
    """Weighted composite from docs/methodology.md section 6. Inputs are clamped to range.

    With cvss=None the CVSS term and its weight are dropped and the rest is renormalized, so the
    result is on a different scale from a score computed with CVSS. Compare scores only when they
    come from the same signal set; score_all enforces that.
    """
    acr = min(max(acr, 0.0), 8.0)
    epss = min(max(epss, 0.0), 1.0)
    score = weights["kev"] * (1.0 if kev else 0.0) + weights["acr"] * (acr / 8.0) + weights["epss"] * epss
    total = weights["kev"] + weights["acr"] + weights["epss"]
    if cvss is not None:
        cvss = min(max(cvss, 0.0), 10.0)
        score += weights["cvss"] * (cvss / 10.0)
        total += weights["cvss"]
    # Divide by the weight total so the result is a true 0-100 regardless of how the weights are
    # tuned (the documented defaults sum to 1.05). When CVSS is absent its weight is dropped from
    # the total, so a finding without CVSS is still scored on 0-100.
    return round(100.0 * score / total, 1)


def _read_text(path: str, what: str) -> str:
    try:
        with open(path, encoding="utf-8-sig", newline="") as fh:
            text = fh.read()
    except FileNotFoundError:
        raise InputError("%s file not found: %s" % (what, path)) from None
    except (OSError, UnicodeDecodeError) as exc:
        raise InputError("cannot read %s file %s: %s" % (what, path, exc)) from None
    if not text.strip():
        raise InputError("%s file is empty: %s" % (what, path))
    return text


def load_findings(path: str) -> list[Finding]:
    text = _read_text(path, "findings")
    numbered: list[tuple[int, dict[str, Any]]] = []
    try:
        reader = csv.DictReader(io.StringIO(text, newline=""))
        header = [h.strip() for h in (reader.fieldnames or [])]
        reader.fieldnames = header
        missing = [c for c in REQUIRED_COLUMNS if c not in header]
        if missing:
            raise InputError(
                "%s: missing required column(s): %s (found: %s)"
                % (path, ", ".join(missing), ", ".join(header) or "none")
            )
        for row in reader:
            numbered.append((reader.line_num, row))
    except csv.Error as exc:
        raise InputError("%s: malformed CSV: %s" % (path, exc)) from None
    return _parse_rows(numbered, path)


def load_findings_from_rows(rows: Iterable[dict[str, Any]]) -> list[Finding]:
    """Parse already-read rows. Row numbers in errors count the header as row 1."""
    return _parse_rows(list(enumerate(rows, start=2)), "input")


def _num(row: dict[str, Any], col: str, lo: float, hi: float, where: str) -> float:
    raw = (row.get(col) or "").strip()
    if not raw:
        raise InputError("%s: column '%s' is empty" % (where, col))
    try:
        val = float(raw)
    except ValueError:
        raise InputError("%s: column '%s' is not a number: %r" % (where, col, raw)) from None
    if not math.isfinite(val) or not lo <= val <= hi:
        raise InputError("%s: column '%s' = %s is out of range (%g to %g)" % (where, col, raw, lo, hi))
    return val


def _parse_rows(rows: list[tuple[int, dict[str, Any]]], source: str) -> list[Finding]:
    if not rows:
        raise InputError("%s: no data rows" % source)
    out = []
    for n, r in rows:
        where = "%s: row %d" % (source, n)
        absent = [c for c in REQUIRED_COLUMNS if c not in r]
        if absent:
            raise InputError("%s: missing column(s): %s" % (where, ", ".join(absent)))
        cve = (r.get("cve") or "").strip().upper()
        if not CVE_RE.match(cve):
            raise InputError("%s: column 'cve' is not a CVE id (CVE-YYYY-NNNN): %r" % (where, r.get("cve")))
        asset = (r.get("asset") or "").strip()
        if not asset:
            raise InputError("%s: column 'asset' is empty" % where)
        acr = _num(r, "acr", 1, 8, where)
        epss = _num(r, "epss", 0, 1, where)
        days_raw = (r.get("days_open") or "").strip()
        try:
            days_open = int(days_raw)
        except ValueError:
            raise InputError("%s: column 'days_open' is not a whole number: %r" % (where, days_raw)) from None
        if days_open < 0:
            raise InputError("%s: column 'days_open' = %d is negative" % (where, days_open))
        cvss = _num(r, "cvss", 0, 10, where) if (r.get("cvss") or "").strip() else None
        exposed_raw = (r.get("internet_exposed") or "").strip().lower()
        if exposed_raw not in TRUE_VALUES | FALSE_VALUES:
            raise InputError(
                "%s: column 'internet_exposed' must be 1/true/yes/0/false/no or blank: %r" % (where, exposed_raw)
            )
        out.append(
            Finding(
                cve=cve,
                asset=asset,
                acr=acr,
                cvss=cvss,
                epss=epss,
                days_open=days_open,
                system_group=r.get("system_group") or "",
                vendor=r.get("vendor") or "",
                internet_exposed=exposed_raw in TRUE_VALUES,
            )
        )
    return out


def parse_kev(data: Any, source: str) -> set[str]:
    """CVE ids from a parsed KEV document (CISA schema: {"vulnerabilities":[{"cveID":...}]})."""
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise InputError("%s: not a KEV catalog (expected an object with a 'vulnerabilities' list)" % source)
    ids = set()
    for i, v in enumerate(data["vulnerabilities"], start=1):
        cid = v.get("cveID") if isinstance(v, dict) else None
        if not isinstance(cid, str) or not cid.strip():
            raise InputError("%s: vulnerabilities entry %d has no 'cveID'" % (source, i))
        ids.add(cid.strip().upper())
    if not ids:
        # An empty catalog would silently mark every finding as non-KEV.
        raise InputError("%s: KEV catalog contains no vulnerabilities" % source)
    return ids


def load_kev(path: Optional[str] = None, live: bool = False) -> set[str]:
    """Return the set of CVE IDs in the KEV catalog (CISA JSON schema)."""
    if live:
        try:
            with urllib.request.urlopen(KEV_FEED_URL, timeout=30) as resp:  # noqa: S310 - fixed https URL
                data = json.load(resp)
        except (urllib.error.URLError, OSError) as exc:
            raise NetworkError("could not fetch the live KEV feed: %s" % exc) from None
        except ValueError as exc:
            raise InputError("live KEV feed is not valid JSON: %s" % exc) from None
        return parse_kev(data, "live KEV feed")
    if not path:
        raise InputError("need --kev <file.json> or --kev-live")
    text = _read_text(path, "KEV")
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise InputError("%s: malformed KEV JSON: %s" % (path, exc)) from None
    return parse_kev(data, path)


def cvss_coverage(findings: list[Finding]) -> tuple[int, int]:
    """(rows with CVSS, rows without CVSS)."""
    have = sum(1 for f in findings if f.cvss is not None)
    return have, len(findings) - have


def sort_key(f: Finding) -> tuple:
    """Total order: score, then KEV, EPSS, CVSS, ACR, days open (all descending), then stable
    identity keys (CVE id, asset, group, vendor, exposure) so input order never matters."""
    return (
        -f.risk_score,
        not f.kev,
        -f.epss,
        -(f.cvss if f.cvss is not None else -1.0),
        -f.acr,
        -f.days_open,
        f.cve,
        f.asset,
        f.system_group,
        f.vendor,
        f.internet_exposed,
    )


def score_all(
    findings: list[Finding], kev: set[str], weights: dict[str, float] = DEFAULT_WEIGHTS, allow_mixed: bool = False
) -> list[Finding]:
    """Score and rank. A list that mixes rows with and without CVSS raises InputError unless
    allow_mixed is set; then every row is scored without its CVSS term so all scores share one scale."""
    with_cvss, without_cvss = cvss_coverage(findings)
    mixed = with_cvss > 0 and without_cvss > 0
    if mixed and not allow_mixed:
        raise InputError(
            "findings mix %d row(s) with CVSS and %d without; scores computed from different signals are "
            "not comparable. Fill in CVSS for every row, remove the cvss column, or pass --allow-mixed to "
            "rank every row without its CVSS term" % (with_cvss, without_cvss)
        )
    use_cvss = with_cvss > 0 and not mixed
    for f in findings:
        f.cve = f.cve.strip().upper()
        f.kev = f.cve in kev
        f.risk_score = risk_score(f.kev, f.acr, f.epss, f.cvss if use_cvss else None, weights)
        f.score_basis = BASIS_FULL if use_cvss else BASIS_NO_CVSS
    return sorted(findings, key=sort_key)


def population_compare(findings: list[Finding]) -> dict[str, dict[str, Any]]:
    """Section 4 of the methodology: KEV vs non-KEV on volume, CVSS, EPSS, days open."""
    out: dict[str, dict[str, Any]] = {}
    for label, group in (("kev", [f for f in findings if f.kev]), ("non_kev", [f for f in findings if not f.kev])):
        if not group:
            out[label] = {"count": 0}
            continue
        cvss_vals = [f.cvss for f in group if f.cvss is not None]
        out[label] = {
            "count": len(group),
            "avg_cvss": round(statistics.mean(cvss_vals), 2) if cvss_vals else None,
            "avg_epss": round(statistics.mean(f.epss for f in group), 3),
            "avg_days_open": round(statistics.mean(f.days_open for f in group), 1),
        }
    return out


def concentration(findings: list[Finding], key: str) -> list[tuple[str, int]]:
    """Section 5: where KEV findings cluster (by system_group or vendor)."""
    counts: dict[str, int] = {}
    for f in findings:
        if f.kev:
            k = getattr(f, key) or "(unknown)"
            counts[k] = counts.get(k, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def render_text(ranked: list[Finding], top: int) -> str:
    lines = [f"{'#':>3} {'risk':>5}  {'KEV':<3} {'CVE':<16} {'CVSS':>4} {'EPSS':>5} {'ACR':>3} {'days':>4}  asset"]
    for i, f in enumerate(ranked[:top], 1):
        cvss = f"{f.cvss:>4.1f}" if f.cvss is not None else " n/a"
        lines.append(
            f"{i:>3} {f.risk_score:>5.1f}  {'yes' if f.kev else '-':<3} {f.cve:<16} "
            f"{cvss} {f.epss:>5.3f} {f.acr:>3.0f} {f.days_open:>4}  {f.asset}"
        )
    comp = population_compare(ranked)
    lines.append("")
    lines.append("KEV vs non-KEV population")
    for label in ("kev", "non_kev"):
        c = comp[label]
        if c["count"]:
            avg_cvss = c["avg_cvss"] if c["avg_cvss"] is not None else "n/a"
            lines.append(
                f"  {label:<8} n={c['count']:<3} avg CVSS {avg_cvss:<5} "
                f"avg EPSS {c['avg_epss']:<6} avg days open {c['avg_days_open']}"
            )
        else:
            lines.append(f"  {label:<8} n=0")
    conc = concentration(ranked, "system_group")
    if conc:
        lines.append("")
        lines.append("KEV concentration by system group: " + ", ".join(f"{k}={n}" for k, n in conc))
    with_cvss, without_cvss = cvss_coverage(ranked)
    if with_cvss and without_cvss:
        lines.append("")
        lines.append(
            "NOTE: mixed list (--allow-mixed). %d row(s) have CVSS and %d do not; every score above "
            "was computed WITHOUT the CVSS term so scores share one scale." % (with_cvss, without_cvss)
        )
    return "\n".join(lines)


def _run(args: argparse.Namespace) -> int:
    kev = load_kev(args.kev, live=args.kev_live)
    findings = load_findings(args.findings)
    with_cvss, without_cvss = cvss_coverage(findings)
    ranked = score_all(findings, kev, allow_mixed=args.allow_mixed)
    if with_cvss and without_cvss:
        print(
            "kev_prioritize: warning: mixed list (%d row(s) with CVSS, %d without); ranked without the CVSS "
            "term for every row (--allow-mixed)" % (with_cvss, without_cvss),
            file=sys.stderr,
        )

    if args.format == "text":
        text = render_text(ranked, args.top)
    elif args.format == "json":
        text = json.dumps({"ranked": [asdict(f) for f in ranked], "population": population_compare(ranked)}, indent=2)
    else:
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=list(asdict(ranked[0]).keys()))
        w.writeheader()
        for f in ranked:
            w.writerow(asdict(f))
        text = buf.getvalue()

    if not text.endswith("\n"):
        text += "\n"
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
        except OSError as exc:
            print("kev_prioritize: error: cannot write %s: %s" % (args.output, exc), file=sys.stderr)
            return 1
    else:
        sys.stdout.write(text)
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    p.add_argument("--version", action="version", version="%(prog)s " + __version__)
    p.add_argument("findings", help="CSV of scan findings (see data/sample_findings.csv)")
    p.add_argument("--kev", help="KEV catalog JSON file (CISA schema)")
    p.add_argument("--kev-live", action="store_true", help="fetch the live CISA KEV feed instead")
    p.add_argument("--format", choices=["text", "csv", "json"], default="text")
    p.add_argument("-o", "--output", help="write output to this file instead of stdout")
    p.add_argument("--top", type=int, default=25, help="rows to show in text mode")
    p.add_argument(
        "--allow-mixed",
        action="store_true",
        help="rank a list that mixes rows with and without CVSS, scoring every row without CVSS",
    )
    args = p.parse_args(argv)
    try:
        return _run(args)
    except InputError as exc:
        print("kev_prioritize: error: %s" % exc, file=sys.stderr)
        return 2
    except NetworkError as exc:
        print("kev_prioritize: error: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
