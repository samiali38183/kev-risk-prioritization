#!/usr/bin/env python3
"""Risk-based vulnerability prioritization: KEV + ACR + EPSS + CVSS.

Reference implementation of the weighted model described in docs/methodology.md. This is a simple
weighted score of the author's own design that puts known-exploited vulnerabilities first. It is NOT
an implementation of CISA BOD 26-04 (see docs/methodology.md section 8).
Standard library only. Runs on the synthetic data in data/ or on your own CSV.

    python kev_prioritize.py data/sample_findings.csv --kev data/sample_kev.json
    python kev_prioritize.py findings.csv --kev-live --format csv -o ranked.csv

Input CSV columns (header required):
    cve, asset, acr, epss, days_open  [optional: cvss, system_group, vendor, internet_exposed]

If the cvss column is missing or a cell is blank, the CVSS term is left out of that finding's score and
the remaining weights are renormalized to 0-100.

Scoring (0-100):
    risk = 100 * (0.40*kev + 0.25*(acr/8) + 0.20*epss + 0.20*(cvss/10))
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import urllib.request
from dataclasses import asdict, dataclass
from typing import Optional

__version__ = "0.2.0"

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

DEFAULT_WEIGHTS = {"kev": 0.40, "acr": 0.25, "epss": 0.20, "cvss": 0.20}


@dataclass
class Finding:
    cve: str
    asset: str
    acr: float            # asset criticality rating, 1-8
    cvss: Optional[float]  # 0-10, None when the input has no CVSS
    epss: float           # 0-1
    days_open: int
    system_group: str = ""
    vendor: str = ""
    internet_exposed: bool = False
    kev: bool = False
    risk_score: float = 0.0


def risk_score(kev: bool, acr: float, epss: float, cvss: Optional[float],
               weights: dict[str, float] = DEFAULT_WEIGHTS) -> float:
    """Weighted composite from docs/methodology.md section 6. Inputs are clamped to range."""
    acr = min(max(acr, 0.0), 8.0)
    epss = min(max(epss, 0.0), 1.0)
    score = (weights["kev"] * (1.0 if kev else 0.0)
             + weights["acr"] * (acr / 8.0)
             + weights["epss"] * epss)
    total = weights["kev"] + weights["acr"] + weights["epss"]
    if cvss is not None:
        cvss = min(max(cvss, 0.0), 10.0)
        score += weights["cvss"] * (cvss / 10.0)
        total += weights["cvss"]
    # Divide by the weight total so the result is a true 0-100 regardless of how the weights are
    # tuned (the documented defaults sum to 1.05). When CVSS is absent its weight is dropped from
    # the total, so a finding without CVSS is still scored on 0-100.
    return round(100.0 * score / total, 1)


def load_findings(path: str) -> list[Finding]:
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    return load_findings_from_rows(rows)


def load_findings_from_rows(rows: list[dict]) -> list[Finding]:
    out = []
    for r in rows:
        out.append(Finding(
            cve=r["cve"].strip().upper(),
            asset=r["asset"],
            acr=float(r["acr"]),
            cvss=float(r["cvss"]) if (r.get("cvss") or "").strip() else None,
            epss=float(r["epss"]),
            days_open=int(r["days_open"]),
            system_group=r.get("system_group", ""),
            vendor=r.get("vendor", ""),
            internet_exposed=r.get("internet_exposed", "").strip().lower() in {"1", "true", "yes"},
        ))
    return out


def load_kev(path: str | None = None, live: bool = False) -> set[str]:
    """Return the set of CVE IDs in the KEV catalog (CISA JSON schema: {"vulnerabilities":[{"cveID":...}]})."""
    if live:
        with urllib.request.urlopen(KEV_FEED_URL, timeout=30) as resp:  # noqa: S310 - fixed https URL
            data = json.load(resp)
    else:
        if not path:
            raise SystemExit("need --kev <file.json> or --kev-live")
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    return {v["cveID"].upper() for v in data["vulnerabilities"]}


def score_all(findings: list[Finding], kev: set[str],
              weights: dict[str, float] = DEFAULT_WEIGHTS) -> list[Finding]:
    for f in findings:
        f.cve = f.cve.strip().upper()
        f.kev = f.cve in kev
        f.risk_score = risk_score(f.kev, f.acr, f.epss, f.cvss, weights)
    return sorted(findings, key=lambda f: (-f.risk_score, -f.epss, -(f.cvss if f.cvss is not None else 0.0)))


def population_compare(findings: list[Finding]) -> dict[str, dict[str, float]]:
    """Section 4 of the methodology: KEV vs non-KEV on volume, CVSS, EPSS, days open."""
    out = {}
    for label, group in (("kev", [f for f in findings if f.kev]),
                         ("non_kev", [f for f in findings if not f.kev])):
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
    return sorted(counts.items(), key=lambda kv: -kv[1])


def render_text(ranked: list[Finding], top: int) -> str:
    lines = [f"{'#':>3} {'risk':>5}  {'KEV':<3} {'CVE':<16} {'CVSS':>4} {'EPSS':>5} {'ACR':>3} {'days':>4}  asset"]
    for i, f in enumerate(ranked[:top], 1):
        cvss = f"{f.cvss:>4.1f}" if f.cvss is not None else " n/a"
        lines.append(f"{i:>3} {f.risk_score:>5.1f}  {'yes' if f.kev else '-':<3} {f.cve:<16} "
                     f"{cvss} {f.epss:>5.3f} {f.acr:>3.0f} {f.days_open:>4}  {f.asset}")
    comp = population_compare(ranked)
    lines.append("")
    lines.append("KEV vs non-KEV population")
    for label in ("kev", "non_kev"):
        c = comp[label]
        if c["count"]:
            avg_cvss = c["avg_cvss"] if c["avg_cvss"] is not None else "n/a"
            lines.append(f"  {label:<8} n={c['count']:<3} avg CVSS {avg_cvss:<5} "
                         f"avg EPSS {c['avg_epss']:<6} avg days open {c['avg_days_open']}")
        else:
            lines.append(f"  {label:<8} n=0")
    conc = concentration(ranked, "system_group")
    if conc:
        lines.append("")
        lines.append("KEV concentration by system group: " + ", ".join(f"{k}={n}" for k, n in conc))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    p.add_argument("--version", action="version", version="%(prog)s " + __version__)
    p.add_argument("findings", help="CSV of scan findings (see data/sample_findings.csv)")
    p.add_argument("--kev", help="KEV catalog JSON file (CISA schema)")
    p.add_argument("--kev-live", action="store_true", help="fetch the live CISA KEV feed instead")
    p.add_argument("--format", choices=["text", "csv", "json"], default="text")
    p.add_argument("-o", "--output", help="write output to this file instead of stdout")
    p.add_argument("--top", type=int, default=25, help="rows to show in text mode")
    args = p.parse_args(argv)

    kev = load_kev(args.kev, live=args.kev_live)
    ranked = score_all(load_findings(args.findings), kev)

    if args.format == "text":
        text = render_text(ranked, args.top)
    elif args.format == "json":
        text = json.dumps({"ranked": [asdict(f) for f in ranked],
                           "population": population_compare(ranked)}, indent=2)
    else:
        import io
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=list(asdict(ranked[0]).keys()) if ranked else ["cve"])
        w.writeheader()
        for f in ranked:
            w.writerow(asdict(f))
        text = buf.getvalue()

    if not text.endswith("\n"):
        text += "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
