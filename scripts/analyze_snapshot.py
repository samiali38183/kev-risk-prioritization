#!/usr/bin/env python3
"""Analyze the pinned KEV + EPSS snapshot and write docs/real_data_analysis.md. Standard library only.

    python scripts/analyze_snapshot.py            # (re)write docs/real_data_analysis.md and
                                                  # data/snapshot/mixed_findings.csv
    python scripts/analyze_snapshot.py --check    # fail if either committed file is out of date

Everything is computed from data/snapshot/ only (no network). Output is deterministic: no timestamps,
fixed seeds, sample selection by SHA-256 rather than the random module.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import random
import sys
from typing import Dict, List, Optional, Sequence, Tuple

Subset = Tuple[str, float, float, bool]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import kev_prioritize as kp  # noqa: E402

SNAP = os.path.join(ROOT, "data", "snapshot")
DOC_PATH = os.path.join(ROOT, "docs", "real_data_analysis.md")
MIXED_PATH = os.path.join(SNAP, "mixed_findings.csv")

MIX_KEV = 100  # KEV rows in the mixed list
MIX_NON_KEV = 1900  # non-KEV rows in the mixed list (KEV share 5%, chosen, not measured)
MIX_SEED = "mixed-list-v1"
BOOT_SEED = 20261111
BOOT_ITERS = 500
THRESHOLDS = (0.1, 0.5, 0.9)
# CVSS is not in the snapshot, so the tool runs with its CVSS term dropped (see kev_prioritize.risk_score).


def load_subset() -> List[Tuple[str, float, float, bool]]:
    rows = []
    with open(os.path.join(SNAP, "epss_subset.csv"), newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            rows.append((r["cve"], float(r["epss"]), float(r["percentile"]), r["in_kev"] == "1"))
    return rows


def auc(pos: Sequence[float], neg: Sequence[float]) -> float:
    """P(score_pos > score_neg) + 0.5 P(tie), via average ranks (Mann-Whitney U)."""
    scored = [(v, 1) for v in pos] + [(v, 0) for v in neg]
    scored.sort(key=lambda t: t[0])
    rank_sum_pos = 0.0
    i = 0
    n = len(scored)
    while i < n:
        j = i
        while j + 1 < n and scored[j + 1][0] == scored[i][0]:
            j += 1
        avg_rank = (i + j) / 2.0 + 1.0
        rank_sum_pos += avg_rank * sum(lab for _, lab in scored[i : j + 1])
        i = j + 1
    n_pos, n_neg = len(pos), len(neg)
    return (rank_sum_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def bootstrap_ci(pos: Sequence[float], neg: Sequence[float]) -> Tuple[float, float]:
    rng = random.Random(BOOT_SEED)
    vals = []
    for _ in range(BOOT_ITERS):
        bp = [pos[int(rng.random() * len(pos))] for _ in pos]
        bn = [neg[int(rng.random() * len(neg))] for _ in neg]
        vals.append(auc(bp, bn))
    vals.sort()
    return vals[int(0.025 * BOOT_ITERS)], vals[int(0.975 * BOOT_ITERS) - 1]


def quantile(sorted_vals: Sequence[float], q: float) -> float:
    """Linear interpolation between closest ranks."""
    pos = q * (len(sorted_vals) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (pos - lo)


def hkey(tag: str, cve: str) -> str:
    return hashlib.sha256(("%s:%s:%s" % (MIX_SEED, tag, cve)).encode("utf-8")).hexdigest()


def build_mixed(subset: List[Subset]) -> List[Dict[str, str]]:
    """KEV + non-KEV CVEs from the snapshot with INVENTED asset, ACR and days_open."""
    kev = sorted((r for r in subset if r[3]), key=lambda r: hkey("pick", r[0]))[:MIX_KEV]
    non = sorted((r for r in subset if not r[3]), key=lambda r: hkey("pick", r[0]))[:MIX_NON_KEV]
    rows = []
    for cve, epss, _pct, _k in sorted(kev + non, key=lambda r: hkey("order", r[0])):
        acr = 1 + int(hkey("acr", cve)[:8], 16) % 8
        days = 1 + int(hkey("days", cve)[:8], 16) % 365
        rows.append(
            {
                "cve": cve,
                "asset": "asset-%s" % hkey("asset", cve)[:6],
                "acr": str(acr),
                "epss": "%.5f" % epss,
                "days_open": str(days),
            }
        )
    return rows


def mixed_csv(rows: List[Dict[str, str]]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["cve", "asset", "acr", "epss", "days_open"], lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


def pct(x: float, nd: int = 1) -> str:
    return "%.*f%%" % (nd, 100.0 * x)


def render(meta: dict, subset: List[Subset]) -> Tuple[str, str]:
    kev_e = sorted(r[1] for r in subset if r[3])
    non_e = sorted(r[1] for r in subset if not r[3])
    kev_p = sorted(r[2] for r in subset if r[3])
    non_p = sorted(r[2] for r in subset if not r[3])
    n_kev, n_non = len(kev_e), len(non_e)
    pop = meta["population_stats"]
    non_pop = meta["subset"]["non_kev_population"]
    epss_total = meta["epss"]["rows_total"]

    a = auc(kev_e, non_e)
    lo, hi = bootstrap_ci(kev_e, non_e)

    out: List[str] = []
    w = out.append
    w("# Real-data analysis (KEV vs EPSS snapshot)")
    w("")
    w(
        "Generated by `python scripts/analyze_snapshot.py`; do not edit by hand. CI fails if this file is stale "
        "(`python scripts/analyze_snapshot.py --check`)."
    )
    w("")
    w("## What is real and what is invented")
    w("")
    w("| Column | Status |")
    w("|---|---|")
    w(
        "| KEV membership | **Real.** CISA KEV catalog %s (released %s, %d entries). |"
        % (meta["kev"]["catalogVersion"], meta["kev"]["dateReleased"], meta["kev"]["count"])
    )
    w(
        "| EPSS score and percentile | **Real.** FIRST EPSS file scored %s, model %s. |"
        % (meta["epss"]["score_date"], meta["epss"]["model_version"])
    )
    w(
        "| CVSS | **Not used.** Not in either source; fetching it for thousands of CVEs from the NVD API "
        "(5 requests per 30 s without a key) was not done. The tool runs with its CVSS term dropped. |"
    )
    w("| Asset, ACR, days open (mixed list only) | **Invented**, hash-derived, independent of everything else. |")
    w("| KEV share of the mixed list (5%) | **Chosen**, not measured. |")
    w("")
    w(
        "Sample design: all %d KEV CVEs plus %d non-KEV CVEs drawn with a fixed seed from the %d non-KEV CVEs "
        "in the EPSS file (%d CVEs scored in total; KEV is %s of them). Population-level counts for non-KEV CVEs "
        "come from the "
        "full file at fetch time and are stored in `data/snapshot/SNAPSHOT.json`."
        % (n_kev, n_non, non_pop, epss_total, pct(n_kev / float(epss_total), 2))
    )
    w("")
    w("## Caveats that apply to every number below")
    w("")
    w(
        "- **Circularity.** EPSS is trained on observed exploitation evidence, and its published list of data "
        "partners includes a known-exploited-vulnerabilities feed (VulnCheck KEV), a separate catalog whose overlap "
        "with the CISA catalog was not measured here. EPSS separating KEV from non-KEV is therefore partly the model "
        "recovering its own training signal, "
        "not an independent validation. These numbers describe the relationship between two related signals; they do "
        "not show that either one improves remediation outcomes."
    )
    w(
        "- **KEV is an incomplete label.** A non-KEV CVE is not known to be unexploited; it is only absent from the "
        "catalog. Exploited-but-unlisted CVEs sit in the non-KEV group, which depresses every precision figure."
    )
    w(
        "- **A single snapshot, no time dimension.** Scores were read after most KEV entries were added, so EPSS may "
        "already reflect the listing. This is not a forecast test."
    )
    w("")
    w("## 1. EPSS distribution: KEV vs sampled non-KEV")
    w("")
    w("| | KEV (n=%d) | Non-KEV sample (n=%d) |" % (n_kev, n_non))
    w("|---|---|---|")
    for label, q in (
        ("EPSS p10", 0.10),
        ("EPSS p25", 0.25),
        ("EPSS median", 0.50),
        ("EPSS p75", 0.75),
        ("EPSS p90", 0.90),
    ):
        w("| %s | %.5f | %.5f |" % (label, quantile(kev_e, q), quantile(non_e, q)))
    for label, q in (("EPSS percentile p10", 0.10), ("EPSS percentile median", 0.50), ("EPSS percentile p90", 0.90)):
        w("| %s | %.3f | %.3f |" % (label, quantile(kev_p, q), quantile(non_p, q)))
    w("")
    w("EPSS percentile is the share of all scored CVEs with a lower score (the `percentile` column of the EPSS file).")
    w("")
    w(
        "**AUC of EPSS for separating KEV from sampled non-KEV: %.4f** (95%% bootstrap interval %.4f to %.4f, "
        "%d resamples, seed %d). AUC is the probability that a random KEV CVE has a higher EPSS than a random sampled "
        "non-KEV CVE; it does not depend on how many non-KEV CVEs were sampled. See the circularity caveat."
        % (a, lo, hi, BOOT_ITERS, BOOT_SEED)
    )
    w("")
    w("## 2. Thresholds: recall and precision")
    w("")
    w(
        "Recall is exact (every KEV CVE is in the snapshot). The non-KEV count is the exact count over the whole EPSS "
        "file, so precision below is the population value (KEV prevalence %s), not the sample's inflated one. "
        "Sample columns show the same rule applied to the %d sampled non-KEV CVEs."
        % (pct(n_kev / float(epss_total), 2), n_non)
    )
    w("")
    w(
        "| EPSS >= | KEV flagged | Recall | Non-KEV flagged (all %d) | Precision (population) | "
        "Non-KEV flagged in sample (n=%d) |" % (non_pop, n_non)
    )
    w("|---|---|---|---|---|---|")
    for t in THRESHOLDS:
        k = pop["%g" % t]["kev_ge"]
        nk = pop["%g" % t]["non_kev_ge"]
        in_sample = sum(1 for e in non_e if e >= t)
        w(
            "| %g | %d | %s | %d (%s) | %s | %d (%s) |"
            % (
                t,
                k,
                pct(k / float(n_kev)),
                nk,
                pct(nk / float(non_pop), 2),
                pct(k / float(k + nk)),
                in_sample,
                pct(in_sample / float(n_non), 2),
            )
        )
    w("")
    w(
        "Read this as: a threshold of 0.1 reaches most KEV CVEs but flags many times more non-KEV CVEs than KEV ones "
        "at population prevalence, so most flagged CVEs are not in the catalog. Whether those are false alarms or "
        "unlisted exploitation cannot be told from this data."
    )
    w("")

    # Mixed list through the tool
    mixed_rows = build_mixed(subset)
    mixed_text = mixed_csv(mixed_rows)
    findings = kp.load_findings_from_rows(mixed_rows)
    kev_ids = kp.load_kev(os.path.join(SNAP, "known_exploited_vulnerabilities.json"))
    ranked = kp.score_all(findings, kev_ids)
    n = len(ranked)
    n_k = sum(1 for f in ranked if f.kev)

    def hits(order: List[kp.Finding], k: int) -> int:
        return sum(1 for f in order[:k] if f.kev)

    by_epss = sorted(findings, key=lambda f: (-f.epss, f.cve))
    by_acr = sorted(findings, key=lambda f: (-f.acr, f.cve))
    w("## 3. The tool on a mixed list (KEV + sampled non-KEV, invented assets)")
    w("")
    w(
        "`data/snapshot/mixed_findings.csv`: %d findings = %d KEV + %d non-KEV CVEs from the snapshot, with invented "
        "asset, ACR 1-8 and days open, no CVSS. Run through `kev_prioritize.py` with its default weights (CVSS term "
        "dropped and the rest renormalized)." % (n, n_k, n - n_k)
    )
    w("")
    w("| Ranking | KEV in top 50 | KEV in top 100 | KEV in top 200 | Rank of last KEV |")
    w("|---|---|---|---|---|")
    for label, order in (("Risk score (tool)", ranked), ("EPSS only", by_epss), ("ACR only (control)", by_acr)):
        last = max(i for i, f in enumerate(order, 1) if f.kev)
        w("| %s | %d | %d | %d | %d |" % (label, hits(order, 50), hits(order, 100), hits(order, 200), last))
    w("")
    kev_below_100 = [i for i, f in enumerate(ranked, 1) if f.kev and i > 100]
    nonkev_in_100 = sum(1 for f in ranked[:100] if not f.kev)
    w(
        "With %d KEV rows in the list, a perfect top-100 would contain %d. The tool's top 100 holds %d KEV and %d "
        "non-KEV findings; %d KEV findings rank below position 100."
        % (n_k, n_k, hits(ranked, 100), nonkev_in_100, len(kev_below_100))
    )
    w("")
    w(
        "This result is largely **by construction**: the KEV term carries 0.40 of the weight, so KEV matches "
        "sort ahead of most non-KEV findings unless ACR and EPSS differ widely (a non-KEV finding on ACR 8 with EPSS "
        "near 1 can still outscore a KEV finding on ACR 1 with EPSS near 0). It shows the formula behaves as "
        "described on realistic EPSS values; it is not evidence that the ranking reduces risk."
    )
    w("")
    w("## Reproduce")
    w("")
    w("```bash")
    w("python scripts/analyze_snapshot.py          # rewrites this file and data/snapshot/mixed_findings.csv")
    w("python scripts/analyze_snapshot.py --check  # exits 1 if either differs from the committed copy")
    w("```")
    w("")
    return "\n".join(out), mixed_text


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    p.add_argument("--check", action="store_true", help="compare with committed files, write nothing")
    args = p.parse_args(argv)
    with open(os.path.join(SNAP, "SNAPSHOT.json"), encoding="utf-8") as fh:
        meta = json.load(fh)
    doc, mixed = render(meta, load_subset())
    if args.check:
        bad = []
        for path, text in ((DOC_PATH, doc), (MIXED_PATH, mixed)):
            with open(path, "rb") as fh:
                if fh.read() != text.encode("utf-8"):
                    bad.append(os.path.relpath(path, ROOT))
        if bad:
            print("STALE: " + ", ".join(bad), file=sys.stderr)
            return 1
        print("analysis files are up to date")
        return 0
    for path, text in ((DOC_PATH, doc), (MIXED_PATH, mixed)):
        with open(path, "wb") as fh:
            fh.write(text.encode("utf-8"))
    print("wrote %s and %s" % (os.path.relpath(DOC_PATH, ROOT), os.path.relpath(MIXED_PATH, ROOT)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
