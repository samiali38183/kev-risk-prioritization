"""Render docs/img/hero-real-data.png from the pinned snapshot in data/snapshot/.

Optional tool for the README image only; the project itself stays standard-library only.

    pip install matplotlib
    python docs/img/make_hero.py

Every number is computed from data/snapshot/ (no network): the EPSS histogram and AUC from epss_subset.csv,
the top-100 counts by running kev_prioritize.py on mixed_findings.csv. The script asserts that they match the
figures in docs/real_data_analysis.md.
"""

from __future__ import annotations

import os
import sys
import textwrap

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import analyze_snapshot as az  # noqa: E402

import kev_prioritize as kp  # noqa: E402

SNAP = os.path.join(ROOT, "data", "snapshot")
OUT = os.path.join(ROOT, "docs", "img", "hero-real-data.png")
INK, MUTED, LINE = "#111827", "#4b5563", "#d1d5db"
RED, BLUE, GREY, AMBER = "#b91c1c", "#1d4ed8", "#6b7280", "#b45309"
plt.rcParams["font.family"] = ["Segoe UI", "DejaVu Sans"]


def main() -> None:
    subset = az.load_subset()
    kev_e = sorted(r[1] for r in subset if r[3])
    non_e = sorted(r[1] for r in subset if not r[3])
    auc = az.auc(kev_e, non_e)
    lo, hi = az.bootstrap_ci(kev_e, non_e)
    med_kev, med_non = az.quantile(kev_e, 0.5), az.quantile(non_e, 0.5)
    assert (len(kev_e), len(non_e)) == (1779, 5000)
    assert round(auc, 4) == 0.9515 and (round(lo, 4), round(hi, 4)) == (0.9454, 0.9565)

    findings = kp.load_findings(os.path.join(SNAP, "mixed_findings.csv"))
    kev_ids = kp.load_kev(os.path.join(SNAP, "known_exploited_vulnerabilities.json"))
    ranked = kp.score_all(findings, kev_ids)
    n_kev = sum(1 for f in ranked if f.kev)
    orders = {
        "Risk score\n(this tool)": ranked,
        "EPSS alone": sorted(findings, key=lambda f: (-f.epss, f.cve)),
        "Asset criticality\nalone (control)": sorted(findings, key=lambda f: (-f.acr, f.cve)),
    }
    top100 = {k: sum(1 for f in v[:100] if f.kev) for k, v in orders.items()}
    assert list(top100.values()) == [100, 65, 10] and n_kev == 100

    fig = plt.figure(figsize=(9, 6.5), dpi=200, facecolor="white")
    fig.text(0.03, 0.95, "How well does EPSS separate known-exploited CVEs?", fontsize=18.5, weight="bold", color=INK)
    fig.text(
        0.03,
        0.906,
        "Real data: CISA KEV catalog (2026.11.10) and FIRST EPSS scores (2026-11-11). Assets in the list are invented.",
        fontsize=10.5,
        color=MUTED,
    )

    # Left: EPSS distributions
    ax = fig.add_axes([0.075, 0.43, 0.42, 0.36])
    bins = [i / 20 for i in range(21)]
    ax.hist(
        non_e,
        bins=bins,
        weights=[100 / len(non_e)] * len(non_e),
        color=GREY,
        alpha=0.85,
        label="5,000 other CVEs (sample)",
    )
    ax.hist(
        kev_e,
        bins=bins,
        weights=[100 / len(kev_e)] * len(kev_e),
        color=RED,
        alpha=0.75,
        label="1,779 known-exploited CVEs",
    )
    ax.set_xlabel("EPSS score (chance of exploitation)", fontsize=10.5, color=INK)
    ax.set_ylabel("% of the group", fontsize=10.5, color=INK)
    ax.tick_params(labelsize=10, colors=INK)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.legend(frameon=False, fontsize=10, loc="upper center", bbox_to_anchor=(0.5, 1.02))
    fig.text(0.03, 0.84, "EPSS score, known-exploited vs other CVEs", fontsize=11.5, weight="bold", color=MUTED)
    fig.text(
        0.075,
        0.345,
        "Median EPSS: %.3f for KEV, %.3f for the rest.\nAUC %.4f (95%% interval %.4f to %.4f)."
        % (med_kev, med_non, auc, lo, hi),
        fontsize=10.5,
        color=INK,
        va="top",
        linespacing=1.35,
    )

    # Right: how many KEV findings land in the top 100
    ax2 = fig.add_axes([0.60, 0.43, 0.37, 0.36])
    labels = list(top100)
    vals = list(top100.values())
    bars = ax2.barh(range(len(vals)), vals, color=[RED, BLUE, GREY], height=0.62)
    ax2.set_yticks(range(len(vals)))
    ax2.set_yticklabels(labels, fontsize=10.5, color=INK)
    ax2.invert_yaxis()
    ax2.set_xlim(0, 118)
    ax2.set_xticks([0, 50, 100])
    ax2.tick_params(labelsize=10, colors=INK)
    for side in ("top", "right"):
        ax2.spines[side].set_visible(False)
    for b, v in zip(bars, vals):
        ax2.text(v + 2, b.get_y() + b.get_height() / 2, str(v), va="center", fontsize=14, weight="bold", color=INK)
    fig.text(0.60, 0.84, "KEV findings in the top 100 of 2,000", fontsize=11.5, weight="bold", color=MUTED)
    fig.text(
        0.60,
        0.345,
        textwrap.fill(
            "All 100 KEV findings reach this tool's top 100 mostly because KEV carries 0.40 of the "
            "score. That shows what the formula does, not that it reduces risk.",
            52,
        ),
        fontsize=10,
        color=INK,
        va="top",
        linespacing=1.35,
    )

    # Caveat banner
    fig.patches.append(
        plt.Rectangle((0.03, 0.03), 0.94, 0.165, transform=fig.transFigure, fc="#fffbeb", ec=AMBER, lw=1.6)
    )
    fig.text(0.045, 0.18, "The caveat that matters", fontsize=11.5, weight="bold", color=AMBER, va="top")
    fig.text(
        0.045,
        0.147,
        textwrap.fill(
            "The 0.95 AUC is partly circular. EPSS is trained on exploitation evidence that overlaps with what KEV "
            "records, so it largely recovers its own training signal. It describes how two related signals line up. "
            "It is not validation of either, and the score weights are unvalidated.",
            112,
        ),
        fontsize=9.8,
        color=INK,
        va="top",
        linespacing=1.35,
    )
    fig.savefig(OUT, dpi=200, facecolor="white")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
