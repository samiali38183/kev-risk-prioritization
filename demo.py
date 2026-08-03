"""
End-to-end demonstration pipeline.

1. Downloads the live CISA Known Exploited Vulnerabilities (KEV) Catalog.
2. Generates a synthetic scan-export dataset.
3. Salts a realistic share of KEV CVEs into the synthetic data so matching
   produces meaningful comparisons.
4. Computes KEV vs. non-KEV comparison statistics.
5. Applies the weighted risk-scoring model and prints the ranked queue.

Run with:
    python demo.py
"""
from __future__ import annotations
import json
import random
import sys
import urllib.request

import pandas as pd

from synthetic_data import generate_scan_dataset
from risk_model import score_dataframe

KEV_URLS = [
    # Official CISA feed
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    # Official cisagov GitHub mirror (updated shortly after canonical)
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]

USER_AGENT = "Mozilla/5.0 (compatible; kev-risk-prioritization/1.0)"


def fetch_kev_catalog() -> pd.DataFrame:
    """Download the live CISA KEV Catalog and return a DataFrame.

    Tries the official CISA endpoint first, then falls back to the
    cisagov/kev-data GitHub mirror.
    """
    last_exc = None
    for url in KEV_URLS:
        print(f"[+] Fetching CISA KEV Catalog from {url}")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
            vulns = data.get("vulnerabilities", [])
            df = pd.DataFrame(vulns)
            print(f"[+] Loaded CISA KEV Catalog: {len(df):,} unique KEVs")
            return df
        except Exception as exc:
            print(f"[!] {url} failed: {exc}", file=sys.stderr)
            last_exc = exc
    print(f"[!] All KEV feed sources failed. Last error: {last_exc}", file=sys.stderr)
    sys.exit(1)


def salt_scan_data_with_kevs(scan_df: pd.DataFrame,
                             kev_df: pd.DataFrame,
                             kev_share: float = 0.025,
                             seed: int = 42) -> pd.DataFrame:
    """Replace ~kev_share of scan CVE ids with real KEV CVE ids so matching
    produces a realistic KEV vs. non-KEV mix in the demo."""
    random.seed(seed)
    n_replace = int(len(scan_df) * kev_share)
    kev_ids = kev_df["cveID"].tolist()
    indices = random.sample(range(len(scan_df)), n_replace)
    scan_df = scan_df.copy()
    for i in indices:
        scan_df.at[i, "cve"] = random.choice(kev_ids)
    return scan_df


def match_kevs(scan_df: pd.DataFrame, kev_df: pd.DataFrame) -> pd.DataFrame:
    """Add an is_kev boolean column to the scan dataset."""
    kev_set = set(kev_df["cveID"])
    scan_df = scan_df.copy()
    scan_df["is_kev"] = scan_df["cve"].isin(kev_set)
    # Boost EPSS on KEVs to reflect real-world distribution
    kev_mask = scan_df["is_kev"]
    scan_df.loc[kev_mask, "epss"] = [
        round(random.betavariate(2, 4), 4) for _ in range(kev_mask.sum())
    ]
    return scan_df


def compare_populations(df: pd.DataFrame) -> None:
    """Print KEV vs. non-KEV comparison table."""
    print("\n=== KEV vs. Non-KEV Comparison ===")
    grouped = df.groupby("is_kev").agg(
        findings=("cve", "count"),
        avg_cvss=("cvss", "mean"),
        avg_epss=("epss", "mean"),
        avg_remediation_days=("remediation_days", "mean"),
    )
    grouped.index = grouped.index.map({True: "KEV", False: "Non-KEV"})
    print(grouped.round(2).to_string())


def print_top_priorities(df: pd.DataFrame, n: int = 10) -> None:
    """Print the top-N ranked findings from the risk-scoring model."""
    print(f"\n=== Top {n} Priority CVEs (Weighted Risk Score) ===")
    top = df.head(n)[["risk_score", "cve", "is_kev", "severity",
                       "vendor", "acr", "epss", "cvss"]]
    print(top.to_string(index=False))


def main() -> int:
    random.seed(42)
    kev_df = fetch_kev_catalog()
    scan_df = generate_scan_dataset(50_000, seed=42)
    print(f"[+] Generated synthetic scan dataset: {len(scan_df):,} findings")

    scan_df = salt_scan_data_with_kevs(scan_df, kev_df)
    scan_df = match_kevs(scan_df, kev_df)
    kev_count = int(scan_df["is_kev"].sum())
    print(f"[+] Matched {kev_count:,} KEV findings "
          f"({kev_count / len(scan_df) * 100:.2f}% of volume)")

    compare_populations(scan_df)

    scored = score_dataframe(scan_df)
    print_top_priorities(scored)

    print("\n[+] Done. See docs/methodology.md for the full writeup.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
