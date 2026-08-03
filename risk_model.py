"""
Weighted risk-scoring model for vulnerability prioritization.

Implements the composite scoring approach aligned with CISA BOD 26-04:
exploitation evidence carries the heaviest weight, with asset criticality,
exploitation probability, and severity as supporting factors.

Weights:
    KEV status           0.40   (in CISA KEV Catalog: confirmed exploitation)
    Asset criticality    0.25   (ACR / HVA designation)
    EPSS score           0.20   (FIRST: 30-day exploitation probability)
    CVSS score           0.20   (CVSS v3.x: severity if exploited)

All inputs are normalized to a 0-1 scale, and the final score is expressed
as 0-100 for readability.
"""
from __future__ import annotations
import pandas as pd

WEIGHTS = {
    "kev": 0.40,
    "acr": 0.25,
    "epss": 0.20,
    "cvss": 0.20,
}


def compute_risk_score(row: pd.Series) -> float:
    """Return a 0-100 weighted risk score for a single finding."""
    kev = 1.0 if row["is_kev"] else 0.0
    acr = min(max(row.get("acr", 5), 1), 8) / 8.0  # ACR is typically 1-8
    epss = min(max(row.get("epss", 0.0), 0.0), 1.0)
    cvss = min(max(row.get("cvss", 0.0), 0.0), 10.0) / 10.0

    score = (
        WEIGHTS["kev"] * kev
        + WEIGHTS["acr"] * acr
        + WEIGHTS["epss"] * epss
        + WEIGHTS["cvss"] * cvss
    )
    return round(score * 100, 2)


def score_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Add a 'risk_score' column and return sorted DataFrame (highest first)."""
    df = df.copy()
    df["risk_score"] = df.apply(compute_risk_score, axis=1)
    return df.sort_values("risk_score", ascending=False).reset_index(drop=True)


if __name__ == "__main__":
    # Quick self-test with a handful of made-up findings
    sample = pd.DataFrame([
        {"cve": "CVE-2023-44487", "is_kev": True, "acr": 8, "epss": 0.94, "cvss": 7.5},
        {"cve": "CVE-2024-99999", "is_kev": False, "acr": 8, "epss": 0.02, "cvss": 9.8},
        {"cve": "CVE-2024-00001", "is_kev": False, "acr": 4, "epss": 0.001, "cvss": 6.5},
    ])
    print(score_dataframe(sample).to_string(index=False))
