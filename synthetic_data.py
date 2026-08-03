"""
Reproducible synthetic vulnerability-scan dataset generator.

Simulates the structure of a Nessus/Tenable scan export at enterprise scale.
Everything here is invented — no real scan data, no real system names, no
real asset counts. The generator is deterministic (seed=42 by default) so
runs are reproducible.
"""
from __future__ import annotations
import random
import string
import pandas as pd

# Generic placeholder repository / system group names
REPOSITORIES = [
    "WORKSTATIONS-A", "WORKSTATIONS-B", "WORKSTATIONS-C",
    "SERVERS-PROD",   "SERVERS-DEV",   "SERVERS-NOC",
    "CLOUD-PROD",     "CLOUD-DEV",     "APPLIANCE-NET",
]

# Common vendors/products in the wild (from public CISA advisories)
VENDORS = ["Microsoft", "Google", "Oracle", "Cisco", "Adobe", "Apache", "Linux"]

SEVERITIES = ["Critical", "High", "Medium", "Low"]
SEVERITY_WEIGHTS = [0.30, 0.50, 0.17, 0.03]  # roughly enterprise-typical


def _random_cve(year_range=(2016, 2025)) -> str:
    year = random.randint(*year_range)
    num = random.randint(1, 99999)
    return f"CVE-{year}-{num:05d}"


def generate_scan_dataset(n: int = 50_000, seed: int = 42) -> pd.DataFrame:
    """Generate a synthetic scan-export DataFrame of n rows."""
    random.seed(seed)

    rows = []
    for _ in range(n):
        severity = random.choices(SEVERITIES, weights=SEVERITY_WEIGHTS, k=1)[0]
        # CVSS aligned to severity band, with noise
        cvss_ranges = {"Critical": (9.0, 10.0), "High": (7.0, 8.9),
                       "Medium": (4.0, 6.9), "Low": (0.1, 3.9)}
        cvss = round(random.uniform(*cvss_ranges[severity]), 1)

        # EPSS: heavily skewed low, occasional high value
        epss = round(random.betavariate(0.5, 20), 4)

        # Asset criticality 1-8, biased toward middle
        acr = random.choices(range(1, 9), weights=[1, 2, 4, 6, 6, 4, 3, 2], k=1)[0]

        # Remediation days — most fast, long tail
        remediation_days = int(random.expovariate(1 / 7))

        rows.append({
            "cve": _random_cve(),
            "repository": random.choice(REPOSITORIES),
            "vendor": random.choice(VENDORS),
            "severity": severity,
            "cvss": cvss,
            "epss": epss,
            "acr": acr,
            "remediation_days": remediation_days,
        })

    return pd.DataFrame(rows)


if __name__ == "__main__":
    df = generate_scan_dataset(1000)
    print(df.head())
    print(f"\nTotal rows: {len(df)}")
    print(f"Severity distribution:\n{df['severity'].value_counts()}")
