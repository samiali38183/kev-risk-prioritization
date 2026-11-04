# kev-risk-prioritization

[![ci](https://github.com/samiali38183/kev-risk-prioritization/actions/workflows/ci.yml/badge.svg)](https://github.com/samiali38183/kev-risk-prioritization/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.9%2B%20%C2%B7%20stdlib%20only-blue)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

**Risk-based vulnerability prioritization with CISA KEV, EPSS, CVSS and asset criticality, aligned with CISA BOD 26-04.**

Two things live here:

1. A **written case study** of the methodology I applied during my DHS HS-POWER internship on the
   U.S. Customs and Border Protection Vulnerability Assessment Team (Summer 2026), matching enterprise
   Nessus/Tenable scan results against the KEV Catalog and benchmarking remediation against BOD 26-04.
   Every number, system name, dashboard and report from that work is non-public and is **not** in this repo.
2. A small **reference implementation** (`kev_prioritize.py`, standard library only) of the same weighted
   model, runnable on the synthetic findings in `data/` or on your own CSV, with the option to match against
   the live CISA KEV feed.

```
$ python kev_prioritize.py data/sample_findings.csv --kev data/sample_kev.json --top 14

  #  risk  KEV CVE              CVSS  EPSS ACR days  asset
  1  99.4  yes CVE-2021-44228   10.0 0.970   8   42  web-portal-01
  2  99.0  yes CVE-2024-3400    10.0 0.950   8    9  fw-edge-01
  3  98.1  yes CVE-2023-4966     9.4 0.960   8   18  vpn-gw-02
  ...
 12  85.0  yes CVE-2021-34527    8.8 0.960   4  160  print-srv-03
 13  38.5  -   CVE-2023-99996    8.8 0.050   7   22  backup-srv-02
 14  33.7  -   CVE-2023-99994    7.5 0.080   6   33  reporting-db-01

KEV vs non-KEV population
  kev      n=12  avg CVSS 9.53  avg EPSS 0.935  avg days open 94.2
  non_kev  n=8   avg CVSS 8.34  avg EPSS 0.029  avg days open 101.5

KEV concentration by system group: Remote Access=4, File Services=2, Public Web=1, ...
```

Look at row 13: a CVSS 8.8 on an important asset still ranks below every KEV match, including a CVSS 8.1
on an old file server. If you sort by CVSS alone you get that order backwards.

## The problem

Scanners find way more vulnerabilities than a team can fix, so what you fix first matters a lot. CVSS
tells you how bad a vulnerability could be, not whether anyone is actually exploiting it. A 9.8 nobody
has weaponized is less urgent than a 7.5 that's being mass-exploited right now. BOD 26-04 tells federal
agencies to prioritize the same way: known exploitation (KEV) and likelihood of exploitation (EPSS) first,
then severity.

So the question is: if you can only patch 10% of open findings this sprint, which ones?

## Quick start

Python 3.9+, no dependencies.

```bash
git clone https://github.com/samiali38183/kev-risk-prioritization
cd kev-risk-prioritization

# rank the synthetic sample against an offline KEV fixture
python kev_prioritize.py data/sample_findings.csv --kev data/sample_kev.json

# same, against the live CISA KEV catalog (one HTTPS request)
python kev_prioritize.py data/sample_findings.csv --kev-live

# machine-readable output for a dashboard or ticketing import
python kev_prioritize.py data/sample_findings.csv --kev data/sample_kev.json --format csv -o ranked.csv
python kev_prioritize.py data/sample_findings.csv --kev data/sample_kev.json --format json

# tests
python -m pytest -q        # or: python -m unittest discover tests
```

Input CSV columns: `cve, asset, acr (1-8), cvss (0-10), epss (0-1), days_open`, optional
`system_group, vendor, internet_exposed`. Export those from Tenable/Nessus plus your asset inventory and
the script works unchanged.

## What it does

1. Match each finding's CVE against the KEV Catalog (offline JSON fixture or the live feed, same schema).
2. Score each finding with the weighted composite below and sort descending.
3. Compare KEV vs non-KEV findings on count, average CVSS, average EPSS and average days open. On real
   data, CVSS is pretty similar between the two groups but EPSS is very different.
4. Count KEV findings by system group (and vendor, in the JSON output) to show where they cluster.

```
findings.csv ──┐
               ├─▶ match CVE ∈ KEV ─▶ risk_score ─▶ sort ─▶ text | csv | json
KEV catalog ───┘        │
 (file or live)         └─▶ KEV vs non-KEV stats, concentration by group
```

## Design

The composite, from [`docs/methodology.md`](docs/methodology.md):

```
risk = 100 * ( 0.40*kev + 0.25*(acr/8) + 0.20*epss + 0.20*(cvss/10) ) / Σweights
```

- KEV status (0.40): known exploitation is the strongest signal, so a KEV match on its own puts a
  finding above any non-KEV finding on the same asset. That matches the BOD 26-04 ordering.
- Asset criticality (0.25): HVA status and internet exposure, on a 1-8 scale. The same CVE matters
  more on a critical, exposed system.
- EPSS (0.20) and CVSS (0.20): likelihood of exploitation in the next 30 days, and severity if exploited.
- Weights are a starting point. `DEFAULT_WEIGHTS` is a dict; pass a different one to `score_all()` to raise
  internet exposure for public-facing fleets or ACR for regulated environments. The score is divided by the
  weight total so it stays on a 0–100 scale however the weights are tuned (the defaults sum to 1.05).
- Inputs are clamped to their documented ranges; CVE IDs are matched case-insensitively; ties break on
  EPSS, then CVSS.
- Standard library only (`csv`, `json`, `argparse`, `statistics`, `urllib`) so it runs on a locked-down
  analyst workstation with no package install.

At the internship, this was a Power BI dashboard over real scan data plus a briefing and reports. This
script is just the scoring logic, rebuilt on synthetic data so it can be public.

## Limitations

- Synthetic data. `data/sample_findings.csv` uses real KEV CVE IDs but invented assets, ACR, EPSS,
  CVSS and age values chosen to illustrate the ordering. It is not a dataset and proves nothing about
  any real environment. No figure here comes from internship data.
- It's not a scanner or an enrichment service. It consumes CVSS/EPSS values you supply; it does not
  query NVD or the FIRST EPSS API. The live mode fetches only the KEV catalog.
- It's a simple weighted sum. That's easy to explain and tune, but it can't express a rule like
  "KEV and internet-exposed always goes first." Adding rules on top would be the next step.
- No per-finding due dates. BOD 26-04 timelines are reported as mean days open per population, not
  evaluated per finding against due dates.
- This is a case study, not policy. BOD 26-04 and the KEV Catalog are the authoritative sources.

## Repository layout

```
kev_prioritize.py          scoring, matching, population compare, CLI (stdlib only)
data/sample_findings.csv   20 synthetic findings (12 KEV, 8 non-KEV)
data/sample_kev.json       offline KEV fixture in the CISA feed schema
tests/test_scoring.py      9 unit tests: bounds, normalization, KEV-over-severity, pipeline, CLI
docs/methodology.md        full writeup of the methodology and its BOD 26-04 alignment
```

## References

- [CISA BOD 26-04: Prioritizing Security Updates Based on Risk](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- [FIRST Exploit Prediction Scoring System (EPSS)](https://www.first.org/epss/)
- [National Vulnerability Database](https://nvd.nist.gov/) · [CVSS v3.1 Specification](https://www.first.org/cvss/specification-document)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) · [FedRAMP](https://www.fedramp.gov/)

## License

MIT. See [LICENSE](LICENSE).
