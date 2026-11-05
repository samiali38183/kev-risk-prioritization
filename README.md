# kev-risk-prioritization

[![ci](https://github.com/samiali38183/kev-risk-prioritization/actions/workflows/ci.yml/badge.svg)](https://github.com/samiali38183/kev-risk-prioritization/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.9%2B%20%C2%B7%20stdlib%20only-blue)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

**Rank vulnerability scan findings by known exploitation (CISA KEV), exploit likelihood (EPSS), severity (CVSS) and asset criticality, in the order CISA BOD 26-04 asks federal agencies to work.**

Scanners return more findings than a team can patch. Sorting by CVSS puts severity first and ignores whether anyone is exploiting the bug. This tool puts KEV matches first. On the 20-finding synthetic sample in this repo, a CVSS-only sort puts 9 KEV findings in its top 12; the risk score puts all 12 there. The two KEV findings with the lowest CVSS (8.8 and 8.1) land at positions 15 and 17 of 20 by CVSS and at 12 and 11 by risk.

> **Data note.** Everything runnable here uses **synthetic data** by design: real KEV CVE IDs, invented assets, ACR, EPSS, CVSS and ages. No internal, DHS or CBP data is in this repository. See [Limitations](#limitations).

## The problem

CVSS describes how bad a vulnerability could be, not whether it is being used. A 9.8 nobody has weaponized is less urgent than a 7.5 under mass exploitation. BOD 26-04 directs agencies to prioritize known exploitation (KEV) and likelihood of exploitation (EPSS) ahead of raw severity.

The question this tool answers: if you can fix only a slice of open findings this sprint, which ones?

## Methodology and architecture

Pipeline (one pass, in memory, standard library only):

```mermaid
flowchart LR
    F["Scan export (CSV)<br/>cve, asset, acr, cvss, epss, days_open"] --> M["Match each CVE<br/>against the KEV set"]
    K["KEV catalog<br/>offline JSON fixture or live CISA feed"] --> M
    M --> S["Weighted risk score<br/>0 to 100"]
    S --> R["Sort by score,<br/>then EPSS, then CVSS"]
    R --> O["Ranked queue<br/>text, csv or json"]
    M --> P["KEV vs non-KEV<br/>count, CVSS, EPSS, days open"]
    M --> C["KEV concentration<br/>by system group"]
```

The score, defined in [`docs/methodology.md`](docs/methodology.md) section 6:

```
risk = 100 * ( 0.40*kev + 0.25*(acr/8) + 0.20*epss + 0.20*(cvss/10) ) / 1.05
```

| Input | Weight | Why |
|---|---|---|
| KEV match (0/1) | 0.40 | Confirmed exploitation is the strongest signal; matches the BOD 26-04 ordering |
| Asset criticality, ACR 1-8 | 0.25 | Same CVE matters more on a critical or internet-exposed system |
| EPSS (0-1) | 0.20 | Probability of exploitation in the next 30 days |
| CVSS (0-10) | 0.20 | Severity if exploited |

The KEV weight (0.40) equals the EPSS and CVSS weights combined, so on the same asset a KEV finding never scores below a non-KEV finding; the two tie only at the extreme of EPSS 1.0 and CVSS 10 against 0 and 0.

## Engineering decisions

- **Standard library only** (`csv`, `json`, `argparse`, `statistics`, `urllib`). It runs on a locked-down analyst workstation with no package install.
- **Score normalized by the weight total.** The defaults sum to 1.05, so the raw composite would top out at 105. Dividing by `sum(weights)` keeps the scale at 0-100 for any re-tuned weight set; ordering is unchanged. A test asserts 100.0 at the maximum for a custom weight set.
- **Weights are data.** `DEFAULT_WEIGHTS` is a dict; pass another to `score_all()` to raise ACR for regulated environments or exposure for public-facing fleets.
- **Defensive inputs.** Values are clamped to documented ranges, CVE IDs match case-insensitively, and ties break deterministically on EPSS, then CVSS.
- **Offline-first.** KEV can come from a local JSON file in the CISA feed schema, so the demo and CI need no network. `--kev-live` fetches the real catalog over one HTTPS request.
- **Three output formats** (text, CSV, JSON) so the ranked queue can feed a dashboard or ticketing import.

## Verified measurements

Reproduced on 2026-11-05 (Python 3.12.2):

| Check | Result |
|---|---|
| Tests | `python -m pytest -q`: **9 passed**; `python -m unittest discover -s tests`: 9 tests OK |
| Sample size | 20 findings: 12 KEV, 8 non-KEV |
| Top 10 of the ranked queue | all 10 are KEV matches (asserted in tests) |
| Lowest-scoring KEV finding vs highest-scoring non-KEV finding | 85.0 vs 38.5 |
| KEV vs non-KEV average CVSS | 9.53 vs 8.34 |
| KEV vs non-KEV average EPSS | 0.935 vs 0.029 |
| KEV vs non-KEV average days open | 94.2 vs 101.5 |
| KEV in top 12 by CVSS-only sort vs by risk score | 9 vs 12 |
| `--kev-live` against the current CISA catalog | same ranking as the offline fixture (all 12 sample CVEs are in the live catalog) |

On this sample the groups differ by 1.19 points of average CVSS but by 0.906 of average EPSS, which is the gap the methodology is built around.

## Quick start

Python 3.9+, no dependencies.

```bash
git clone https://github.com/samiali38183/kev-risk-prioritization
cd kev-risk-prioritization

# rank the synthetic sample against the offline KEV fixture
python kev_prioritize.py data/sample_findings.csv --kev data/sample_kev.json

# same, against the live CISA KEV catalog
python kev_prioritize.py data/sample_findings.csv --kev-live

# machine-readable output
python kev_prioritize.py data/sample_findings.csv --kev data/sample_kev.json --format csv -o ranked.csv
python kev_prioritize.py data/sample_findings.csv --kev data/sample_kev.json --format json

# tests
python -m pytest -q        # or: python -m unittest discover -s tests
```

Input CSV columns: `cve, asset, acr (1-8), cvss (0-10), epss (0-1), days_open`; optional `system_group, vendor, internet_exposed`.

## Example output

```
$ python kev_prioritize.py data/sample_findings.csv --kev data/sample_kev.json --top 14

  #  risk  KEV CVE              CVSS  EPSS ACR days  asset
  1  99.4  yes CVE-2021-44228   10.0 0.970   8   42  web-portal-01
  2  99.0  yes CVE-2024-3400    10.0 0.950   8    9  fw-edge-01
  3  98.1  yes CVE-2023-4966     9.4 0.960   8   18  vpn-gw-02
  ...
 11  86.9  yes CVE-2017-0144     8.1 0.970   5  210  file-srv-legacy
 12  85.0  yes CVE-2021-34527    8.8 0.960   4  160  print-srv-03
 13  38.5  -   CVE-2023-99996    8.8 0.050   7   22  backup-srv-02
 14  33.7  -   CVE-2023-99994    7.5 0.080   6   33  reporting-db-01

KEV vs non-KEV population
  kev      n=12  avg CVSS 9.53  avg EPSS 0.935  avg days open 94.2
  non_kev  n=8   avg CVSS 8.34  avg EPSS 0.029  avg days open 101.5

KEV concentration by system group: Remote Access=4, File Services=2, Public Web=1, ...
```

Row 13 is a CVSS 8.8 on a high-criticality asset (ACR 7). It ranks below every KEV match, including a CVSS 8.1 on an old file server (row 11).

## Real-world applicability

The input is what a vulnerability scanner export plus an asset inventory already contains: CVE, asset, CVSS, a criticality rating, and an EPSS value from the public FIRST feed. A Tenable or Nessus export joined with an asset list maps onto the CSV columns directly. The output is a ranked work-list for a remediation sprint, with a population comparison and a KEV concentration view to show where remediation effort pays off most (for example, which system groups or vendors hold the exploited CVEs). The methodology behind it is written up in [`docs/methodology.md`](docs/methodology.md), including the section-by-section alignment with BOD 26-04.

## Limitations

- **Synthetic data.** The sample uses real KEV CVE IDs but invented assets, ACR, EPSS, CVSS and ages chosen to illustrate the ordering. It proves nothing about any real environment.
- **Not a scanner or enrichment service.** It consumes CVSS and EPSS values you supply; it does not query NVD or the FIRST EPSS API. Live mode fetches only the KEV catalog.
- **Simple weighted sum.** Easy to explain and tune, but it cannot express a rule such as "KEV and internet-exposed always goes first". Hard rules layered on top would be the next step.
- **No per-finding due dates.** Remediation age is reported as mean days open per population, not evaluated against BOD 26-04 deadlines per finding.
- **Weights are a starting point,** not validated against outcome data.
- **Not policy.** BOD 26-04 and the KEV Catalog are the authoritative sources.

## Repository layout

```
kev_prioritize.py          scoring, matching, population compare, CLI (stdlib only)
data/sample_findings.csv   20 synthetic findings (12 KEV, 8 non-KEV)
data/sample_kev.json       offline KEV fixture in the CISA feed schema
tests/test_scoring.py      9 tests: bounds, normalization, KEV-over-severity, clamping, pipeline, CLI
docs/methodology.md        methodology and its BOD 26-04 alignment
.github/workflows/ci.yml   unittest + CLI run on Python 3.9 and 3.13
```

## References

- [CISA BOD 26-04: Prioritizing Security Updates Based on Risk](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- [FIRST Exploit Prediction Scoring System (EPSS)](https://www.first.org/epss/)
- [National Vulnerability Database](https://nvd.nist.gov/) · [CVSS v3.1 Specification](https://www.first.org/cvss/specification-document)

## License

MIT. See [LICENSE](LICENSE).
