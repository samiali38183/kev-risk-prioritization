# Methodology: KEV Risk Prioritization

This document explains the weighted risk-prioritization model implemented in `kev_prioritize.py`, using only public sources. No internal data, figures, or system names appear here. The model is a simple score of this project's own design; it is not an implementation of any CISA directive (see section 8).

## 1. Problem framing

Vulnerability scan output arrives at a volume no team can remediate synchronously, so the ordering decision drives real-world risk reduction more than the mechanics of patching. The premise of this model is that confirmed exploitation should sort ahead of theoretical severity. The weighted model below is a teaching formula built on that premise. CISA's BOD 26-04 also treats known exploitation (KEV) as a prioritization input, but alongside three other variables and as a lookup table rather than a score; see [`bod-26-04.md`](bod-26-04.md).

## 2. Data inputs

The model combines four inputs for every finding:

| Input | Source | Role |
|---|---|---|
| CISA KEV Catalog | CISA (public, CC0) | Confirmed exploitation evidence |
| CVSS score | NVD (public, per CVE); optional | Severity if exploited |
| EPSS score | FIRST (public, per CVE) | Exploitation probability (30-day window) |
| Asset Criticality Rating (ACR) | Enterprise asset context (e.g., HVA designation, internet exposure) | Business/mission value of the asset |

CVSS is optional: when absent, its term and weight are dropped and the remaining weights are renormalized (section 6).

## 3. Matching

Every scan finding carries a CVE identifier. The KEV Catalog is treated as a set of CVE IDs, and each finding is marked as KEV-matched or not. This turns "known exploited in the wild" into a per-finding boolean the model can weight.

## 4. Population comparison

The KEV-matched population is compared against the non-KEV population on four dimensions:

- **Volume**: how many findings fall in each group
- **Average CVSS**: mean severity
- **Average EPSS**: mean exploitation probability
- **Average remediation days**: how long findings stay open

On the synthetic demo the comparison is built to show a pattern: severity close across the two groups, exploitation probability far apart. Those demo values are invented. On real data the relationship between KEV and EPSS is measured in [`real_data_analysis.md`](real_data_analysis.md), with the caveat that the two signals are not independent (section 10).

## 5. Concentration mapping

For the KEV population, findings are grouped by system role, vendor, and technology to identify remediation focus areas: the systems, vendors, and product families where confirmed-exploited CVEs cluster.

## 6. Weighted risk model

Every finding is scored on a 0-100 scale using a weighted composite:

```
risk_score = 100 * (
    0.40 * kev_flag        # 1 if in KEV Catalog, else 0
  + 0.25 * (acr / 8)       # normalized asset criticality (1-8 scale)
  + 0.20 * epss            # already 0-1
  + 0.20 * (cvss / 10)     # normalized severity (0-10 scale)
) / 1.05                   # divide by the weight total so the scale is a true 0-100
```

The weights sum to 1.05, so the composite is divided by the weight total; this keeps the score on a 0-100 scale without changing the ordering, and it holds for any re-tuned weight set. When a finding has no CVSS, the CVSS term is omitted and the divisor becomes 0.85 (the sum of the remaining weights). `kev_prioritize.py` at the repository root implements this exactly.

The weights express a KEV-first ordering. They are a design choice, **not validated against outcome data**:

- **KEV status carries the heaviest weight (0.40)**: confirmed exploitation is treated as the strongest indicator of real-world risk.
- **Asset criticality (0.25)**: exploiting a low-value asset produces a lower business impact than exploiting a High Value Asset with the same CVE.
- **EPSS and CVSS split the remaining weight (0.20 each)**: likelihood of exploitation and severity if exploited.

Weights should be tuned to the organization's risk appetite (for example, weighting internet exposure more heavily for public-facing systems, or raising ACR weight for regulated environments).

## 7. Output: the ranked queue

Findings are sorted by `risk_score` descending (ties: EPSS, then CVSS). The top of the ranked queue is the candidate work-list for the current sprint. With these weights the top of the queue is dominated by KEV matches, which is the intended behavior and follows from the weights: it is a property of the formula, not evidence that the ordering reduces risk.

## 8. Relationship to BOD 26-04

BOD 26-04 (CISA, June 10, 2026) sets remediation timelines for federal civilian agencies from four variables, **publicly exposed, in the KEV, automatable by adversary, and technical impact (partial or total control)**, using a 16-row decision table with outcomes of 3 days (with forensic triage in some rows), 14 days, 60 days or "fix on system upgrade". The sources, a transcription of Table 1 and what could not be verified are in [`bod-26-04.md`](bod-26-04.md).

This project does not implement the directive. It shares one idea with it (known exploitation matters a lot) and differs in structure and inputs:

| Element | BOD 26-04 | This project |
|---|---|---|
| Form | Decision table over four categorical variables, per asset | Weighted sum, 0-100 |
| KEV status | One of four inputs | Heaviest of four weighted terms (0.40) |
| Asset exposure (public yes/no) | Input | Not modeled; the optional `internet_exposed` column is carried through but not scored. ACR is a different, 1-8 criticality rating |
| Exploit automation, technical impact | Inputs (from Vulnrichment) | Not modeled |
| EPSS, CVSS | Not inputs | Inputs (0.20 each) |
| Output | Deadline (3 / 14 / 60 days / on upgrade), forensic triage flag | Rank order; no deadlines |

Remediation age is reported per population (mean days open) and is not evaluated against any directive timeline.

## 9. What this document is not

- **Not a policy document.** BOD 26-04 is the authoritative source for what federal agencies must do; this project is neither a compliance tool nor a statement of what the directive requires.
- **Not a replacement for organizational judgment.** Weights should be tuned per environment.
- **Not a scanner.** The methodology consumes scan output; it does not generate it.

## 10. Known weaknesses of the inputs

- **EPSS and KEV are not independent.** EPSS is trained on observed exploitation evidence, and FIRST lists a known-exploited-vulnerabilities feed (VulnCheck KEV) among its data partners. A model that adds EPSS to KEV partly counts the same evidence twice.
- **KEV is an incomplete label.** Absence from the catalog does not mean a CVE is not exploited.
- **CVSS measures severity, not likelihood.** It is retained at a modest weight for that reason.

## References

See `README.md` for the full reference list.
