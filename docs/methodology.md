# Methodology: KEV Risk Prioritization

This document describes the weighted risk-prioritization model in `kev_prioritize.py`. It uses only public sources, and no internal data, figures or system names appear here. The model is a simple score of my own design. It is not an implementation of any CISA directive (see section 8).

## 1. Problem framing

Vulnerability scan output arrives at a volume no team can remediate synchronously, so the ordering decision matters more than the mechanics of patching. The premise of this model is that confirmed exploitation should sort ahead of theoretical severity. The weighted model below is a formula I wrote to explore that premise. CISA's BOD 26-04 also treats known exploitation (KEV) as a prioritization input, but alongside three other variables and as a lookup table rather than a score; see [`bod-26-04.md`](bod-26-04.md).

## 2. Data inputs

The model combines four inputs for every finding:

| Input | Source | Role |
|---|---|---|
| CISA KEV Catalog | CISA (public, CC0) | Confirmed exploitation evidence |
| CVSS score | NVD (public, per CVE); optional | Severity if exploited |
| EPSS score | FIRST (public, per CVE) | Exploitation probability (30-day window) |
| Asset Criticality Rating (ACR) | A 1-8 number you supply per asset (for example from an HVA designation; if you want internet exposure to count, fold it into this number) | Business/mission value of the asset |

CVSS is optional: when absent, its term and weight are dropped and the remaining weights are renormalized (section 6). The CSV may also carry `internet_exposed` and `days_open`; they are read and reported but are **not inputs to the score** (section 8).

## 3. Matching

Every scan finding carries a CVE identifier. The KEV Catalog is treated as a set of CVE IDs, and each finding is marked as KEV-matched or not. This turns "known exploited in the wild" into a per-finding boolean the model can weight.

## 4. Population comparison

The KEV-matched population is compared against the non-KEV population on four dimensions:

- Volume: how many findings fall in each group
- Average CVSS: mean severity
- Average EPSS: mean exploitation probability
- Average remediation days: how long findings stay open

On the synthetic demo I built the values to show a pattern: severity close across the two groups, exploitation probability far apart. Those demo values are invented. On real data the relationship between KEV and EPSS is measured in [`real_data_analysis.md`](real_data_analysis.md), with the caveat that the two signals are not independent (section 10).

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

**Scores are comparable only within one signal set.** Dropping a term and renormalizing puts a score on a different scale: the same KEV finding (ACR 4, EPSS 0.5) is 73.5 without CVSS but 59.5 with CVSS 0.0, so a CVSS-less row would outrank an otherwise identical row whose CVSS is low. The tool therefore enforces one signal set per ranked list:

- every row has CVSS: all four terms are used (`score_basis` = `kev+acr+epss+cvss`);
- no row has CVSS (column absent or every cell blank): three terms, divisor 0.85 (`kev+acr+epss`);
- some rows have CVSS and some do not: the list is refused (exit code 2) because any single ranking would compare incomparable scores. With `--allow-mixed` every row is scored **without** its CVSS term (three terms, one scale, `score_basis` = `kev+acr+epss` on every row), a warning is printed, and the text output ends with a note. Existing CVSS values are still shown but do not affect the order.

Imputing a value for missing CVSS was considered and not done: any imputed number is an unvalidated assumption that would be baked into the scores.

The weights express a KEV-first ordering. They are a design choice, **not validated against outcome data**:

- KEV status carries the heaviest weight (0.40). I treat confirmed exploitation as the strongest indicator of risk.
- Asset criticality gets 0.25, because exploiting a low-value asset has less business impact than exploiting a High Value Asset with the same CVE.
- EPSS and CVSS split the remaining weight (0.20 each): likelihood of exploitation and severity if exploited.

Weights should be tuned to the organization's risk appetite (for example raising the ACR weight for regulated environments, via the `weights` argument of `score_all()`). There is no exposure weight: `internet_exposed` is not scored, and exposure can only enter through the ACR you supply.

## 7. Output: the ranked queue

Findings are sorted by a total order: `risk_score` descending, then KEV status (KEV first), EPSS, CVSS (missing CVSS last), ACR and days open, all descending, then CVE id, asset, system group, vendor and exposure ascending. Because every field participates, the output does not depend on the input order. The top of the ranked queue is the candidate work-list for the current sprint. With these weights the top of the queue is mostly KEV matches. That follows from the weights. It is a property of the formula, not evidence that the ordering reduces risk.

## 8. Relationship to BOD 26-04

BOD 26-04 (CISA, June 10, 2026) sets remediation timelines for federal civilian agencies from four variables, **publicly exposed, in the KEV, automatable by adversary, and technical impact (partial or total control)**, using a 16-row decision table with outcomes of 3 days (with forensic triage in some rows), 14 days, 60 days or "fix on system upgrade". The sources, a transcription of Table 1 and what could not be verified are in [`bod-26-04.md`](bod-26-04.md).

This project does not implement the directive. It shares one idea with it (known exploitation matters a lot) and differs in structure and inputs:

| Element | BOD 26-04 | This project |
|---|---|---|
| Form | Decision table over four categorical variables, per asset | Weighted sum, 0-100 |
| KEV status | One of four inputs | Heaviest of four weighted terms (0.40) |
| Asset exposure (public yes/no) | Input | Not modeled; the optional `internet_exposed` column is carried through but not scored (changing it never changes a score; a test pins this). ACR is a different, 1-8 criticality rating |
| Exploit automation, technical impact | Inputs (from Vulnrichment) | Not modeled |
| EPSS, CVSS | Not inputs | Inputs (0.20 each) |
| Output | Deadline (3 / 14 / 60 days / on upgrade), forensic triage flag | Rank order; no deadlines |

Remediation age (`days_open`) is reported per population as a mean, used only as a late sort tie-break, and is not compared with any directive timeline.

## 9. What this document is not

- It is not a policy document. BOD 26-04 is the authority on what federal agencies must do, and this project is neither a compliance tool nor a statement of what the directive requires.
- It does not replace judgment about your own environment. Tune the weights for it.
- It is not a scanner. It reads scan output and does not generate it.

## 10. Known weaknesses of the inputs

- EPSS and KEV are not independent. EPSS is trained on observed exploitation evidence, and FIRST lists a known-exploited-vulnerabilities feed (VulnCheck KEV) among its data partners. A model that adds EPSS to KEV partly counts the same evidence twice.
- KEV is an incomplete label. Absence from the catalog does not mean a CVE is not exploited.
- CVSS measures severity, not likelihood, so it keeps only a modest weight.

## References

See `README.md` for the full reference list.
