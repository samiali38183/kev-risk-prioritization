# Methodology — KEV Risk Prioritization

This document explains the methodology implemented in this repository. Everything here is derived from public sources (CISA, FIRST, NVD) and applied to synthetic data.

## 1. Problem framing

Federal and enterprise environments produce vulnerability scan output at a volume no team can remediate synchronously. Prioritization decisions therefore drive real-world risk reduction more than the mechanics of patching. CISA's **Binding Operational Directive 26-04** formalizes a risk-based ordering that puts confirmed exploitation ahead of theoretical severity.

## 2. Data inputs

| Input | Source | Role |
|---|---|---|
| CISA KEV Catalog | live from CISA / cisagov mirror | Confirmed exploitation evidence |
| Synthetic scan dataset | `synthetic_data.py` | 50,000 findings shaped like Nessus/Tenable export |
| CVSS scores | assigned per severity band | Severity if exploited |
| EPSS scores | generated with a heavy-tailed beta distribution | Exploitation probability (30-day) |
| Asset Criticality Rating (ACR) | 1–8 scale, middle-biased | Business/mission value of the asset |

The synthetic generator is seeded (`seed=42` by default) so results are reproducible across runs.

## 3. Matching

Every scan finding carries a CVE identifier. `demo.py` builds a set of KEV CVE IDs from the live catalog and marks each finding `is_kev = True` or `False`. To simulate a realistic mix, ~2.5% of the synthetic findings have their CVE replaced with a real KEV ID before matching. EPSS for KEV-matched findings is redistributed on a Beta(2, 4) to reflect the higher exploitation-probability distribution observed for known-exploited CVEs.

## 4. Population comparison

`compare_populations()` produces a KEV vs. non-KEV table across four columns:

- **findings** — volume in each population
- **avg_cvss** — mean severity
- **avg_epss** — mean exploitation probability
- **avg_remediation_days** — how long findings stay open

The comparison surfaces the core insight of BOD 26-04: severity is roughly flat across the two populations, but exploitation probability is orders of magnitude higher in the KEV group. That is the signal a severity-only queue misses.

## 5. Weighted risk model

Each finding is scored 0–100:

```
risk_score = 100 * (
    0.40 * kev_flag        # 1 if in KEV, else 0
  + 0.25 * (acr / 8)       # normalized asset criticality
  + 0.20 * epss            # already 0–1
  + 0.20 * (cvss / 10)     # normalized severity
)
```

Weights reflect BOD 26-04's ordering: confirmed exploitation dominates, asset criticality is the next largest factor (because exploiting a low-value asset is a lower business impact than exploiting a High Value Asset), and EPSS and CVSS split the remaining weight roughly evenly. The weights are constants at the top of `risk_model.py` and can be swapped for any organization's local risk appetite.

## 6. Output — the ranked queue

`score_dataframe()` returns the full scan set sorted by `risk_score` descending. `demo.py` prints the top 10. Every top-10 finding in a typical run is a KEV match — which is the intended behavior.

For a real environment, the top of that ranked queue is the remediation work-list for the current sprint; the middle is monitoring; the tail is deferred with justification.

## 7. Alignment with BOD 26-04

| BOD 26-04 element | How this repo implements it |
|---|---|
| Prioritize confirmed exploitation | KEV status carries the heaviest weight (0.40) |
| Incorporate exploitation probability | EPSS included as a scoring input (0.20) |
| Weight asset context | ACR (Asset Criticality Rating) at 0.25 |
| Bench remediation against risk-based timelines | `avg_remediation_days` reported per population |

## 8. What this repo is not

- **Not a scanner.** It consumes scan output; it does not generate it.
- **Not a policy document.** BOD 26-04 is linked in the README; this repo implements one interpretation of a scoring model consistent with it.
- **Not a replacement for organizational judgment.** Weights should be tuned to the environment. HVAs, internet exposure, and business context often warrant custom weighting.

## References

See `README.md` for the full reference list.
