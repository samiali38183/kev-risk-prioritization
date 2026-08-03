# Methodology — KEV Risk Prioritization

This document explains the risk-based vulnerability prioritization methodology I applied during my DHS HS-POWER internship on the CBP Vulnerability Assessment Team, using only public federal guidance and public references. No internal data, figures, or system names appear here.

## 1. Problem framing

Federal and enterprise environments produce vulnerability scan output at a volume no team can remediate synchronously. Prioritization decisions therefore drive real-world risk reduction more than the mechanics of patching. CISA's **Binding Operational Directive 26-04** formalizes a risk-based ordering that puts confirmed exploitation ahead of theoretical severity.

## 2. Data inputs

The methodology combines four inputs for every finding:

| Input | Source | Role |
|---|---|---|
| CISA KEV Catalog | CISA (public) | Confirmed exploitation evidence |
| CVSS score | NVD (public, per CVE) | Severity if exploited |
| EPSS score | FIRST (public, per CVE) | Exploitation probability (30-day window) |
| Asset Criticality Rating (ACR) | Enterprise asset context (e.g., HVA designation, internet exposure) | Business/mission value of the asset |

## 3. Matching

Every scan finding carries a CVE identifier. The KEV Catalog is treated as a set of CVE IDs, and each finding is marked as KEV-matched or not. This turns "known exploited in the wild" into a per-finding boolean the model can weight.

## 4. Population comparison

The KEV-matched population is compared against the non-KEV population on four dimensions:

- **Volume** — how many findings fall in each group
- **Average CVSS** — mean severity
- **Average EPSS** — mean exploitation probability
- **Average remediation days** — how long findings stay open

The comparison surfaces the core insight of BOD 26-04: **severity is roughly flat across the two populations, but exploitation probability is dramatically higher in the KEV group.** That is exactly the signal a severity-only queue misses.

## 5. Concentration mapping

For the KEV population, findings are grouped by system role, vendor, and technology to identify remediation focus areas — the systems, vendors, and product families where confirmed-exploited CVEs cluster. This informs where remediation effort produces the largest risk reduction per hour of engineering time.

## 6. Weighted risk model

Every finding is scored on a 0–100 scale using a weighted composite:

```
risk_score = 100 * (
    0.40 * kev_flag        # 1 if in KEV Catalog, else 0
  + 0.25 * (acr / 8)       # normalized asset criticality (1–8 scale)
  + 0.20 * epss            # already 0–1
  + 0.20 * (cvss / 10)     # normalized severity (0–10 scale)
)
```

Weights reflect BOD 26-04's ordering:

- **KEV status carries the heaviest weight (0.40)** — confirmed exploitation is the single strongest indicator of real-world risk.
- **Asset criticality (0.25)** — exploiting a low-value asset produces a lower business impact than exploiting a High Value Asset with the same CVE.
- **EPSS and CVSS split the remaining weight (0.20 each)** — likelihood of exploitation and severity if exploited.

Weights are a starting point, not a mandate. In production, they are tuned to the organization's risk appetite (for example, weighting internet exposure more heavily for public-facing systems, or raising ACR weight for regulated environments).

## 7. Output — the ranked queue

Findings are sorted by `risk_score` descending. The top of the ranked queue is the remediation work-list for the current sprint; the middle is monitoring; the tail is deferred with justification. In practice, the top of a ranked queue built with these weights is dominated by KEV matches — which is the intended behavior.

## 8. Alignment with BOD 26-04

| BOD 26-04 element | How this methodology implements it |
|---|---|
| Prioritize confirmed exploitation | KEV status carries the heaviest single weight (0.40) |
| Incorporate exploitation probability | EPSS as a scoring input (0.20) |
| Weight asset context | ACR at 0.25 (captures HVA designation and internet exposure) |
| Bench remediation against risk-based timelines | Remediation-day averages reported per population |

## 9. Deliverables (in the internship context)

The methodology above supported four internship deliverables:

- **Multi-page Power BI dashboard** integrating CVSS, EPSS, KEV status, and remediation-age metrics for federal-scale scan output.
- **KEV vs. non-KEV analysis** demonstrating the exploitation-vs-severity gap on real data.
- **Executive briefing** presenting the findings to technical and leadership audiences.
- **Technical compliance reports** on vulnerability findings and remediation recommendations aligned with the NIST Cybersecurity Framework, FedRAMP, and Zero Trust architecture.

The specific numbers, screenshots, and system references from those deliverables are non-public and are not included in this repository.

## 10. What this document is not

- **Not a policy document.** BOD 26-04 is the authoritative source; the linked CISA page is the reference.
- **Not a replacement for organizational judgment.** Weights should be tuned per environment.
- **Not a scanner.** The methodology consumes scan output; it does not generate it.

## References

See `README.md` for the full reference list.
