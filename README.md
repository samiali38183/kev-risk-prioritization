# KEV Risk Prioritization Framework

A reproducible demonstration of **risk-based vulnerability prioritization** using the CISA Known Exploited Vulnerabilities (KEV) Catalog, the Exploit Prediction Scoring System (EPSS), and the Common Vulnerability Scoring System (CVSS), aligned with **CISA Binding Operational Directive (BOD) 26-04**: *Prioritizing Security Updates Based on Risk*.

All data in this repository is either **synthetic** or drawn from **public sources** (CISA, FIRST, NVD). No internal, agency, or otherwise non-public data is included.

---

## The Problem

Enterprise vulnerability scanners routinely detect millions of findings. No team can remediate everything at once, so *which* vulnerabilities get fixed first matters as much as the fixing itself.

Traditional prioritization relies on the CVSS severity score, which measures how *bad* an exploit could be. Severity, though, is not the same as risk:

- A vulnerability can score 9.8 on CVSS and never be exploited in the wild.
- A moderate-severity vulnerability can be under active mass exploitation today.

**BOD 26-04** codifies the modern federal approach: prioritize vulnerabilities with confirmed exploitation (KEV) and high exploitation probability (EPSS) ahead of vulnerabilities that are severe on paper alone.

## What This Repo Demonstrates

- Pulling the **live CISA KEV Catalog** and joining it against a synthetic scanner-export dataset.
- Comparing KEV vs. non-KEV populations on severity, exploitation probability, and remediation velocity.
- Applying a **weighted risk score** — KEV status (0.40) + Asset Criticality (0.25) + EPSS (0.20) + CVSS (0.20) — to produce an automatically ranked remediation queue.
- Answering the core prioritization question with reproducible code: *if we could only patch 10% of open vulnerabilities this month, which should be fixed first, and why?*

---

## Quick Start

```bash
git clone https://github.com/samiali38183/kev-risk-prioritization.git
cd kev-risk-prioritization
pip install -r requirements.txt
python demo.py
```

The demo downloads the live CISA KEV Catalog, generates a synthetic scan dataset of 50,000 findings, runs the full matching and scoring pipeline, and prints the ranked results.

## Repository Contents

| File | Purpose |
|---|---|
| `demo.py` | End-to-end pipeline: fetch KEV, generate synthetic data, match, score, rank |
| `synthetic_data.py` | Reproducible synthetic scanner-export generator (seeded) |
| `risk_model.py` | Weighted risk-scoring implementation |
| `requirements.txt` | Python dependencies (pandas — KEV fetch uses stdlib `urllib.request`) |
| `docs/methodology.md` | Detailed methodology writeup |
| `LICENSE` | MIT |

## Methodology Summary

1. **Data collection.** Vulnerability scan results (Nessus/Tenable schema) matched against the CISA KEV Catalog via CVE identifier.
2. **Population comparison.** KEV and non-KEV findings compared on CVSS (severity), EPSS (exploitation probability), and remediation timelines.
3. **Concentration mapping.** Where KEVs live by system group, vendor, and technology.
4. **Weighted risk model.** Every finding scored 0–100 using a composite formula that puts exploitation evidence at the top of the weighting, consistent with BOD 26-04's risk-based ordering.
5. **Deliverables.** Ranked remediation queue, benchmarked against BOD 26-04 timelines.

See [`docs/methodology.md`](docs/methodology.md) for the full writeup.

## Background

This project is informed by hands-on work on the **U.S. Customs and Border Protection Vulnerability Assessment Team** during my DHS HS-POWER internship (Summer 2026), where the same methodology — matching enterprise scan data against KEV, benchmarking against BOD 26-04, and applying a weighted risk-scoring model — was applied to federal-scale scanner output. All specific findings, figures, system names, and internal artifacts from that work are non-public and are not included in this repository. What appears here is a public, generic implementation on synthetic data.

## References

- [CISA BOD 26-04: Prioritizing Security Updates Based on Risk](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [FIRST Exploit Prediction Scoring System (EPSS)](https://www.first.org/epss/)
- [National Vulnerability Database](https://nvd.nist.gov/)
- [CVSS v3.1 Specification](https://www.first.org/cvss/specification-document)

## License

MIT. See [LICENSE](LICENSE).

---

**Author:** Sami Ali · IT/Cybersecurity student, Northern Virginia Community College · CompTIA Security+ · AWS Certified Cloud Practitioner · AWS Solutions Architect – Associate *(in progress)* · CompTIA CySA+ *(in progress)* · DHS HS-POWER intern, CBP Vulnerability Assessment Team (Summer 2026)
