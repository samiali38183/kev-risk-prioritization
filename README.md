# KEV Risk Prioritization — Internship Case Study

A case study on **risk-based vulnerability prioritization** using the CISA Known Exploited Vulnerabilities (KEV) Catalog, the Exploit Prediction Scoring System (EPSS), and the Common Vulnerability Scoring System (CVSS), aligned with **CISA Binding Operational Directive (BOD) 26-04**: *Prioritizing Security Updates Based on Risk*.

This repository documents the methodology I applied during my **DHS HS-POWER internship on the U.S. Customs and Border Protection Vulnerability Assessment Team** (Summer 2026). All specific findings, figures, dashboards, and system references from that work are non-public and are not included here. What appears in this repository is the public methodology and my written explanation of it.

---

## The Problem

Enterprise vulnerability scanners routinely detect millions of findings. No team can remediate everything at once, so *which* vulnerabilities get fixed first matters as much as the fixing itself.

Traditional prioritization relies on the CVSS severity score, which measures how *bad* an exploit could be. Severity is not the same as risk:

- A vulnerability can score 9.8 on CVSS and never be exploited in the wild.
- A moderate-severity vulnerability can be under active mass exploitation today.

**CISA BOD 26-04** codifies the modern federal approach: prioritize vulnerabilities with confirmed exploitation (KEV) and high exploitation probability (EPSS) ahead of vulnerabilities that are severe on paper alone.

---

## What I Did

Over the internship I led an end-to-end research project on risk-based vulnerability prioritization for the CBP Vulnerability Assessment Team.

- **Led an end-to-end KEV research project** matching enterprise-wide Nessus/Tenable scan results against the CISA KEV Catalog, benchmarking remediation performance against CISA BOD 26-04 to identify outlier systems and aged-finding backlogs.
- **Built a multi-page Microsoft Power BI dashboard** integrating CVSS, EPSS, and remediation-age metrics — demonstrating that exploitation likelihood, not severity alone, distinguishes real-world risk.
- **Designed a risk-based prioritization methodology** weighing KEV status, asset criticality (HVA designation), internet exposure, EPSS, and CVSS to guide enterprise remediation under federal directives.
- **Delivered an executive briefing** on the findings to technical and leadership audiences.
- **Drafted technical compliance reports** on vulnerability findings and remediation recommendations, supporting operations aligned with the NIST Cybersecurity Framework, FedRAMP, and Zero Trust architecture.

---

## Why This Matters

Severity-only queues push teams toward the highest CVSS numbers first, which is not the same as pushing them toward the highest *risk*. A CVSS-9.8 that no one has ever weaponized is a lower business risk than a CVSS-7.5 that is under mass exploitation today. BOD 26-04 formalizes this insight. This project applied that framing to real federal scan data.

The core question the prioritization model answers: *if we could only patch 10% of open vulnerabilities this sprint, which should be fixed first, and why?*

---

## The Methodology (High Level)

1. **Match** every scan finding against the live CISA KEV Catalog by CVE ID.
2. **Compare** the KEV-matched population against the non-KEV population on severity, exploitation probability, and remediation velocity to surface the exploitation-vs-severity gap.
3. **Map** where KEVs concentrate — by system group, vendor, and technology — to identify remediation focus areas.
4. **Score** every finding with a weighted composite that puts exploitation evidence at the top of the ordering.
5. **Rank** the resulting queue, and **benchmark** remediation timelines against BOD 26-04 targets.

The weighted composite (from the model I built):

- KEV status — **0.40** — confirmed exploitation is the strongest signal
- Asset criticality (ACR / HVA) — **0.25** — the value of what would be lost
- EPSS — **0.20** — likelihood of exploitation in the next 30 days
- CVSS — **0.20** — severity if exploited

See [`docs/methodology.md`](docs/methodology.md) for the full writeup.

---

## What Is *Not* In This Repository

Deliberately excluded, because it is either sensitive to the internship environment or otherwise non-public:

- Scan output, asset counts, or system names from any real environment
- Screenshots of the Power BI dashboard or any real dashboard visuals
- Compliance-report text or executive-briefing materials
- Any figure or statistic derived from real scan data

This repository is a **written case study** on public methodology. It contains no code, no synthetic dataset, no runnable demo — only documentation of the approach, aligned with public federal guidance.

---

## References

- [CISA BOD 26-04: Prioritizing Security Updates Based on Risk](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [FIRST Exploit Prediction Scoring System (EPSS)](https://www.first.org/epss/)
- [National Vulnerability Database](https://nvd.nist.gov/)
- [CVSS v3.1 Specification](https://www.first.org/cvss/specification-document)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [FedRAMP](https://www.fedramp.gov/)

## License

MIT. See [LICENSE](LICENSE).

---

**Author:** Sami Ali · IT/Cybersecurity student, Northern Virginia Community College · CompTIA Security+ · AWS Certified Cloud Practitioner · AWS Solutions Architect – Associate *(in progress)* · CompTIA CySA+ *(in progress)* · DHS HS-POWER intern, CBP Vulnerability Assessment Team (Summer 2026)
