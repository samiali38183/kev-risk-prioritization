# Changelog

## 0.2.0 - 2026-11-11

### Corrections to earlier claims

- **BOD 26-04.** Earlier text said the score was "in the spirit of" CISA BOD 26-04 and "consistent with" its KEV-first approach. That overstated the relationship. The directive uses four variables (publicly exposed, in KEV, automatable, technical impact) in a decision table with per-asset deadlines; KEV is one input, and EPSS, CVSS and asset criticality are not inputs. The project is now described as a simple weighted score of its own design, not an implementation of the directive. The variables it does not model are listed under Limitations, and `docs/bod-26-04.md` records what the directive says, with sources and what could not be verified.
- **"Verified measurements" table removed.** It reported properties of invented EPSS and CVSS values on synthetic data (for example average EPSS 0.935 for KEV vs 0.029 for non-KEV), which says nothing about real vulnerabilities. The synthetic sample is kept and labeled as a demo of the formula. Real-data measurements replace it (see below).
- **Methodology document.** Removed first-person internship framing and the section listing internship deliverables, none of which could be verified from this repository.

### Added

- Pinned real-data snapshot in `data/snapshot/`: CISA KEV catalog 2026.11.10 (1,779 entries) and the EPSS rows for all KEV CVEs plus 5,000 seeded non-KEV CVEs from the FIRST EPSS file scored 2026-11-11, with SHA-256 of the raw downloads, sources, terms and caveats in `SNAPSHOT.md` / `SNAPSHOT.json`.
- `scripts/fetch_snapshot.py` (build or verify the snapshot, stdlib only).
- `scripts/analyze_snapshot.py` and the generated `docs/real_data_analysis.md`: EPSS distribution and AUC for KEV vs sampled non-KEV, threshold recall/precision at population prevalence, and the tool's behavior on a mixed list with invented asset values. The analysis states the EPSS/KEV circularity and other limits.
- The `cvss` input column is now optional; when absent its term and weight are dropped and the score is renormalized to 0-100.
- `--version` flag.
- Tests for the snapshot (integrity, hashes), the scripts, the no-CVSS path, and golden output of the tool on the snapshot (27 tests in total).

### Changed

- CI: every action pinned by full commit SHA with a version comment, job-level least-privilege `permissions`, `persist-credentials: false`, concurrency control and timeouts, a golden-file check of the tool on the snapshot, a freshness check of the generated analysis, and a zizmor (offline, auditor persona) job.
- Text and file output now always end with a newline.

## 0.1.0

Initial reference implementation, synthetic sample data and tests (not released as a tag).
