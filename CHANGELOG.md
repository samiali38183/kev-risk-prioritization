# Changelog

## 0.3.0 - 2026-11-11

Fixes for defects found in review of 0.2.0. Tests: 27 before, 63 now.

### Behavior changes (read these before upgrading)

- **Mixed CVSS lists are refused.** In 0.2.0 a row without CVSS was scored on a different scale from a row with CVSS (the same KEV finding, ACR 4, EPSS 0.5, scored 73.5 without CVSS and 59.5 with CVSS 0.0), so a list mixing both was ranked with incomparable scores. Now `score_all` raises and the CLI exits 2 on such a list unless `--allow-mixed` is given; then every row is scored without its CVSS term so all scores share one scale, a warning is printed, and each output row has a new `score_basis` field. Lists where every row has CVSS, or none does, score exactly as before.
- **Input is validated instead of clamped at load.** `acr` must be 1-8, `epss` 0-1, `cvss` 0-10, `days_open` a whole number >= 0, `cve` of the form `CVE-YYYY-NNNN`, `internet_exposed` one of 1/true/yes/0/false/no/blank. Out-of-range values that 0.2.0 silently clamped are now errors with the row number. `risk_score()` itself still clamps for library callers.
- **New CSV/JSON field `score_basis`**, so the CSV golden hash changed (see below).
- **Sort order is now a total order** (score, KEV, EPSS, CVSS, ACR, days open, then CVE id, asset, system group, vendor, exposure). In 0.2.0 ties depended on input order although the README said otherwise. On the 2,000-row real-data list 139 tied rows changed position; the row set and every score are unchanged. KEV-concentration ties are now ordered by name.

### Fixed

- Error handling: missing columns, non-numeric or out-of-range values (with row numbers), empty files, header-only files, malformed or wrongly shaped KEV JSON, an empty KEV catalog, missing files, an unwritable output path and a failed live fetch each produce a one-line `kev_prioritize: error: ...` on stderr and a non-zero exit code (2 for bad input, 1 for network or output failures) instead of a traceback. A UTF-8 byte-order mark and spaces around header names are accepted.
- Docs: the README said exposure could be weighted via `score_all()` and that "ties break deterministically on EPSS, then CVSS"; neither was accurate. `internet_exposed` and `days_open` are documented as read and passed through but **not scored** (a test pins this), with a table of the BOD 26-04 variables the tool does not model. The README now says at the top that "all KEV in the top N" results are true by construction. Chose documenting over adding an exposure weight (one more unvalidated number).
- BOD 26-04 Table 1: re-read against the full-size image from cisa.gov, 16 of 16 rows matched the transcription. No machine-readable source was found (alt text is only a title), so it stays flagged as visually transcribed and not machine-verified.

### Added

- `ruff` (lint and format check) and `mypy` (3.9 target) in CI at pinned versions (ruff 0.17.4, mypy 1.19.1; config in `pyproject.toml`); type annotations added to `scripts/`. zizmor re-run clean (1.32.0); action SHAs unchanged and re-verified against their tags.
- `scripts/refresh_goldens.py` (regenerate or `--check` the generated analysis, the mixed list and both golden files) and `docs/REFRESHING_SNAPSHOT.md`. CI now runs `--check` and fails with an explanation naming the stale files.
- A test that the AUC figures quoted in the README match the generated analysis.

### Regenerated

- `tests/golden/snapshot_ranked_csv.sha256` only (same rows, new column, tied rows reordered). `tests/golden/snapshot_top25.txt`, `docs/real_data_analysis.md` and `data/snapshot/mixed_findings.csv` regenerated from real runs and were byte-identical.

### Not done

- No exposure, automation or impact modeling, no `--weights` flag, no weight-sensitivity analysis, no coverage measure; these remain listed under Limitations.

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
