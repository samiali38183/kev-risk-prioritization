# Refreshing the pinned snapshot and regenerating the golden files

The repository pins one real KEV + EPSS snapshot (`data/snapshot/`). Several files are derived from it and are checked byte for byte, in the unit tests and in CI, so that no number in the repository can drift silently:

| Derived file | Produced by | Checked by |
|---|---|---|
| `data/snapshot/mixed_findings.csv`, `docs/real_data_analysis.md` | `scripts/analyze_snapshot.py` | `refresh_goldens.py --check` (CI), `GoldenTests` |
| `tests/golden/snapshot_top25.txt` | `kev_prioritize.py --top 25` on the mixed list | same |
| `tests/golden/snapshot_ranked_csv.sha256` | SHA-256 of `kev_prioritize.py --format csv` on the mixed list | same |

If any of them is stale, CI fails with an explanation naming the stale files. That is the intended behavior: the failure means "the tool's output on real data changed", and a person has to look at the diff and decide whether the change is wanted.

## A. After a deliberate code change (scoring, sort order, output columns)

```bash
python scripts/refresh_goldens.py          # rewrites the generated analysis, the mixed list and both goldens
git diff                                   # review every changed line
python scripts/refresh_goldens.py --check  # must now exit 0
python -m unittest discover -s tests
```

What to look for in the diff: a sort-order change should only re-order rows that tie on score (the row set is unchanged); a scoring change moves scores and the analysis text. Do not regenerate to silence a failure you did not expect. Then update any README or docs figure that quotes the regenerated output (section C) and add a `CHANGELOG.md` line.

## B. Refreshing the snapshot itself (new KEV catalog / new EPSS day)

cisa.gov serves only the current KEV catalog and EPSS files are published per day, so a refresh replaces the pin; the old KEV file is kept only in git history. Save the raw downloads yourself so the result can be re-verified (the EPSS gzip is about 3 MB and is deliberately not committed).

```bash
git switch -c data/refresh-YYYY-MM-DD
D=YYYY-MM-DD                                   # an EPSS score date that exists
curl -fLo kev.json  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
curl -fLo epss.csv.gz "https://epss.empiricalsecurity.com/epss_scores-$D.csv.gz"

# write the new snapshot files from the saved raw downloads
python scripts/fetch_snapshot.py --date $D --kev-file kev.json --epss-file epss.csv.gz
# prove it is reproducible from those raw files
python scripts/fetch_snapshot.py --date $D --kev-file kev.json --epss-file epss.csv.gz --check

python scripts/refresh_goldens.py              # regenerate analysis, mixed list, goldens
python scripts/refresh_goldens.py --check
python -m unittest discover -s tests
```

Notes:

- `fetch_snapshot.py` keeps its default sampling seed (`kev-risk-prioritization-2026-11-11`) so successive snapshots draw comparable samples; pass `--seed` only if you want a different draw, and record why. The mixed-list and bootstrap seeds in `scripts/analyze_snapshot.py` are constants for the same reason.
- Without `--kev-file` / `--epss-file` the script downloads fresh copies but does not keep them; prefer the saved-file form above.
- Check the new `SNAPSHOT.json` for `kev_ids_missing_from_epss`; the analysis assumes it is empty.
- Review the new numbers before publishing them. A different KEV size, a new EPSS model version or a different prevalence can change what the analysis says, not just its figures.

## C. Figures that are written by hand and must be updated by a person

These are not generated, so a refresh leaves them stale until edited. A unit test (`test_readme_figures_match_analysis`) checks the AUC figures in the README against the generated analysis; the rest rely on review.

- `README.md`: the "Data note" dates, the "Evidence" section figures (AUC and interval, threshold recall and precision, mixed-list counts), and the synthetic-demo numbers if the demo or scoring changed.
- `data/snapshot/SNAPSHOT.md`: the source table (versions, dates, sizes, hashes), counts, and the sampling paragraph.
- `CHANGELOG.md`: what changed and why, including any correction.

## What CI does

`ci.yml` runs `python scripts/refresh_goldens.py --check` on Python 3.9 and 3.13. It regenerates everything in the first table from the committed snapshot and compares bytes. It never rewrites files in CI.
