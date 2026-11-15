# kev-risk-prioritization

[![ci](https://github.com/samiali38183/kev-risk-prioritization/actions/workflows/ci.yml/badge.svg)](https://github.com/samiali38183/kev-risk-prioritization/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.9%2B%20%C2%B7%20stdlib%20only-blue)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

This is a small command-line tool that ranks vulnerability findings so the CVEs on CISA's Known Exploited Vulnerabilities (KEV) list come first, followed by asset criticality, EPSS and CVSS. It uses only the Python standard library and runs offline against a KEV file. I wrote it to think through a question: if a team can fix only a slice of its open findings this sprint, which slice should it be?

It is a case study, not an implementation of CISA BOD 26-04, which sets deadlines from a lookup table and not from a score ([how they differ](docs/bod-26-04.md)). The weights and the tests are my own design. The same score is used in [kevgate](https://github.com/samiali38183/kevgate), a service built around it, and in [kevgate-admit](https://github.com/samiali38183/kevgate-admit), a Kubernetes admission webhook.

![Left: EPSS scores of 1,779 known-exploited CVEs against 5,000 others, medians 0.533 and 0.006, AUC 0.9515. Right: this tool puts all 100 KEV findings of a 2,000-row list in its top 100, EPSS alone puts 65 and asset criticality alone puts 10. Bottom: the AUC is partly circular and the weights are unvalidated.](docs/img/hero-real-data.png)

*Computed from the pinned snapshot in [`data/snapshot/`](data/snapshot/SNAPSHOT.md) (CISA KEV catalog 2026.11.10, FIRST EPSS scores for 2026-11-11) by `docs/img/make_hero.py`, which needs matplotlib; the tool itself does not. The 100 of 100 comes mostly from the weights, since KEV carries 0.40 of the score. The 0.9515 AUC is partly circular: EPSS is trained on exploitation evidence that overlaps with what KEV records, so it does not validate either. Assets (ACR, names, days open) in the real-data list are invented, and no CVSS is used with it.*

## Try it

Python 3.9 or newer, standard library only, no network.

```
git clone https://github.com/samiali38183/kev-risk-prioritization && cd kev-risk-prioritization
python kev_prioritize.py data/sample_findings.csv --kev data/sample_kev.json --top 14
python -m unittest discover -s tests        # 63 tests
```

```
  #  risk  KEV CVE              CVSS  EPSS ACR days  asset
  1  99.4  yes CVE-2021-44228   10.0 0.970   8   42  web-portal-01
  ...
 12  85.0  yes CVE-2021-34527    8.8 0.960   4  160  print-srv-03
 13  38.5  -   CVE-2023-99996    8.8 0.050   7   22  backup-srv-02
```

The demo file uses real KEV CVE IDs with invented values for everything else, so row 13, a CVSS 8.8 on a high-criticality asset, ranking below every KEV match shows what the formula does and nothing about real systems. No internal, DHS or CBP data is in the repository.

## The score

```
risk = 100 * ( 0.40*kev + 0.25*(acr/8) + 0.20*epss + 0.20*(cvss/10) ) / 1.05
```

KEV is worth as much as EPSS and CVSS together, so on the same asset a KEV finding never scores below a non-KEV one. Across different assets that does not hold. A list is scored with CVSS on every row or on none, and a mixed list is refused unless you pass `--allow-mixed`. The weights are a design choice with no outcome data behind them.

## More

[Design decisions, evidence, limitations and repository layout](docs/DESIGN_AND_LIMITS.md), [methodology](docs/methodology.md), [real-data analysis](docs/real_data_analysis.md), [how to refresh the snapshot](docs/REFRESHING_SNAPSHOT.md), [changelog](CHANGELOG.md).

## License

MIT, see [LICENSE](LICENSE). The pinned KEV data is CC0 1.0; EPSS data is free to use with attribution requested.
