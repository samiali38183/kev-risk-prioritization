#!/usr/bin/env python3
"""Build (or verify) the pinned real-data snapshot under data/snapshot/. Standard library only.

Sources (both free to use; see data/snapshot/SNAPSHOT.md for terms):
  * CISA KEV catalog JSON   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  * FIRST EPSS daily scores https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz

Outputs (in --out):
  known_exploited_vulnerabilities.json   the raw KEV download, byte for byte
  epss_subset.csv                        EPSS rows for every KEV CVE plus a seeded sample of non-KEV CVEs
  SNAPSHOT.json                          source URLs, SHA-256 of the raw downloads, counts, full-population stats

Typical use:
  python scripts/fetch_snapshot.py --date 2026-11-11            # download and write
  python scripts/fetch_snapshot.py --date 2026-11-11 --kev-file K.json --epss-file E.csv.gz --check
                                                                # rebuild from local raw files and compare

Note: cisa.gov serves only the CURRENT KEV catalog, so a later download will differ from the committed
one. The committed KEV JSON is the pin; --check against local raw files is the reproducible path.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import sys
import urllib.request
from typing import Dict, List, Optional, Tuple

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL_TEMPLATE = "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz"
USER_AGENT = "kev-risk-prioritization-snapshot/0.2"
DEFAULT_SEED = "kev-risk-prioritization-2026-11-11"
DEFAULT_SAMPLE_SIZE = 5000
THRESHOLDS = (0.1, 0.5, 0.9)
KEV_NAME = "known_exploited_vulnerabilities.json"
SUBSET_NAME = "epss_subset.csv"
META_NAME = "SNAPSHOT.json"

Row = Tuple[str, str, str]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 - fixed https URLs
        return resp.read()


def parse_epss(raw_gz: bytes) -> Tuple[Dict[str, str], List[Row]]:
    """Return (header comment fields, rows of (cve, epss, percentile) as the original strings)."""
    text = gzip.decompress(raw_gz).decode("utf-8")
    lines = text.splitlines()
    meta: Dict[str, str] = {}
    if lines and lines[0].startswith("#"):
        for part in lines[0][1:].split(","):
            if ":" in part:
                k, v = part.split(":", 1)
                meta[k.strip()] = v.strip()
        lines = lines[1:]
    rows: List[Row] = []
    reader = csv.reader(io.StringIO("\n".join(lines)))
    header = next(reader)
    if [h.strip().lower() for h in header] != ["cve", "epss", "percentile"]:
        raise ValueError("unexpected EPSS header: %r" % header)
    for r in reader:
        if r:
            rows.append((r[0].strip().upper(), r[1], r[2]))
    return meta, rows


def sample_key(seed: str, cve: str) -> str:
    """Deterministic, Python-version-independent sampling key (no random module)."""
    return hashlib.sha256(("%s:%s" % (seed, cve)).encode("utf-8")).hexdigest()


def build_subset(rows: List[Row], kev_ids: set, seed: str, sample_size: int):
    """KEV rows + the `sample_size` non-KEV rows with the smallest sample_key. Sorted by CVE ID."""
    kev_rows = [r for r in rows if r[0] in kev_ids]
    non_kev = [r for r in rows if r[0] not in kev_ids]
    ordered = sorted(non_kev, key=lambda r: sample_key(seed, r[0]))
    sampled = ordered[:sample_size]
    out = [(c, e, p, "1") for c, e, p in kev_rows] + [(c, e, p, "0") for c, e, p in sampled]
    out.sort(key=lambda r: r[0])
    return out, kev_rows, non_kev


def subset_csv_bytes(subset) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["cve", "epss", "percentile", "in_kev"])
    w.writerows(subset)
    return buf.getvalue().encode("utf-8")


def population_stats(kev_rows: List[Row], non_kev_rows: List[Row]) -> Dict[str, Dict[str, int]]:
    stats: Dict[str, Dict[str, int]] = {}
    for t in THRESHOLDS:
        stats["%g" % t] = {
            "kev_ge": sum(1 for r in kev_rows if float(r[1]) >= t),
            "non_kev_ge": sum(1 for r in non_kev_rows if float(r[1]) >= t),
        }
    return stats


def build(kev_raw: bytes, epss_raw: bytes, epss_url: str, seed: str, sample_size: int,
          retrieved: str) -> Tuple[dict, bytes]:
    kev = json.loads(kev_raw.decode("utf-8"))
    kev_ids = {v["cveID"].strip().upper() for v in kev["vulnerabilities"]}
    epss_meta, rows = parse_epss(epss_raw)
    subset, kev_rows, non_kev = build_subset(rows, kev_ids, seed, sample_size)
    missing = sorted(kev_ids - {r[0] for r in rows})
    sub_bytes = subset_csv_bytes(subset)
    meta = {
        "retrieved_utc": retrieved,
        "kev": {
            "url": KEV_URL,
            "file": KEV_NAME,
            "sha256": sha256_hex(kev_raw),
            "bytes": len(kev_raw),
            "catalogVersion": kev.get("catalogVersion"),
            "dateReleased": kev.get("dateReleased"),
            "count": kev.get("count"),
            "unique_cve_ids": len(kev_ids),
            "license": "CC0 1.0 (https://www.cisa.gov/sites/default/files/licenses/kev/license.txt)",
        },
        "epss": {
            "url": epss_url,
            "raw_file": os.path.basename(epss_url),
            "raw_sha256": sha256_hex(epss_raw),
            "raw_bytes": len(epss_raw),
            "model_version": epss_meta.get("model_version"),
            "score_date": epss_meta.get("score_date"),
            "rows_total": len(rows),
            "terms": "Free to use, no registration; attribution requested (https://www.first.org/epss/faq)",
        },
        "subset": {
            "file": SUBSET_NAME,
            "sha256": sha256_hex(sub_bytes),
            "rows": len(subset),
            "kev_rows": len(kev_rows),
            "non_kev_sampled": len(subset) - len(kev_rows),
            "non_kev_population": len(non_kev),
            "kev_ids_missing_from_epss": missing,
            "sampling": "non-KEV CVEs ordered by sha256('<seed>:<CVE>'), first N kept",
            "seed": seed,
            "sample_size": sample_size,
        },
        "population_stats": population_stats(kev_rows, non_kev),
    }
    return meta, sub_bytes


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    p.add_argument("--date", required=True, help="EPSS score date, YYYY-MM-DD")
    p.add_argument("--out", default=os.path.join("data", "snapshot"))
    p.add_argument("--kev-file", help="use this local raw KEV JSON instead of downloading")
    p.add_argument("--epss-file", help="use this local raw EPSS .csv.gz instead of downloading")
    p.add_argument("--seed", default=DEFAULT_SEED)
    p.add_argument("--sample-size", type=int, default=DEFAULT_SAMPLE_SIZE)
    p.add_argument("--check", action="store_true", help="compare against existing files in --out, write nothing")
    args = p.parse_args(argv)

    dt.date.fromisoformat(args.date)  # validates the format
    epss_url = EPSS_URL_TEMPLATE.format(date=args.date)
    if args.kev_file:
        with open(args.kev_file, "rb") as fh:
            kev_raw = fh.read()
    else:
        kev_raw = download(KEV_URL)
    if args.epss_file:
        with open(args.epss_file, "rb") as fh:
            epss_raw = fh.read()
    else:
        epss_raw = download(epss_url)

    retrieved = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    if args.check:
        with open(os.path.join(args.out, META_NAME), encoding="utf-8") as fh:
            retrieved = json.load(fh)["retrieved_utc"]
    meta, subset_bytes = build(kev_raw, epss_raw, epss_url, args.seed, args.sample_size, retrieved)
    meta_bytes = (json.dumps(meta, indent=2, sort_keys=True) + "\n").encode("utf-8")

    wanted = {KEV_NAME: kev_raw, SUBSET_NAME: subset_bytes, META_NAME: meta_bytes}
    if args.check:
        bad = []
        for name, data in wanted.items():
            with open(os.path.join(args.out, name), "rb") as fh:
                if fh.read() != data:
                    bad.append(name)
        if bad:
            print("MISMATCH: " + ", ".join(bad), file=sys.stderr)
            return 1
        print("snapshot matches (%d files)" % len(wanted))
        return 0
    os.makedirs(args.out, exist_ok=True)
    for name, data in wanted.items():
        with open(os.path.join(args.out, name), "wb") as fh:
            fh.write(data)
    print("wrote %s: KEV %s (%s entries), EPSS %s, subset rows %d"
          % (args.out, meta["kev"]["catalogVersion"], meta["kev"]["count"],
             meta["epss"]["score_date"], meta["subset"]["rows"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
