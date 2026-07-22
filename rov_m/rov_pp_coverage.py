#!/usr/bin/env python3
"""
ROV Adoption Coverage of RPKI Publication Points
--------------------------------------------------
Checks what percentage of RPKI Publication Point (PP) hostnames are hosted
within ASes that have adopted Route Origin Validation (ROV).

ROV adoption data is collected via rov_collector (multiple measurement datasets).
Two thresholds are reported:

  Strict: max_percent == 100 across all datasets that cover the ASN
          (every source agrees the AS fully adopts ROV)
  Loose:  max_percent  > 0  (at least one dataset reports any ROV adoption)

PP hostname → ASN data comes from rpki_repo_results.csv (produced by analyze_repos.py).
"""

import csv
import json
import os
from collections import defaultdict
from pathlib import Path

from rov_collector import rov_collector_classes

ROV_JSON       = Path(__file__).parent / "rov_info.json"
REPO_RESULTS   = Path(__file__).parent.parent / "roa_m" / "rpki_repo_results.csv"
CACHE_DB       = None   # set to a Path to cache HTTP requests between runs


# ── 1. Collect ROV data ───────────────────────────────────────────────────────

if not ROV_JSON.exists():
    print("Collecting ROV adoption data (this may take a minute)...")
    for CollectorCls in rov_collector_classes:
        print(f"  Running {CollectorCls.__name__}...")
        try:
            CollectorCls(
                json_path=ROV_JSON,
                requests_cache_db_path=CACHE_DB,
            ).run()
        except Exception as e:
            print(f"    WARNING: {CollectorCls.__name__} failed ({e}) — skipping")
    print(f"  Saved to {ROV_JSON}")
else:
    print(f"Using cached ROV data from {ROV_JSON}")

with ROV_JSON.open() as f:
    rov_data = json.load(f)   # {asn_str: [{source, percent, ...}, ...]}

print(f"  {len(rov_data)} ASNs with ROV data\n")


# ── 2. Build strict and loose ROV ASN sets ────────────────────────────────────

strict_rov = set()   # max_percent == 100 across all covering datasets
loose_rov  = set()   # max_percent  > 0

for asn_str, info_list in rov_data.items():
    asn = int(asn_str)
    max_pct = max(float(info["percent"]) for info in info_list)
    if max_pct > 0:
        loose_rov.add(asn)
    if max_pct == 100:
        strict_rov.add(asn)

print(f"ROV adoption sets:")
print(f"  Strict (max_percent == 100): {len(strict_rov):>6} ASNs")
print(f"  Loose  (max_percent  > 0):   {len(loose_rov):>6} ASNs\n")


# ── 3. Load PP hostname → ASN from rpki_repo_results.csv ─────────────────────

# One row per (hostname, IP) pair — deduplicate to one ASN per hostname.
# If a hostname resolves to multiple IPs in different ASes, use the first found.
hostname_asn = {}   # hostname -> int ASN (or None)

with open(REPO_RESULTS, newline="") as f:
    for row in csv.DictReader(f):
        host = row["hostname"].strip()
        asn_str = row.get("network_asn", "").strip()
        if host and host not in hostname_asn:
            hostname_asn[host] = int(asn_str) if asn_str else None

total_pps    = len(hostname_asn)
resolved_pps = sum(1 for a in hostname_asn.values() if a is not None)
print(f"PP hostnames loaded: {total_pps} total, {resolved_pps} with a resolved ASN\n")


# ── 4. Cross-reference ────────────────────────────────────────────────────────

def coverage(rov_set, label):
    in_rov       = []
    not_in_rov   = []
    unresolved   = []

    for host, asn in hostname_asn.items():
        if asn is None:
            unresolved.append(host)
        elif asn in rov_set:
            in_rov.append((host, asn))
        else:
            not_in_rov.append((host, asn))

    denom = len(in_rov) + len(not_in_rov)   # exclude unresolved from %
    pct   = len(in_rov) / denom * 100 if denom else 0

    print(f"  {label}")
    print(f"  {'PPs in ROV ASes:':<30} {len(in_rov):>4}  ({pct:.1f}% of resolved PPs)")
    print(f"  {'PPs NOT in ROV ASes:':<30} {len(not_in_rov):>4}  ({100-pct:.1f}%)")
    print(f"  {'PPs unresolved (no ASN):':<30} {len(unresolved):>4}")
    print()

    # if in_rov:
    #     print(f"    PPs hosted in ROV-adopting ASes:")
    #     for host, asn in sorted(in_rov, key=lambda x: x[0]):
    #         print(f"      AS{asn:<8}  {host}")
    # print()

    return in_rov, not_in_rov, unresolved


OUTPUT_CSV = Path(__file__).parent / "rov_pp_coverage.csv"

print("=" * 65)
print("ROV Adoption Coverage of RPKI Publication Points")
print("=" * 65)
print()

strict_in, strict_out, strict_unres = coverage(strict_rov, "STRICT  (max_percent == 100 — full adoption confirmed by all sources)")
loose_in,  loose_out,  loose_unres  = coverage(loose_rov,  "LOOSE   (max_percent  > 0   — any ROV signal in any dataset)")

# ── 5. Save results ───────────────────────────────────────────────────────────

rows = []
for host, asn in hostname_asn.items():
    strict = asn in strict_rov if asn is not None else None
    loose  = asn in loose_rov  if asn is not None else None
    rows.append({
        "hostname":     host,
        "asn":          asn or "",
        "rov_strict":   "" if asn is None else ("YES" if strict else "NO"),
        "rov_loose":    "" if asn is None else ("YES" if loose  else "NO"),
    })

rows.sort(key=lambda r: r["hostname"])

with open(OUTPUT_CSV, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["hostname", "asn", "rov_strict", "rov_loose"])
    writer.writeheader()
    writer.writerows(rows)

print(f"Full results saved to: {OUTPUT_CSV}")
