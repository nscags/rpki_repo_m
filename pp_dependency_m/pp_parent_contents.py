#!/usr/bin/env python3
"""
Parent PP Contents Analysis
-----------------------------
For each resource certificate in the RPKI cache, checks whether the parent
Publication Point (PP) directory — the directory where the certificate is
physically stored — contains only resource certificates or also co-locates ROAs.

Method:
  1. Scan all RPKI objects from Routinator's local cache (rsync files and RRDP
     packed .bin snapshots). For each object URI, record the file extension
     present in its directory, and collect every .cer URI found.
  2. For each certificate, derive its parent PP directory by stripping the
     filename from its URI.
  3. Check whether that directory contains any .roa files alongside the .cer.

Output:
  pp_parent_contents.csv  — one row per certificate with parent dir and result
"""

import csv
import glob
import os
import struct
import sys
from collections import defaultdict

RSYNC_CACHE  = os.path.expanduser("~/.rpki-cache/repository/rsync")
RRDP_CACHE   = os.path.expanduser("~/.rpki-cache/repository/rrdp")
RSYNC_PREFIX = "rsync://"
OUTPUT_CSV   = os.path.join(os.path.dirname(__file__), "pp_parent_contents.csv")


# ── 1. Scan all objects: build dir→extensions map and collect .cer URIs ───────

dir_exts = defaultdict(set)   # rsync directory URI -> set of extensions present
cer_uris  = []                 # all .cer URIs found

def record(uri):
    filename = uri.rsplit("/", 1)[-1]
    ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else ".other"
    parent_dir = uri.rsplit("/", 1)[0] + "/"
    dir_exts[parent_dir].add(ext)
    if ext == ".cer":
        cer_uris.append(uri)


print("Scanning rsync cache...", flush=True)
rsync_count = 0
for path in glob.glob(os.path.join(RSYNC_CACHE, "**", "*.*"), recursive=True):
    if os.path.isfile(path):
        rel = os.path.relpath(path, RSYNC_CACHE).replace(os.sep, "/")
        record(RSYNC_PREFIX + rel)
        rsync_count += 1
print(f"  {rsync_count} objects")

bin_files = glob.glob(os.path.join(RRDP_CACHE, "*", "*.bin"))
print(f"Scanning {len(bin_files)} RRDP .bin files...", flush=True)
rrdp_count = 0

for bin_path in bin_files:
    host = os.path.basename(os.path.dirname(bin_path))
    sys.stdout.write(f"\r  {host:<55}"); sys.stdout.flush()

    data = open(bin_path, "rb").read()
    search_from = 0

    while True:
        idx = data.find(b"rsync://", search_from)
        if idx == -1:
            break
        if idx < 16:
            search_from = idx + 1
            continue

        uri_len = struct.unpack_from("<Q", data, idx - 16)[0]
        der_len = struct.unpack_from("<Q", data, idx - 8)[0]

        if not (8 < uri_len <= 512 and 128 <= der_len <= 20_000_000):
            search_from = idx + 1
            continue

        uri_end   = idx + uri_len
        der_start = uri_end + 32

        if der_start + der_len > len(data):
            search_from = idx + 1
            continue

        uri_bytes = data[idx:uri_end]
        if not all(32 <= b < 127 for b in uri_bytes):
            search_from = idx + 1
            continue

        if data[der_start] != 0x30:
            search_from = idx + 1
            continue

        record(uri_bytes.decode("ascii"))
        rrdp_count += 1
        search_from = der_start + der_len

print(f"\r  Done — {rrdp_count} objects from RRDP{' ' * 30}")
print(f"  Directories indexed: {len(dir_exts)}")
print(f"  Certificates found:  {len(cer_uris)}")


# ── 2. Classify each certificate by its parent directory's contents ───────────

print("\nClassifying certificates...", flush=True)

results   = []
cert_only = 0
has_roa   = 0

for uri in cer_uris:
    parent_dir = uri.rsplit("/", 1)[0] + "/"
    exts = dir_exts.get(parent_dir, set())

    if ".roa" in exts:
        classification = "CERT_AND_ROA"
        has_roa += 1
    else:
        classification = "CERT_ONLY"
        cert_only += 1

    results.append({
        "cert_uri":       uri,
        "parent_pp":      parent_dir,
        "classification": classification,
    })


# ── 3. Save and print results ─────────────────────────────────────────────────

with open(OUTPUT_CSV, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["cert_uri", "parent_pp", "classification"])
    writer.writeheader()
    writer.writerows(results)

total = len(results)
print()
print("=" * 65)
print("Parent PP Contents Analysis")
print("=" * 65)
print(f"  Total certificates:                           {total}")
print()
print(f"  CERT_ONLY    (parent dir has no ROAs):  {cert_only:>7}  ({cert_only/total*100:.1f}%)")
print(f"  CERT_AND_ROA (parent dir also has ROAs):{has_roa:>7}  ({has_roa/total*100:.1f}%)")
print()
print(f"Full results saved to: {OUTPUT_CSV}")
