#!/usr/bin/env python3
"""
Hybrid RPKI Deployment Measurement
------------------------------------
Determines whether RPKI delegations follow the standard model or the hybrid
model by comparing the rpkiNotify URIs of parent and child certificates.

Standard model: child cert's rpkiNotify differs from parent's → child has
                its own independent Publication Point.
Hybrid model:   child cert's rpkiNotify matches parent's → child publishes
                its objects at the parent's PP rather than its own.

Method:
  1. Collect all resource certificates from the Routinator cache
     (rsync files + RRDP packed snapshots).
  2. Parse each cert and extract:
       - Subject Key Identifier (SKI)  — used as the cert's unique key
       - Authority Key Identifier (AKI) — points to the parent cert
       - rpkiNotify URI from SIA       — identifies the cert holder's PP
  3. Build a SKI → cert-info index, then for each cert look up its parent
     by AKI → SKI.
  4. Compare parent rpkiNotify vs child rpkiNotify:
       same URL   → hybrid (child uses parent's PP)
       different  → standard (child has own PP)
       missing    → rsync-only PP (no RRDP, classified separately)
"""

import struct
import glob
import os
import sys
import csv
from collections import defaultdict, Counter
from urllib.parse import urlparse
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

RSYNC_CACHE  = os.path.expanduser("~/.rpki-cache/repository/rsync")
TA_CACHE     = os.path.expanduser("~/.rpki-cache/repository/stored/ta")
RRDP_CACHE   = os.path.expanduser("~/.rpki-cache/repository/rrdp")
RSYNC_PREFIX = "rsync://"
OUTPUT_CSV   = "hybrid_results.csv"

OID_CA_REPOSITORY = x509.ObjectIdentifier("1.3.6.1.5.5.7.48.5")
OID_RPKI_NOTIFY   = x509.ObjectIdentifier("1.3.6.1.5.5.7.48.13")


# ── Cert store: SKI (hex) → cert info ────────────────────────────────────────

cert_store = {}   # ski_hex -> dict

def parse_cert(der_bytes, source_uri):
    """Parse a DER cert and store its info indexed by SKI."""
    try:
        cert = x509.load_der_x509_certificate(der_bytes)
    except Exception:
        return

    # SKI — required in all RPKI resource certs
    try:
        ski = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        ).value.digest.hex()
    except x509.ExtensionNotFound:
        return

    # AKI — absent only in self-signed TA certs
    try:
        aki = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        ).value.key_identifier.hex()
    except x509.ExtensionNotFound:
        aki = None   # self-signed TA

    # SIA: rpkiNotify and caRepository
    rpki_notify    = None
    ca_repository  = None
    try:
        sia = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_INFORMATION_ACCESS
        )
        for desc in sia.value:
            if desc.access_method == OID_RPKI_NOTIFY:
                rpki_notify = desc.access_location.value
            elif desc.access_method == OID_CA_REPOSITORY:
                ca_repository = desc.access_location.value
    except x509.ExtensionNotFound:
        pass

    cert_store[ski] = {
        "ski":           ski,
        "aki":           aki,
        "rpki_notify":   rpki_notify,
        "ca_repository": ca_repository,
        "subject":       cert.subject.rfc4514_string(),
        "issuer":        cert.issuer.rfc4514_string(),
        "source_uri":    source_uri,
    }


# ── 1. rsync cache ────────────────────────────────────────────────────────────
print("Scanning rsync cache...", flush=True)
rsync_cers = glob.glob(os.path.join(RSYNC_CACHE, "**", "*.cer"), recursive=True)
for path in rsync_cers:
    rel      = os.path.relpath(path, RSYNC_CACHE).replace(os.sep, "/")
    cert_uri = RSYNC_PREFIX + rel
    parse_cert(open(path, "rb").read(), cert_uri)
print(f"  {len(rsync_cers)} files processed")

# ── 2. TA certificates ────────────────────────────────────────────────────────
print("Scanning TA store...", flush=True)
ta_cers = glob.glob(os.path.join(TA_CACHE, "**", "*.cer"), recursive=True)
for path in ta_cers:
    parse_cert(open(path, "rb").read(), path)
print(f"  {len(ta_cers)} files processed")

# ── 3. RRDP packed snapshots ──────────────────────────────────────────────────
bin_files = glob.glob(os.path.join(RRDP_CACHE, "*", "*.bin"))
print(f"Scanning {len(bin_files)} RRDP .bin files...", flush=True)
before = len(cert_store)

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

        if uri_bytes.endswith(b".cer"):
            parse_cert(data[der_start:der_start + der_len],
                       uri_bytes.decode("ascii"))

        search_from = der_start + der_len

print(f"\r  Done — {len(cert_store) - before} new certs from RRDP{' ' * 30}")
print(f"  Total certs indexed: {len(cert_store)}")


# ── Build parent-child pairs and classify ─────────────────────────────────────

print("\nBuilding parent-child pairs...", flush=True)

results     = []
counts      = defaultdict(int)

for ski, child in cert_store.items():
    aki = child["aki"]

    # Skip self-signed TA certs (no AKI)
    if aki is None:
        continue

    # Look up parent by AKI → parent's SKI
    parent = cert_store.get(aki)
    if parent is None:
        counts["parent_not_found"] += 1
        continue

    child_notify  = child["rpki_notify"]
    parent_notify = parent["rpki_notify"]

    if child_notify is None and parent_notify is None:
        classification = "RSYNC_ONLY"
    elif child_notify is None or parent_notify is None:
        classification = "MIXED_PROTOCOL"
    elif child_notify == parent_notify:
        classification = "HYBRID"
    else:
        classification = "STANDARD"

    counts[classification] += 1
    results.append({
        "child_uri":      child["source_uri"],
        "child_subject":  child["subject"],
        "child_notify":   child_notify or "",
        "parent_uri":     parent["source_uri"],
        "parent_subject": parent["subject"],
        "parent_notify":  parent_notify or "",
        "classification": classification,
    })


# ── Save results ──────────────────────────────────────────────────────────────

with open(OUTPUT_CSV, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=[
        "child_uri", "child_subject", "child_notify",
        "parent_uri", "parent_subject", "parent_notify",
        "classification"
    ])
    writer.writeheader()
    writer.writerows(results)


# ── Print summary ─────────────────────────────────────────────────────────────

LABEL_DESC = {
    "HYBRID":   "child shares parent's PP (same rpkiNotify)",
    "STANDARD": "child has own PP (different rpkiNotify)",
}

total_pairs = sum(counts[k] for k in ["HYBRID", "STANDARD"])


def print_breakdown(title, counter, total):
    print(f"\n  {title}")
    print(f"  {'Label':<16} {'Count':>7}   {'%':>6}   Description")
    print("  " + "-" * 72)
    for label in ["HYBRID", "STANDARD"]:
        n = counter.get(label, 0)
        pct = n / total * 100 if total else 0
        print(f"  {label:<16} {n:>7}  ({pct:5.1f}%)  — {LABEL_DESC[label]}")
    print(f"  {'Total':<16} {total:>7}")


# ── 1. Per certificate ────────────────────────────────────────────────────────

print()
print("=" * 75)
print("Hybrid RPKI Deployment Measurement")
print("=" * 75)
print(f"  Total certs indexed:                     {len(cert_store)}")
print(f"  Parent cert not found (incomplete cache):{counts['parent_not_found']:>7}")
print(f"  Total classifiable pairs:                {total_pairs}")

print_breakdown("Per certificate", counts, total_pairs)


# ── 2. Per unique rpkiNotify URL ──────────────────────────────────────────────

def is_hybrid(classifications):
    """True only if every cert pair at this URL/host was HYBRID."""
    return classifications == {"HYBRID"}

url_classes = defaultdict(set)
for r in results:
    url = r["child_notify"] or "__none__"
    url_classes[url].add(r["classification"])

url_counter = Counter("HYBRID" if is_hybrid(v) else "STANDARD" for v in url_classes.values())
total_urls = len(url_classes)

print_breakdown("Per unique child rpkiNotify URL", url_counter, total_urls)


# ── 3. Per hostname (PP) ──────────────────────────────────────────────────────

host_classes = defaultdict(set)
for r in results:
    url  = r["child_notify"]
    host = urlparse(url).hostname if url else "__none__"
    host_classes[host].add(r["classification"])

host_counter = Counter("HYBRID" if is_hybrid(v) else "STANDARD" for v in host_classes.values())
total_hosts = len(host_classes)

print_breakdown("Per hostname (Publication Point)", host_counter, total_hosts)

# Per-hostname detail table (HYBRID hosts only)
print(f"\n  {'Hostname':<45} {'HYBRID certs':>12}")
print("  " + "-" * 59)
host_cert_counts = defaultdict(Counter)
for r in results:
    url  = r["child_notify"]
    host = urlparse(url).hostname if url else "__none__"
    host_cert_counts[host][r["classification"]] += 1

for host, cnt in sorted(host_cert_counts.items(), key=lambda x: -x[1]["HYBRID"]):
    if not is_hybrid(set(cnt.keys())):
        continue
    print(f"  {host:<45} {cnt['HYBRID']:>12}")

print()
print(f"Full results saved to: {OUTPUT_CSV}")
