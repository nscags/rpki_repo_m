"""
SIA Multiple Publication Point Checker
---------------------------------------
Parses all RPKI certificates in the Routinator cache and checks
whether any certificates list multiple Publication Points in their
Subject Information Access (SIA) extension.

Logs all SIA fields for every certificate to sia_log.csv for inspection.
"""

import os
import csv
from cryptography import x509

CACHE_DIR  = os.path.expanduser("~/.rpki-cache/repository/")
LOG_CSV    = "sia_log.csv"

# OIDs for SIA access methods
OID_CA_REPOSITORY = "1.3.6.1.5.5.7.48.5"
OID_RPKI_MANIFEST = "1.3.6.1.5.5.7.48.10"
OID_RPKI_NOTIFY   = "1.3.6.1.5.5.7.48.13"

OID_SIA = "1.3.6.1.5.5.7.1.11"  # id-pe-subjectInfoAccessSyntax

ACCESS_METHOD_NAMES = {
    OID_CA_REPOSITORY: "caRepository",
    OID_RPKI_MANIFEST: "rpkiManifest",
    OID_RPKI_NOTIFY:   "rpkiNotify",
}

# ── Walk cache and find all .cer files ────────────────────────────────────────

cert_files = []
for root, dirs, files in os.walk(CACHE_DIR):
    for fname in files:
        if fname.endswith(".cer"):
            cert_files.append(os.path.join(root, fname))

print(f"Found {len(cert_files)} certificates in cache\n")

# ── Parse each certificate and log all SIA fields ────────────────────────────

total_certs          = 0
certs_with_sia       = 0
certs_multi_repo     = 0
certs_multi_notify   = 0
certs_multi_manifest = 0

log_rows       = []  # one row per URI per certificate
multi_examples = []

for cert_path in cert_files:
    try:
        with open(cert_path, "rb") as f:
            data = f.read()
        cert = x509.load_der_x509_certificate(data)
        total_certs += 1
    except Exception as e:
        print(f"  [PARSE ERROR] {cert_path}: {e}")
        continue

    # Try to find SIA extension
    sia_ext = None
    for ext in cert.extensions:
        if ext.oid.dotted_string == OID_SIA:
            sia_ext = ext
            break

    if sia_ext is None:
        log_rows.append({
            "cert_path":          cert_path,
            "has_sia":            "NO",
            "access_method":      "",
            "access_method_name": "",
            "uri":                "",
            "multi_repo":         "",
            "multi_notify":       "",
            "multi_manifest":     "",
        })
        continue

    certs_with_sia += 1

    # Group URIs by access method OID
    by_method = {}
    for access_desc in sia_ext.value:
        oid = access_desc.access_method.dotted_string
        uri = access_desc.access_location.value
        by_method.setdefault(oid, []).append(uri)

    repo_uris     = by_method.get(OID_CA_REPOSITORY, [])
    notify_uris   = by_method.get(OID_RPKI_NOTIFY, [])
    manifest_uris = by_method.get(OID_RPKI_MANIFEST, [])

    has_multi_repo     = len(repo_uris) > 1
    has_multi_notify   = len(notify_uris) > 1
    has_multi_manifest = len(manifest_uris) > 1

    if has_multi_repo:
        certs_multi_repo += 1
    if has_multi_notify:
        certs_multi_notify += 1
    if has_multi_manifest:
        certs_multi_manifest += 1

    if (has_multi_repo or has_multi_notify or has_multi_manifest) and len(multi_examples) < 10:
        multi_examples.append({
            "cert":      cert_path,
            "repos":     repo_uris,
            "notify":    notify_uris,
            "manifests": manifest_uris,
        })

    # Log one row per URI for this cert
    for oid, uris in by_method.items():
        for uri in uris:
            log_rows.append({
                "cert_path":          cert_path,
                "has_sia":            "YES",
                "access_method":      oid,
                "access_method_name": ACCESS_METHOD_NAMES.get(oid, "other"),
                "uri":                uri,
                "multi_repo":         "YES" if has_multi_repo else "NO",
                "multi_notify":       "YES" if has_multi_notify else "NO",
                "multi_manifest":     "YES" if has_multi_manifest else "NO",
            })

# ── Save log to CSV ───────────────────────────────────────────────────────────

with open(LOG_CSV, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=[
        "cert_path", "has_sia", "access_method", "access_method_name",
        "uri", "multi_repo", "multi_notify", "multi_manifest"
    ])
    writer.writeheader()
    writer.writerows(log_rows)

print(f"SIA fields for all certificates saved to: {LOG_CSV}\n")

# ── Print summary ─────────────────────────────────────────────────────────────

def pct(n):
    return f"({n/certs_with_sia*100:.1f}% of certs with SIA)" if certs_with_sia else ""

print("=" * 60)
print("SIA Multiple Publication Point Analysis")
print("=" * 60)
print(f"  Total certificates parsed:               {total_certs}")
print(f"  Certificates with SIA extension:         {certs_with_sia}")
print(f"  Certs with multiple caRepository URIs:   {certs_multi_repo} {pct(certs_multi_repo)}")
print(f"  Certs with multiple rpkiNotify URIs:     {certs_multi_notify} {pct(certs_multi_notify)}")
print(f"  Certs with multiple rpkiManifest URIs:   {certs_multi_manifest} {pct(certs_multi_manifest)}")

if multi_examples:
    print(f"\n--- Example certificates with multiple URIs (up to 10) ---")
    for ex in multi_examples:
        print(f"\n  Cert: {ex['cert']}")
        if len(ex['repos']) > 1:
            print(f"  caRepository URIs ({len(ex['repos'])}):")
            for u in ex['repos']:
                print(f"    {u}")
        if len(ex['notify']) > 1:
            print(f"  rpkiNotify URIs ({len(ex['notify'])}):")
            for u in ex['notify']:
                print(f"    {u}")
        if len(ex['manifests']) > 1:
            print(f"  rpkiManifest URIs ({len(ex['manifests'])}):")
            for u in ex['manifests']:
                print(f"    {u}")
else:
    print("\n  No certificates with multiple URIs found.")

print()
print("=" * 60)
print(f"Full SIA log saved to: {LOG_CSV}")