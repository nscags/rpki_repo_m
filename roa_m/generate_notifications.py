"""
Generates notification_contacts.csv — one row per unique (best_contact, status)
with all affected publication points consolidated, ready for email composition.
Only includes NO_ROA and MISCONFIGURED rows with a best_contact address.
"""

import csv
from collections import defaultdict

INPUT_CSV  = "rpki_repo_results.csv"
OUTPUT_CSV = "notification_contacts.csv"

with open(INPUT_CSV, newline="") as f:
    rows = list(csv.DictReader(f))

# Group by (best_contact, status) — keeps NO_ROA and MISCONFIGURED separate
# since they get different email templates
groups = defaultdict(list)

for r in rows:
    status  = r["status"]
    contact = r.get("best_contact", "").strip()

    if status not in ("NO_ROA", "MISCONFIGURED"):
        continue
    if not contact:
        print(f"  WARNING: no best_contact for {r['hostname']} ({status}) — skipped")
        continue

    groups[(contact, status)].append(r)

# Build output rows
output = []

for (contact, status), members in sorted(groups.items()):

    # Deduplicate by hostname (multiple IPs per host → one PP entry per host)
    seen_hosts = {}
    for r in members:
        h = r["hostname"]
        if h not in seen_hosts:
            seen_hosts[h] = r

    hostnames   = []
    ips         = []
    asns        = []
    prefixes    = []
    max_lengths = []

    for h, r in seen_hosts.items():
        hostnames.append(h)
        ips.append(r["ip"])

        if status == "MISCONFIGURED":
            asn    = r.get("roa_asn", r.get("network_asn", ""))
            prefix = r.get("roa_prefix", r["ip"])
            max_lengths.append(r.get("roa_max_length", ""))
        else:  # NO_ROA — no ROA prefix exists, use IP and network ASN
            asn    = r.get("network_asn", "")
            prefix = r["ip"]

        asns.append(f"AS{asn}" if asn else "")
        prefixes.append(prefix)

    if status == "MISCONFIGURED":
        pp_block = (
            f"  Domain:      {', '.join(hostnames)}\n"
            f"  ROA Prefix:  {', '.join(prefixes)}\n"
            f"  Max Length:  {', '.join(max_lengths)}\n"
            f"  ASN:         {', '.join(a for a in asns if a)}"
        )
    else:
        pp_block = (
            f"  Domain:  {', '.join(hostnames)}\n"
            f"  Prefix:  {', '.join(prefixes)}\n"
            f"  ASN:     {', '.join(a for a in asns if a)}"
        )

    output.append({
        "status":        status,
        "best_contact":  contact,
        "hostnames":     ", ".join(hostnames),
        "ips":           ", ".join(ips),
        "asns":          ", ".join(a for a in asns if a),
        "prefixes":      ", ".join(prefixes),
        "max_lengths":   ", ".join(max_lengths) if max_lengths else "",
        "pp_block":      pp_block,
    })

fieldnames = ["status", "best_contact", "hostnames", "ips", "asns", "prefixes", "max_lengths", "pp_block"]

with open(OUTPUT_CSV, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(output)

# Summary
no_roa_count  = sum(1 for o in output if o["status"] == "NO_ROA")
misc_count    = sum(1 for o in output if o["status"] == "MISCONFIGURED")
skipped       = sum(1 for r in rows if r["status"] in ("NO_ROA", "MISCONFIGURED")
                    and not r.get("best_contact", "").strip())

print(f"Notification recipients:")
print(f"  NO_ROA emails to send:        {no_roa_count}")
print(f"  MISCONFIGURED emails to send: {misc_count}")
print(f"  Skipped (no contact found):   {skipped}")
print(f"\nSaved to {OUTPUT_CSV}")
