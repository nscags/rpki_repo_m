import csv
from collections import defaultdict, Counter

with open('rpki_repo_results.csv', newline='') as f:
    reader = csv.DictReader(f)
    rows = list(reader)

# ── Helper ────────────────────────────────────────────────────────────────────

def section(title):
    print(f"\n{'=' * 50}")
    print(f"  {title}")
    print(f"{'=' * 50}")

# ── 1. Overall status ─────────────────────────────────────────────────────────

section("Overall Status")

# IP level — one row per IP (as-is in the CSV)
status_counts_ip = Counter(r['status'] for r in rows)
total_ip = len(rows)

# Hostname level — worst case status per hostname
priority = {"MISCONFIGURED": 4, "NO_ROA": 3, "DNS_FAILED": 2, "INVALID_IP": 1, "OK": 0}
pp_status = {}
for r in rows:
    h, s = r['hostname'], r['status']
    if h not in pp_status:
        pp_status[h] = s  # always set on first encounter
    elif priority.get(s, 0) > priority.get(pp_status[h], 0):
        pp_status[h] = s  # only upgrade to worse status

status_counts_pp = Counter(pp_status.values())
total_pp = len(pp_status)

print(f"\n  {'Status':<25} {'By Hostname (PP)':>18}  {'By IP':>10}")
print(f"  {'-'*57}")
all_statuses = sorted(set(list(status_counts_ip.keys()) + list(status_counts_pp.keys())))
for status in sorted(all_statuses, key=lambda s: -status_counts_ip.get(s, 0)):
    pp_count = status_counts_pp.get(status, 0)
    ip_count = status_counts_ip.get(status, 0)
    print(f"  {status:<25} {pp_count:>6} ({pp_count/total_pp*100:.1f}%)  {ip_count:>6} ({ip_count/total_ip*100:.1f}%)")
print(f"  {'TOTAL':<25} {total_pp:>6}           {total_ip:>6}")

# ── 2. By Trust Anchor ────────────────────────────────────────────────────────

section("By Trust Anchor (ROA source)")
ta_counts = defaultdict(Counter)
for r in rows:
    ta = r.get('roa_ta') or 'N/A'
    ta_counts[ta][r['status']] += 1

for ta, counts in sorted(ta_counts.items()):
    total_ta = sum(counts.values())
    status_str = ', '.join(f"{s}: {c}" for s, c in sorted(counts.items()))
    print(f"  {ta:<15} {total_ta:>4} PPs  ({status_str})")

# ── 3. By ASN ─────────────────────────────────────────────────────────────────

section("By ASN (top 15 by PP count)")
asn_counts = defaultdict(list)
for r in rows:
    asn  = r.get('network_asn') or 'UNKNOWN'
    desc = r.get('network_desc') or ''
    key  = f"AS{asn} {desc}" if asn != 'UNKNOWN' else 'UNKNOWN'
    asn_counts[key].append(r['status'])

for asn, statuses in sorted(asn_counts.items(), key=lambda x: -len(x[1]))[:15]:
    count = len(statuses)
    status_str = ', '.join(f"{s}: {c}" for s, c in sorted(Counter(statuses).items()))
    print(f"  {asn:<45} {count:>3} PPs  ({status_str})")

# ── 4. By prefix length ───────────────────────────────────────────────────────

section("By Prefix Length (ROA-covered PPs only)")
pfx_counts = defaultdict(Counter)
for r in rows:
    if r['status'] in ('OK', 'MISCONFIGURED') and r.get('roa_prefix_len'):
        pfx_len = r['roa_prefix_len']
        pfx_counts[pfx_len][r['status']] += 1

for pfx_len, counts in sorted(pfx_counts.items(), key=lambda x: int(x[0])):
    total_pfx = sum(counts.values())
    status_str = ', '.join(f"{s}: {c}" for s, c in sorted(counts.items()))
    hijack_risk = "subprefix + prefix hijack possible" if int(pfx_len) < 24 else "prefix hijack only"
    print(f"  /{pfx_len:<5} {total_pfx:>4} PPs  ({status_str}) [{hijack_risk}]")

# ── 5. Contact coverage ───────────────────────────────────────────────────────

section("Contact Coverage (for notification)")
has_contact    = sum(1 for r in rows if r.get('best_contact'))
no_contact     = sum(1 for r in rows if not r.get('best_contact'))
vulnerable     = [r for r in rows if r['status'] in ('NO_ROA', 'MISCONFIGURED')]
vuln_contact   = sum(1 for r in vulnerable if r.get('best_contact'))
vuln_no_contact = sum(1 for r in vulnerable if not r.get('best_contact'))

print(f"  All PPs with a contact email:        {has_contact}")
print(f"  All PPs without a contact email:     {no_contact}")
print(f"  Vulnerable PPs with contact email:   {vuln_contact}")
print(f"  Vulnerable PPs without contact email:{vuln_no_contact}")

# ── 6. ROA Prefix Length Breakdown ───────────────────────────────────────────

section("ROA Prefix Length Breakdown")

# Deduplicate by unique prefix
seen = {}
for r in rows:
    p = r.get('roa_prefix')
    if not p:
        continue
    # worst case status wins
    if p not in seen or priority.get(r['status'], 0) > priority.get(seen[p]['status'], 0):
        seen[p] = r

no_roa_prefixes  = [r for r in rows if r['status'] == 'NO_ROA']
roa_prefixes     = list(seen.values())

in_24            = [r for r in roa_prefixes if r.get('roa_prefix_len') == '24']
not_in_24        = [r for r in roa_prefixes if r.get('roa_prefix_len') and int(r['roa_prefix_len']) < 24]
misconfigured    = [r for r in roa_prefixes if r['status'] == 'MISCONFIGURED']
ok_in_24         = [r for r in roa_prefixes if r.get('roa_prefix_len') == '24' and r['status'] == 'OK']

# deduplicate no_roa by unique IP
no_roa_unique = len(set(r['ip'] for r in no_roa_prefixes))

print(f"  Prefixes with no ROA (unique IPs):              {no_roa_unique}")
print(f"  Prefixes with ROA (unique prefixes):            {len(roa_prefixes)}")
print(f"")
print(f"  Of those with a ROA:")
print(f"    Covered by a /24 ROA:                         {len(in_24)}")
print(f"    Covered by a non-/24 ROA (shorter):           {len(not_in_24)}")
print(f"    Misconfigured maxLength:                      {len(misconfigured)}")
print(f"    /24 ROA with correct maxLength (no issue):    {len(ok_in_24)}")