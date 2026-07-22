"""
RPKI Repository Analysis
------------------------
1. Extracts hostnames from Routinator cache
2. Resolves hostnames to IP addresses
3. RDAP lookup per IP (network ASN, description, abuse/tech emails)
4. Loads VRPs from Routinator output
5. For each repository IP:
   - Checks if a ROA exists
   - If ROA exists, checks if maxLength is correctly configured (RFC 9319)
6. Saves full results to CSV and prints summary stats
"""

import os
import socket
import csv
import time
from collections import defaultdict
from ipaddress import ip_network, ip_address

from ipwhois import IPWhois

# ── Configuration ─────────────────────────────────────────────────────────────

CACHE_DIR  = os.path.expanduser("~/.rpki-cache/repository/")
VRPS_FILE  = "rpki_vrps.csv"
OUTPUT_CSV = "rpki_repo_results.csv"

RDAP_DELAY    = 0.5   # seconds between RDAP calls
CONTACT_ROLES = {"abuse", "technical", "admin"}

# ── 1. Extract hostnames from Routinator cache ────────────────────────────────

print("[1/5] Extracting hostnames from Routinator cache...")

rrdp_dir  = os.path.join(CACHE_DIR, "rrdp")
rsync_dir = os.path.join(CACHE_DIR, "rsync")

hostnames = set()
for directory in [rrdp_dir, rsync_dir]:
    if os.path.isdir(directory):
        for entry in os.listdir(directory):
            if entry == "tmp":
                continue
            if os.path.isdir(os.path.join(directory, entry)):
                hostnames.add(entry)

hostnames = sorted(hostnames)
print(f"      → found {len(hostnames)} unique hostnames")

# ── 2. Resolve hostnames to IPs ───────────────────────────────────────────────

print("[2/5] Resolving hostnames to IP addresses...")

repo_ips = []  # list of (hostname, ip) -- ip is None if resolution failed
failed   = 0

for host in hostnames:
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        ips = sorted(set(info[4][0] for info in infos))
        for ip in ips:
            repo_ips.append((host, ip))
    except socket.gaierror:
        repo_ips.append((host, None))
        failed += 1

resolved = sum(1 for _, ip in repo_ips if ip is not None)
print(f"      → Resolved: {resolved}  |  Failed: {failed}")

# ── 3. RDAP lookup per unique IP ──────────────────────────────────────────────

print("[3/5] Running RDAP lookups (this may take a minute)...")

def extract_emails(rdap):
    """Return {role: email} for abuse/technical/admin contacts."""
    emails = {}
    for obj in rdap.get("objects", {}).values():
        roles = set(obj.get("roles", []))
        matched = roles & CONTACT_ROLES
        if not matched:
            continue
        for entry in obj.get("contact", {}).get("email", []):
            addr = entry.get("value", "").strip()
            if addr:
                for role in matched:
                    emails.setdefault(role, addr)
    return emails

rdap_cache = {}  # ip -> {network_asn, network_desc, abuse_email, tech_email}

unique_ips = sorted(set(ip for _, ip in repo_ips if ip is not None))
for ip in unique_ips:
    info = {"network_asn": "", "network_desc": "", "abuse_email": "", "tech_email": ""}
    try:
        obj  = IPWhois(ip)
        # Try RDAP first (richer data), fall back to legacy WHOIS
        try:
            rdap   = obj.lookup_rdap(depth=1, retry_count=3)
            emails = extract_emails(rdap)
            info = {
                "network_asn":  rdap.get("asn", ""),
                "network_desc": rdap.get("asn_description", ""),
                "abuse_email":  emails.get("abuse", ""),
                "tech_email":   emails.get("technical", emails.get("admin", "")),
            }
        except Exception:
            whois = obj.lookup_whois()
            info = {
                "network_asn":  whois.get("asn", ""),
                "network_desc": whois.get("asn_description", ""),
                "abuse_email":  whois.get("nets", [{}])[0].get("abuse_emails", "").split("\n")[0],
                "tech_email":   whois.get("nets", [{}])[0].get("tech_emails", "").split("\n")[0],
            }
    except Exception:
        pass
    rdap_cache[ip] = info
    time.sleep(RDAP_DELAY)

print(f"      → Looked up {len(unique_ips)} IPs")

# ── 3b. Domain WHOIS lookup for all hostnames ────────────────────────────────

import whois as pywhois
import tldextract

def get_domain_whois_email(hostname):
    """Return the first email from domain WHOIS for the registrable domain."""
    ext = tldextract.extract(hostname)
    domain = f"{ext.domain}.{ext.suffix}"
    try:
        w = pywhois.whois(domain)
        emails = w.emails
        if isinstance(emails, list):
            return emails[0] if emails else ""
        return emails or ""
    except Exception:
        return ""

GENERIC_EMAIL_DOMAINS = {
    # Cloud / hosting providers
    "vultr.com", "linode.com", "akamai.com", "digitalocean.com",
    "amazonaws.com", "amazon.com", "ovh.ca", "ovh.net",
    "hetzner.com", "tencent.com", "alibaba.com", "oracle.com",
    "zappiehost.com", "xtom.com", "hostpapa.com",
    # Domain registrars
    "porkbun.com", "godaddy.com", "namesilo.com", "key-systems.net",
    "markmonitor.com", "enom.com", "namecheap.com", "tucows.com",
    "name.com", "encirca.com", "35.cn",
}

def pick_best_contact(hostname, abuse_email, tech_email, domain_whois_email):
    """Return the most operator-specific email across all three sources."""
    ext = tldextract.extract(hostname)
    host_domain = f"{ext.domain}.{ext.suffix}"

    def clean(email):
        return email.split(" ")[0].strip() if email else ""

    def email_domain(email):
        addr = clean(email)
        return addr.split("@")[1].lower() if "@" in addr else ""

    # tech first, then abuse, then domain whois
    candidates = [tech_email, abuse_email, domain_whois_email]

    # Priority 1: email whose domain matches the repo's own domain
    for email in candidates:
        if email and email_domain(email) == host_domain:
            return clean(email)

    # Priority 2: any non-generic email
    for email in candidates:
        if email and email_domain(email) not in GENERIC_EMAIL_DOMAINS:
            return clean(email)

    # Priority 3: anything at all
    for email in candidates:
        if email:
            return clean(email)

    return ""

print("[3b] Running domain WHOIS for all hostnames...")
domain_whois_cache = {}  # hostname -> email
for host in hostnames:
    domain_whois_cache[host] = get_domain_whois_email(host)
    time.sleep(0.3)
found = sum(1 for v in domain_whois_cache.values() if v)
print(f"      → Found domain WHOIS emails for {found}/{len(hostnames)} hostnames")

# ── 4. Load VRPs (IPv4 only) ──────────────────────────────────────────────────

print("[4/5] Loading VRPs from Routinator output...")

vrps = []
with open(VRPS_FILE, newline="") as f:
    reader = csv.DictReader(f)
    for row in reader:
        try:
            prefix = ip_network(row["IP Prefix"].strip(), strict=False)
            if prefix.version != 4:
                continue
            vrps.append({
                "asn":        row["ASN"].strip(),
                "prefix":     prefix,
                "prefix_len": prefix.prefixlen,
                "max_length": int(row["Max Length"].strip()),
                "ta":         row["Trust Anchor"].strip(),
            })
        except (ValueError, KeyError):
            pass

print(f"      → Loaded {len(vrps)} IPv4 VRPs")

# ── 6. Check ROA existence and maxLength for each repository ──────────────────

print("[5/5] Checking ROA coverage and maxLength configuration...")

results = []

for hostname, ip in repo_ips:
    rdap = rdap_cache.get(ip, {}) if ip else {}
    base = {
        "hostname":      hostname,
        "ip":            ip or "FAILED",
        "network_asn":   rdap.get("network_asn", ""),
        "network_desc":  rdap.get("network_desc", ""),
        "abuse_email":        rdap.get("abuse_email", ""),
        "tech_email":         rdap.get("tech_email", ""),
        "domain_whois_email": domain_whois_cache.get(hostname, ""),
        "best_contact":       pick_best_contact(
                                  hostname,
                                  rdap.get("abuse_email", ""),
                                  rdap.get("tech_email", ""),
                                  domain_whois_cache.get(hostname, ""),
                              ),
        "roa_asn":        "",
        "roa_prefix":     "",
        "roa_prefix_len": "",
        "roa_max_length": "",
        "roa_gap":        "",
        "roa_ta":         "",
    }

    if ip is None:
        results.append({**base, "status": "DNS_FAILED"})
        continue

    try:
        addr = ip_address(ip)
    except ValueError:
        results.append({**base, "status": "INVALID_IP"})
        continue

    matches = [v for v in vrps if addr in v["prefix"]]

    if not matches:
        results.append({**base, "status": "NO_ROA"})
        continue

    best       = max(matches, key=lambda v: v["prefix_len"])
    prefix_len = best["prefix_len"]
    max_len    = best["max_length"]
    gap        = max_len - prefix_len

    if prefix_len < 24 and max_len > prefix_len:
        status = "MISCONFIGURED"
    else:
        status = "OK"

    results.append({**base,
        "status":         status,
        "roa_asn":        best["asn"],
        "roa_prefix":     str(best["prefix"]),
        "roa_prefix_len": prefix_len,
        "roa_max_length": max_len,
        "roa_gap":        gap,
        "roa_ta":         best["ta"],
    })

# ── 7. Save results to CSV ────────────────────────────────────────────────────

fieldnames = [
    "hostname", "ip", "status",
    "network_asn", "network_desc", "abuse_email", "tech_email", "domain_whois_email", "best_contact",
    "roa_asn", "roa_prefix", "roa_prefix_len", "roa_max_length", "roa_gap", "roa_ta",
]

with open(OUTPUT_CSV, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(results)

# ── 8. Print summary stats ────────────────────────────────────────────────────

# PP-level: worst-case status per hostname
priority  = {"MISCONFIGURED": 3, "NO_ROA": 2, "DNS_FAILED": 1, "OK": 0}
pp_status = {}
for r in results:
    h, s = r["hostname"], r["status"]
    if priority.get(s, 0) > priority.get(pp_status.get(h, "OK"), 0):
        pp_status[h] = s

total_pps        = len(hostnames)
dns_failed       = sum(1 for s in pp_status.values() if s == "DNS_FAILED")
pp_ok            = sum(1 for s in pp_status.values() if s == "OK")
pp_misconfigured = sum(1 for s in pp_status.values() if s == "MISCONFIGURED")
pp_no_roa        = sum(1 for s in pp_status.values() if s == "NO_ROA")

# IP-level
total_ips = sum(1 for r in results if r["status"] != "DNS_FAILED")
ip_ok     = sum(1 for r in results if r["status"] == "OK")
ip_misc   = sum(1 for r in results if r["status"] == "MISCONFIGURED")
ip_no_roa = sum(1 for r in results if r["status"] == "NO_ROA")

# Unique prefix level
seen_prefixes = {}
for r in results:
    if r["status"] in ("OK", "MISCONFIGURED"):
        p = r["roa_prefix"]
        if p not in seen_prefixes or r["status"] == "MISCONFIGURED":
            seen_prefixes[p] = r["status"]

unique_ok            = sum(1 for s in seen_prefixes.values() if s == "OK")
unique_misconfigured = sum(1 for s in seen_prefixes.values() if s == "MISCONFIGURED")
unique_no_roa        = len(set(r["ip"] for r in results if r["status"] == "NO_ROA"))

# Misconfigured prefix → hostname map
prefix_to_hosts = defaultdict(list)
for r in results:
    if r["status"] == "MISCONFIGURED":
        prefix_to_hosts[r["roa_prefix"]].append(r["hostname"])

print()
print("=" * 60)
print("RPKI Repository Analysis Results")
print("=" * 60)

print("\n--- Publication Points (hostnames) ---")
print(f"  Total PPs found:                    {total_pps}")
print(f"  DNS resolution failed:              {dns_failed}")
print(f"  Has ROA, correctly configured:      {pp_ok}")
print(f"  Has ROA, misconfigured maxLength:   {pp_misconfigured}")
print(f"  No ROA:                             {pp_no_roa}")

print("\n--- IP Addresses ---")
print(f"  Total IPs resolved:                 {total_ips}")
print(f"  Has ROA, correctly configured:      {ip_ok}")
print(f"  Has ROA, misconfigured maxLength:   {ip_misc}")
print(f"  No ROA:                             {ip_no_roa}")

print("\n--- Unique Prefix Level ---")
print(f"  Correctly configured:               {unique_ok}")
print(f"  Misconfigured maxLength:            {unique_misconfigured}")
print(f"  No ROA (unique IPs):                {unique_no_roa}")

if prefix_to_hosts:
    print("\n--- Misconfigured Prefixes (with hosted PPs) ---")
    print(f"  {'Prefix':<22} {'PPs on this prefix'}")
    print("  " + "-" * 55)
    for prefix, hosts in sorted(prefix_to_hosts.items()):
        print(f"  {prefix:<22} {', '.join(hosts)}")

print()
print("=" * 60)
print(f"Full results saved to: {OUTPUT_CSV}")