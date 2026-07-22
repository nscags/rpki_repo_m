"""
Adds/updates the best_contact column in rpki_repo_results.csv
using existing abuse_email, tech_email, and domain_whois_email columns.
Does not overwrite any other data.
"""

import csv
import tldextract

INPUT_CSV  = "rpki_repo_results.csv"
OUTPUT_CSV = "rpki_repo_results.csv"

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
    ext = tldextract.extract(hostname)
    host_domain = f"{ext.domain}.{ext.suffix}"

    def clean(email):
        return email.split(" ")[0].strip() if email else ""

    def email_domain(email):
        addr = clean(email)
        return addr.split("@")[1].lower() if "@" in addr else ""

    candidates = [tech_email, abuse_email, domain_whois_email]

    for email in candidates:
        if email and email_domain(email) == host_domain:
            return clean(email)

    for email in candidates:
        if email and email_domain(email) not in GENERIC_EMAIL_DOMAINS:
            return clean(email)

    for email in candidates:
        if email:
            return clean(email)

    return ""

with open(INPUT_CSV, newline="") as f:
    reader = csv.DictReader(f)
    fieldnames = reader.fieldnames
    rows = list(reader)

if "best_contact" not in fieldnames:
    fieldnames = fieldnames + ["best_contact"]

for r in rows:
    r["best_contact"] = pick_best_contact(
        r["hostname"],
        r.get("abuse_email", ""),
        r.get("tech_email", ""),
        r.get("domain_whois_email", ""),
    )

with open(OUTPUT_CSV, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

print(f"Done — updated {len(rows)} rows in {OUTPUT_CSV}")
