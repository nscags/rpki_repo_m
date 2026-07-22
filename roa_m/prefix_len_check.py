import csv

with open('rpki_repo_results.csv', newline='') as f:
    reader = csv.DictReader(f)
    rows = list(reader)

no_roa = [r for r in rows if r['status'] == 'NO_ROA']

print(f"Total repositories with no ROA: {len(no_roa)}")

# For no ROA repos we don't have a prefix length from the ROA
# so we need to check the actual IP against BGP table
# but we can check if the IP itself is a /24 or shorter via the VRPs
# A simpler proxy: check if any covering prefix exists at all

# Load VRPs to find the announcing prefix even without a ROA
from ipaddress import ip_network, ip_address

vrps = []
with open('rpki_vrps.csv', newline='') as f:
    reader = csv.DictReader(f)
    for row in reader:
        try:
            prefix = ip_network(row['IP Prefix'].strip(), strict=False)
            if prefix.version == 4:
                vrps.append(prefix)
        except ValueError:
            pass

print("\nNo ROA repositories - hijack risk:")
print(f"  {'Hostname':<45} {'IP':<18} {'Risk'}")
print("  " + "-" * 80)

for r in no_roa:
    ip = r['ip']
    try:
        addr = ip_address(ip)
        # Find longest matching prefix in VRP table as a proxy for the announced prefix
        matches = [p for p in vrps if addr in p]
        if matches:
            best = max(matches, key=lambda p: p.prefixlen)
            if best.prefixlen < 24:
                risk = f"HIGH - prefix + subprefix hijack possible ({best})"
            else:
                risk = f"MEDIUM - prefix hijack only ({best})"
        else:
            risk = "HIGH - no covering prefix found, subprefix hijack possible"
    except ValueError:
        risk = "UNKNOWN"
    print(f"  {r['hostname']:<45} {ip:<18} {risk}")