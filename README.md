# RPKI Repository Measurement

This code supports the measurement study described in our paper (citation below).

## What It Does

RPKI publication points are the servers that distribute the cryptographic objects (certificates, ROAs, manifests) that make up the global RPKI. This code:

**xxx** 
Runs a [Routinator](https://github.com/NLnetLabs/routinator) scan and checks its local cache for PP hostnames, resolves each PP's hostname to an IP, performs RDAP/WHOIS lookups to find the hosting ASN and operator contact, and checks whether the PP's IP is covered by a correctly-configured ROA (per [RFC 9319](https://www.rfc-editor.org/rfc/rfc9319)).

<!-- 2. **Analyzes inter-AS PP dependencies** — for each RPKI resource certificate, identifies the parent PP and child PP and classifies the relationship as same-AS, different-AS, or unresolved, revealing cross-domain routing dependencies in the RPKI infrastructure. -->
3. **Generates operator notifications** — consolidates vulnerable PPs by operator contact email, ready for responsible disclosure.
4. **Simulates BGP attacks** — uses the [bgpy](https://github.com/jfuruness/bgpy_pkg) simulation framework and CAIDA AS topology to generate attack-scenario diagrams for each vulnerable PP.

Vulnerability classes detected:

| Status | Description |
|---|---|
| `MISCONFIGURED` | PP IP has a ROA but `maxLength > prefixLength` (shorter than /24), enabling a subprefix hijack against the PP itself |
| `NO_ROA` | PP IP has no ROA at all, enabling a prefix hijack |
| `OK` | PP IP is correctly covered |

## Repository Structure

```
.
├── analyze_repos.py          # Main analysis: discovers PPs, checks ROA coverage, finds contacts
├── pp_as_dependency.py       # Inter-AS dependency analysis across all resource certificates
├── pp_cert_count.py          # Counts child certificates hosted per publication point
├── pp_object_types.py        # Classifies RPKI objects by type (.cer, .roa, .mft, .crl, .asa)
├── sia_pp.py                 # Checks for multiple Publication Points in SIA extensions
├── stats.py                  # Summary statistics over rpki_repo_results.csv
├── prefix_len_check.py       # Prefix-length-based risk breakdown
├── generate_notifications.py # Consolidates vulnerable PPs by operator contact
├── generate_diagrams.py      # Generates BGP attack diagrams for each notification recipient
├── add_best_contact.py       # Contact email selection logic
├── domain_whois.py           # Domain-level WHOIS lookups
├── cert_scan.py              # Certificate scanner utility
├── run_pipeline.sh           # End-to-end pipeline script
└── requirements.txt
```

## Prerequisites

### System Dependencies

- **Python 3.10+**
- **[Routinator](https://routinator.docs.nlnetlabs.nl/)** — must be installed and have performed at least one validation run to populate the local cache at `~/.rpki-cache/repository/`

### Python Dependencies

Install via pip:

```bash
pip install -r requirements.txt
pip install tldextract python-whois cryptography
```

> **Note:** `generate_diagrams.py` additionally requires [`bgpy`](https://github.com/jfuruness/bgpy_pkg) and the `provable_rpki_sims` package (a sibling directory in this project). Install `bgpy` via pip and ensure `provable_rpki_sims` is importable from the parent directory.

## Running the Pipeline

### 1. Populate the Routinator cache

If you have not already done so, run Routinator to fetch and validate the global RPKI:

```bash
# Export VRPs (Validated ROA Payloads) to CSV — required by analyze_repos.py
routinator vrps --format csv --output rpki_vrps.csv
```

Or use the pipeline script which handles this for you:

```bash
./run_pipeline.sh --fresh   # runs routinator + analyze_repos.py
./run_pipeline.sh            # skips routinator, uses existing rpki_vrps.csv
```

### 2. Main repository analysis

```bash
python analyze_repos.py
```

Produces `rpki_repo_results.csv` with one row per (hostname, IP) pair, including ROA coverage status, hosting ASN, and operator contact emails.

### 3. Inter-AS dependency analysis

```bash
python pp_as_dependency.py
```

Reads the Routinator cache directly. Produces `pp_as_dependency.csv` classifying every parent→child PP relationship.

### 4. Additional analyses (independent, can be run in any order)

```bash
python stats.py                  # summary statistics over rpki_repo_results.csv
python pp_cert_count.py          # child cert counts per PP
python pp_object_types.py        # object type breakdown per PP
python sia_pp.py                 # check for multiple PPs in SIA extensions
python prefix_len_check.py       # risk breakdown by prefix length
```

### 5. Operator notification list

```bash
python generate_notifications.py
```

Reads `rpki_repo_results.csv` and produces `notification_contacts.csv` — one row per unique (operator contact, vulnerability type) pair with all affected PPs consolidated.

### 6. BGP attack diagrams

```bash
python generate_diagrams.py
```

Requires `bgpy` and `provable_rpki_sims`. Reads `notification_contacts.csv` and generates a PNG attack diagram for each recipient in `diagrams/`.

## Output Files

| File | Description |
|---|---|
| `rpki_repo_results.csv` | One row per (hostname, IP); columns: `hostname`, `ip`, `status`, `network_asn`, `network_desc`, `abuse_email`, `tech_email`, `domain_whois_email`, `best_contact`, `roa_asn`, `roa_prefix`, `roa_prefix_len`, `roa_max_length`, `roa_gap`, `roa_ta` |
| `pp_as_dependency.csv` | One row per (parent PP, child PP) certificate relationship; classified as `SAME_HOST`, `SAME_AS`, `DIFF_AS`, or `UNRESOLVED` |
| `notification_contacts.csv` | Consolidated notification list; one row per (contact email, vulnerability type) |
| `domain_whois_results.csv` | Domain-level WHOIS registration data per PP hostname |
| `sia_log.csv` | Per-certificate SIA extension log (all access method URIs) |

## Data Note

The output CSV files contain real operator contact information collected from public RDAP and WHOIS records. These are not included in this repository. If you reproduce the dataset, handle operator email addresses responsibly and in accordance with applicable data protection regulations.

## Citation

If you use this code in your research, please cite our paper:

```bibtex

```

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
