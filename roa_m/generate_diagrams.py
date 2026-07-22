"""
Generates BGP attack diagrams for each email recipient in notification_contacts.csv.
- NO_ROA      → prefix hijack scenario (email_config_000 template)
- MISCONFIGURED → forged-origin subprefix hijack (email_config_001 template)

For each row the script:
  1. Looks up the victim ASN's real provider in the CAIDA AS graph
  2. Finds a real AS for the second attacker upstream (replaces AS 1000)
  3. Builds a dynamic EngineTestConfig with those real ASNs
  4. Runs MyEngineTester and saves the diagram to diagrams/<hostname>.png
"""

import csv
import sys
import shutil
import tempfile
from pathlib import Path
from ipaddress import ip_network, ip_address
from typing import Optional, TYPE_CHECKING

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_DIR        = Path(__file__).parent
DIAGRAMS_DIR    = REPO_DIR / "diagrams"
NOTIFICATIONS   = REPO_DIR / "notification_contacts.csv"
RPKI_RESULTS    = REPO_DIR / "rpki_repo_results.csv"

# Path to the provable_rpki_sims package so we can import MyEngineTester
SIMS_ROOT = REPO_DIR.parent / "provable_rpki_sims"
sys.path.insert(0, str(SIMS_ROOT))

DIAGRAMS_DIR.mkdir(exist_ok=True)

# ── bgpy imports ──────────────────────────────────────────────────────────────

from bgpy.simulation_engine import BGP
from bgpy.simulation_framework import Scenario, ScenarioConfig, PrefixHijack, ForgedOriginPrefixHijack, GraphDataAggregator
from bgpy.tests.engine_tests.utils import EngineTestConfig, EngineTester
from bgpy.as_graphs import ASGraphInfo, CAIDAASGraphConstructor
from bgpy.as_graphs.base.links import CustomerProviderLink as CPLink
from bgpy.utils import Diagram
from bgpy.shared.enums import Outcomes, Timestamps, Relationships
from roa_checker.roa import ROA as RoaEntry

if TYPE_CHECKING:
    from bgpy.simulation_engine import Announcement as Ann
    from bgpy.simulation_engine import BaseSimulationEngine

# ── Import diagram/scenario classes from the email configs ────────────────────

from provable_rpki_sims.tests.engine_tests.engine_test_configs.email_config_000 import DiagramNoROA
from provable_rpki_sims.tests.engine_tests.test_engine import MyEngineTester as _MyEngineTester
from bgpy.simulation_framework import GraphDataAggregator, Scenario


class MyEngineTester(_MyEngineTester):
    def _generate_gt_diagrams(
        self, scenario: Scenario, graph_data_aggregator: GraphDataAggregator
    ) -> None:
        engine_gt  = self.codec.load(self.engine_ground_truth_path)
        outcomes_gt = self.codec.load(self.outcomes_ground_truth_path)

        static_order    = bool(self.conf.as_graph_info.diagram_ranks)
        diagram_obj_ranks = self._get_diagram_obj_ranks(engine_gt)

        # Use the actual victim ASN rather than the hardcoded RPKI_PP_ASN = 1
        victim_asn = next(iter(scenario.victim_asns))

        self.conf.DiagramCls().generate_as_graph(
            engine_gt,
            scenario,
            outcomes_gt,
            f"(Attack Targeting RPKI Publication Point hosted at AS{victim_asn})\n{self.conf.desc}",
            graph_data_aggregator,
            diagram_obj_ranks,
            static_order=static_order,
            path=self.storage_dir / "ground_truth.gv",
            view=False,
            dpi=self.dpi,
        )

# ── Load CAIDA AS graph once ──────────────────────────────────────────────────

print("Loading CAIDA AS graph...")
caida_graph = CAIDAASGraphConstructor().run()
print(f"  {len(caida_graph.as_dict)} ASes loaded")

FALLBACK_PROVIDER_ASN  = 2000   # used when victim has no provider
FALLBACK_UPSTREAM_ASN  = 1000   # used when provider has no upstream

# ── Helper: pick provider chain ───────────────────────────────────────────────

def get_provider_asns(victim_asn: int) -> tuple[int, int]:
    """
    Returns (provider_asn, upstream_asn) for the victim using the CAIDA graph.

    provider_asn  — real provider of victim  (replaces RPKI_PP_PROVIDER_ASN)
    upstream_asn  — real provider of provider (replaces AS 1000 in the template)
    """
    as_obj = caida_graph.as_dict.get(victim_asn)

    if not as_obj or not as_obj.provider_asns:
        return FALLBACK_PROVIDER_ASN, FALLBACK_UPSTREAM_ASN

    provider_asn = sorted(as_obj.provider_asns)[0]   # deterministic pick
    p_obj = caida_graph.as_dict.get(provider_asn)

    if not p_obj or not p_obj.provider_asns:
        return provider_asn, FALLBACK_UPSTREAM_ASN

    upstream_asn = sorted(p_obj.provider_asns)[0]
    return provider_asn, upstream_asn

# ── Helper: derive prefixes ───────────────────────────────────────────────────

def derive_prefixes(row: dict, status: str) -> tuple[str, str | None, int | None]:
    """
    Returns (main_prefix, sub_prefix, roa_max_length).
    sub_prefix and roa_max_length are only used for MISCONFIGURED.
    """
    if status == "MISCONFIGURED":
        main = row["prefixes"].split(",")[0].strip()
        max_len_str = row.get("max_lengths", "").split(",")[0].strip()
        max_len = int(max_len_str) if max_len_str else 24
        net = ip_network(main, strict=False)
        sub_len = min(max_len, 24)
        sub = str(ip_network(f"{net.network_address}/{sub_len}", strict=False))
        return main, sub, max_len
    else:
        # NO_ROA: use a /24 derived from the victim IP
        ip = row["ips"].split(",")[0].strip()
        net = ip_network(f"{ip}/24", strict=False)
        return str(net), None, None

# ── Scenario classes (parameterised at call time) ─────────────────────────────

def make_prefix_hijack_cls(cls_name: str, victim_asn: int, prefix: str, provider_asn: int):
    """Create a module-level PrefixHijack subclass so pickle can find it."""
    def _get_announcements(self, *, engine=None):
        anns = []
        for vasn in self.victim_asns:
            anns.append(self.scenario_config.AnnCls(
                prefix=prefix,
                next_hop_asn=vasn,
                as_path=(vasn,),
                timestamp=Timestamps.VICTIM.value,
                seed_asn=vasn,
                recv_relationship=Relationships.ORIGIN,
            ))
        for aasn in self.attacker_asns:
            anns.append(self.scenario_config.AnnCls(
                prefix=prefix,
                as_path=(aasn, provider_asn),
                next_hop_asn=aasn,
                seed_asn=aasn,
                timestamp=Timestamps.ATTACKER.value,
            ))
        return tuple(anns)

    cls = type(cls_name, (PrefixHijack,), {"_get_announcements": _get_announcements})
    globals()[cls_name] = cls   # register so pickle can resolve by name
    return cls


def make_subprefix_hijack_cls(cls_name: str, victim_asn: int, provider_asn: int,
                               main_prefix: str, sub_prefix: str):
    """Create a module-level ForgedOriginPrefixHijack subclass so pickle can find it."""
    def _get_announcements(self, *, engine=None):
        return (
            self.scenario_config.AnnCls(
                prefix=main_prefix,
                next_hop_asn=victim_asn,
                as_path=(victim_asn,),
                timestamp=Timestamps.VICTIM.value,
                seed_asn=victim_asn,
                recv_relationship=Relationships.ORIGIN,
            ),
            self.scenario_config.AnnCls(
                prefix=sub_prefix,
                as_path=(666, provider_asn, victim_asn),
                timestamp=Timestamps.ATTACKER.value,
                next_hop_asn=666,
                seed_asn=666,
            ),
        )

    cls = type(cls_name, (ForgedOriginPrefixHijack,), {"_get_announcements": _get_announcements})
    globals()[cls_name] = cls   # register so pickle can resolve by name
    return cls

# ── Build EngineTestConfig ────────────────────────────────────────────────────

DESC = (
    "A potential attacker AS whose number has been masked as 666 achieves 100.0% "
    "success in a simulated attack scenario.\nWe picked this one as an example but "
    "there are around 34,000 multi-homed ASes in the Internet who could achieve "
    "similar attack success according to the CAIDA serial-2 topology."
)

def build_config(name: str, status: str, victim_asn: int,
                 provider_asn: int, upstream_asn: int,
                 main_prefix: str, sub_prefix: str | None,
                 roa_max_length: int | None = None) -> EngineTestConfig:

    graph_info = ASGraphInfo(
        peer_links=frozenset(),
        customer_provider_links=frozenset([
            CPLink(provider_asn=provider_asn, customer_asn=victim_asn),
            CPLink(provider_asn=provider_asn, customer_asn=666),
            CPLink(provider_asn=upstream_asn,  customer_asn=666),
        ]),
    )

    if status == "NO_ROA":
        ScenCls = make_prefix_hijack_cls(f"Scen_{name}", victim_asn, main_prefix, provider_asn)
        return EngineTestConfig(
            name=name,
            desc=DESC,
            scenario_config=ScenarioConfig(
                ScenarioCls=ScenCls,
                BasePolicyCls=BGP,
                override_attacker_asns=frozenset({666}),
                override_victim_asns=frozenset({victim_asn}),
                override_roas=None,
            ),
            as_graph_info=graph_info,
            DiagramCls=DiagramNoROA,
        )
    else:  # MISCONFIGURED
        ScenCls = make_subprefix_hijack_cls(
            f"Scen_{name}", victim_asn, provider_asn, main_prefix, sub_prefix
        )
        ml = roa_max_length if roa_max_length is not None else 24
        roa = RoaEntry(
            prefix=ip_network(main_prefix, strict=False),
            origin=victim_asn,
            max_length=ml,
        )
        return EngineTestConfig(
            name=name,
            desc=DESC,
            scenario_config=ScenarioConfig(
                ScenarioCls=ScenCls,
                BasePolicyCls=BGP,
                override_attacker_asns=frozenset({666}),
                override_victim_asns=frozenset({victim_asn}),
                override_roas=tuple([roa]),
            ),
            as_graph_info=graph_info,
            DiagramCls=Diagram,
        )

# ── Load data ─────────────────────────────────────────────────────────────────

with open(RPKI_RESULTS, newline="") as f:
    rpki_rows = {r["hostname"]: r for r in csv.DictReader(f)}

with open(NOTIFICATIONS, newline="") as f:
    notifications = list(csv.DictReader(f))

# ── Generate diagrams ─────────────────────────────────────────────────────────

print(f"\nGenerating {len(notifications)} diagrams...\n")

used_names: dict[str, int] = {}   # tracks how many times a safe_name has been used
diagram_filenames: list[str] = []  # parallel list — one entry per notification row

for row in notifications:
    status   = row["status"]
    hostname = row["hostnames"].split(",")[0].strip()   # first hostname only
    base_name = hostname.replace(".", "_").replace("-", "_")
    count = used_names.get(base_name, 0)
    used_names[base_name] = count + 1
    safe_name = base_name if count == 0 else f"{base_name}_{count}"

    # Get victim ASN: for MISCONFIGURED use roa_asn from the row; for NO_ROA use network_asn
    if status == "MISCONFIGURED":
        asn_str = row.get("asns", "").split(",")[0].strip().lstrip("AS")
    else:
        rpki_row = rpki_rows.get(hostname, {})
        asn_str  = rpki_row.get("network_asn", "").strip()
    if not asn_str:
        print(f"  SKIP {hostname} — no ASN found")
        diagram_filenames.append("")
        continue
    victim_asn = int(asn_str)

    provider_asn, upstream_asn               = get_provider_asns(victim_asn)
    main_prefix, sub_prefix, roa_max_length  = derive_prefixes(row, status)

    print(f"  [{status}] {hostname}")
    print(f"    victim={victim_asn}  provider={provider_asn}  upstream={upstream_asn}")
    print(f"    prefix={main_prefix}" + (f"  sub={sub_prefix}" if sub_prefix else ""))

    conf = build_config(
        name=safe_name,
        status=status,
        victim_asn=victim_asn,
        provider_asn=provider_asn,
        upstream_asn=upstream_asn,
        main_prefix=main_prefix,
        sub_prefix=sub_prefix,
        roa_max_length=roa_max_length,
    )

    diagram_filename = ""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        try:
            MyEngineTester(
                base_dir=tmp_path,
                conf=conf,
                overwrite=True,
            ).test_engine()

            src = tmp_path / safe_name / "ground_truth.gv.png"
            if src.exists():
                dst = DIAGRAMS_DIR / f"{hostname}.png"
                shutil.copy2(src, dst)
                diagram_filename = dst.name
                print(f"    → saved {dst.name}")
            else:
                print(f"    WARNING: diagram not found at {src}")
        except Exception as e:
            import traceback
            print(f"    ERROR: {e}")
            traceback.print_exc()
    diagram_filenames.append(diagram_filename)

# ── Write diagram_filename column back to notification_contacts.csv ───────────

with open(NOTIFICATIONS, newline="") as f:
    reader = csv.DictReader(f)
    fieldnames = reader.fieldnames
    notif_rows = list(reader)

if "diagram_filename" not in fieldnames:
    fieldnames = list(fieldnames) + ["diagram_filename"]

for row, fname in zip(notif_rows, diagram_filenames):
    row["diagram_filename"] = fname

with open(NOTIFICATIONS, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(notif_rows)

print(f"\nDone. Diagrams in {DIAGRAMS_DIR}")
print(f"diagram_filename column written to {NOTIFICATIONS.name}")
