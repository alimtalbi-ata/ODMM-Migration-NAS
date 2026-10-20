"""ODMM Linux multi-node topology validation (planning only, no network IO).

Author: Abdelhalim Talbi. Fail closed on duplicate ownership and ambiguous nodes.
"""
import ipaddress
import json
import re
from pathlib import Path

ROLES = frozenset(("control", "registry", "datamover", "observability"))
NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
MAX_NODES = 128

class TopologyError(ValueError):
    pass

def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise TopologyError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result

def validate_topology(data):
    if not isinstance(data, dict) or set(data) != {"schema_version", "nodes"} or data["schema_version"] != 1:
        raise TopologyError("INVALID_SCHEMA")
    nodes = data["nodes"]
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= MAX_NODES:
        raise TopologyError("INVALID_NODE_COUNT")
    names, addresses, ownership = set(), set(), set()
    normalized = []
    for node in nodes:
        if not isinstance(node, dict) or set(node) != {"name", "address", "roles", "site", "networks"}:
            raise TopologyError("INVALID_NODE")
        name, address, roles, site, networks = (node[k] for k in ("name", "address", "roles", "site", "networks"))
        if not isinstance(name, str) or not NAME.fullmatch(name) or name in names:
            raise TopologyError("INVALID_OR_DUPLICATE_NAME")
        if not isinstance(site, str) or not NAME.fullmatch(site):
            raise TopologyError("INVALID_SITE")
        if not isinstance(address, str):
            raise TopologyError("INVALID_ADDRESS")
        try:
            address = str(ipaddress.ip_address(address))
        except ValueError as exc:
            raise TopologyError("INVALID_ADDRESS") from exc
        if address in addresses or ipaddress.ip_address(address).is_multicast or ipaddress.ip_address(address).is_unspecified:
            raise TopologyError("INVALID_OR_DUPLICATE_ADDRESS")
        if not isinstance(roles, list) or not roles or len(roles) != len(set(roles)) or any(not isinstance(r, str) or r not in ROLES for r in roles):
            raise TopologyError("INVALID_ROLES")
        if not isinstance(networks, list) or len(networks) != len(set(networks)) or any(not isinstance(n, str) or not NAME.fullmatch(n) for n in networks):
            raise TopologyError("INVALID_NETWORKS")
        if "datamover" in roles and not networks:
            raise TopologyError("DATAMOVER_NETWORK_REQUIRED")
        for network in networks:
            key = (site, network, name)
            if key in ownership:
                raise TopologyError("DUPLICATE_OWNERSHIP")
            ownership.add(key)
        names.add(name)
        addresses.add(address)
        normalized.append({"name": name, "address": address, "site": site, "roles": sorted(roles), "networks": sorted(networks)})
    roles_present = set().union(*(set(n["roles"]) for n in normalized))
    missing = {"control", "registry", "datamover"} - roles_present
    if missing:
        raise TopologyError("MISSING_REQUIRED_ROLES")
    return {"schema_version": 1, "nodes": sorted(normalized, key=lambda n: n["name"]), "ready_for_live_migration": False,
            "note": "Topology inventory only; connectivity, fencing, credentials and NAS access unqualified"}

def load_topology(path):
    path = Path(path)
    if path.stat().st_size > 1024 * 1024:
        raise TopologyError("TOPOLOGY_TOO_LARGE")
    try:
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(TopologyError("INVALID_JSON_CONSTANT")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise TopologyError("INVALID_JSON") from exc
    return validate_topology(data)
