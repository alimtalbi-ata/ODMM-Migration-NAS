"""ODMM V205.3: normalisation prudente de réponses API constructeur déjà exportées.
Aucun appel réseau, aucune écriture NAS, aucune validation ACL/cutover.
Auteur: Abdelhalim Talbi
"""
import json
from pathlib import Path

SUPPORTED = {"netapp_ontap": ("version", "svms"), "dell_powerscale": ("version", "zones")}
MAX_BYTES = 2_000_000

def normalize_export(vendor, payload):
    if vendor not in SUPPORTED:
        raise ValueError("Constructeur non pris en charge")
    if not isinstance(payload, dict):
        raise ValueError("Réponse API attendue sous forme d'objet JSON")
    if not all(k in payload for k in SUPPORTED[vendor]):
        raise ValueError("Export incomplet: champs obligatoires absents")
    version = payload["version"]
    if not isinstance(version, str) or not 0 < len(version) <= 128:
        raise ValueError("Version invalide")
    objects = payload[SUPPORTED[vendor][1]]
    if not isinstance(objects, list) or len(objects) > 10000:
        raise ValueError("Inventaire invalide")
    return {"vendor": vendor, "reported_version": version,
            "reported_object_count": len(objects), "source": "offline_vendor_api_export",
            "collection_mode": "read_only_offline", "status": "UNVERIFIED",
            "acl_fidelity_verified": False, "effective_access_verified": False,
            "cutover_authorized": False,
            "limitations": ["Export non authentifié", "ACL non testées", "Accès effectifs non testés"]}

def normalize_file(vendor, filename):
    p=Path(filename)
    if p.stat().st_size > MAX_BYTES:
        raise ValueError("Export trop volumineux")
    return normalize_export(vendor, json.loads(p.read_text(encoding="utf-8")))
