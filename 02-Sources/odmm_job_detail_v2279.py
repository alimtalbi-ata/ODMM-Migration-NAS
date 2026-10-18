"""Shared read-only job detail projection; never infer unreported metrics."""
from copy import deepcopy

SAFE_FIELDS = ("id", "status", "source", "target", "protocol", "created_at", "updated_at", "started_at", "finished_at", "error", "message")

def job_detail(row):
    if not isinstance(row, dict):
        raise ValueError("INVALID_JOB")
    identifier = row.get("id")
    if not isinstance(identifier, str) or not identifier.strip():
        raise ValueError("MISSING_JOB_ID")
    return {"fields": {key: deepcopy(row[key]) for key in SAFE_FIELDS if key in row and row[key] is not None},
            "read_only": True, "unreported_metrics": ["bytes_transferred", "throughput", "progress_percent"]}

def select_job(rows, identifier):
    matches = [row for row in rows if isinstance(row, dict) and row.get("id") == identifier]
    if len(matches) != 1:
        raise ValueError("JOB_NOT_UNIQUE_OR_MISSING")
    return job_detail(matches[0])

def detail_lines(detail):
    labels = {"id":"Identifiant", "status":"État", "source":"Source", "target":"Cible", "protocol":"Protocole", "created_at":"Créé", "updated_at":"Mis à jour", "started_at":"Démarré", "finished_at":"Terminé", "error":"Erreur", "message":"Message"}
    return [f"{labels.get(k,k)} : {v}" for k,v in detail["fields"].items()]
