"""Read-only triage for Open Data Migration Manager jobs.
Never claim successful migration or recommend automatic destructive action.
"""
from odmm_job_detail_v2279 import job_detail

LABELS = {"FAILED": ("À examiner", "Consulter le message d'erreur et les preuves; ne pas relancer sans diagnostic."),
          "RUNNING": ("En cours", "Surveiller les opérations et vérifier les indicateurs disponibles."),
          "PENDING": ("En attente", "Vérifier les précontrôles, les fenêtres et les ressources disponibles."),
          "COMPLETED": ("Terminé déclaré", "Vérifier le rapport de contrôle et la conformité ACL avant toute bascule."),
          "UNKNOWN": ("État non reconnu", "Vérifier le registre et les journaux du serveur.")}

def triage_job(row):
    detail = job_detail(row)
    raw = row.get("status")
    state = str(raw).strip().upper() if isinstance(raw, str) else "UNKNOWN"
    label, action = LABELS.get(state, LABELS["UNKNOWN"])
    return {"detail": detail, "state": state, "label": label, "next_step": action,
            "error_reported": bool(row.get("error")), "read_only": True}

def triage_lines(result):
    from odmm_job_detail_v2279 import detail_lines
    return ["Diagnostic : " + result["label"], "À vérifier : " + result["next_step"],
            *detail_lines(result["detail"])]
