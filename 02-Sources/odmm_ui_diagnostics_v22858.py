"""Pure, bounded UI diagnostics; never expose exception strings or bearer tokens."""

MAX_JOBS_DISPLAY = 100000


def refresh_message(outcome: str, previous_count: int) -> str:
    suffix = f" {previous_count} job(s) précédemment chargés conservés." if previous_count else " Aucun job chargé."
    if outcome == "NETWORK":
        return "Connexion impossible. Vérifier l'adresse, TLS et les droits API." + suffix
    if outcome == "PAYLOAD":
        return "Réponse API invalide : structure du registre non conforme." + suffix
    if outcome == "VALIDATION":
        return "Registre refusé : identifiants ou états incohérents." + suffix
    return "Consultation terminée — lecture seule"


def safe_count(rows):
    if not isinstance(rows, list) or len(rows) > MAX_JOBS_DISPLAY:
        raise ValueError("Registre trop volumineux ou invalide")
    return len(rows)
