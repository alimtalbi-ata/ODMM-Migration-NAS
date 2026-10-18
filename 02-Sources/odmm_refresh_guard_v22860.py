"""Pure helpers for refresh coordination and honest server-capacity reporting."""

def is_current_response(response_generation, current_generation, closed=False):
    return not closed and type(response_generation) is int and response_generation == current_generation

def server_limit_notice(count, limit=200):
    if type(count) is not int or count < 0 or type(limit) is not int or limit < 1:
        raise ValueError("INVALID_COUNT")
    return ("Limite serveur atteinte : seuls les jobs reçus sont affichés ; "
            "pagination côté serveur non disponible") if count >= limit else "Résultats reçus du serveur (exhaustivité non garantie)"
