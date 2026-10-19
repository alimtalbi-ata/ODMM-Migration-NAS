"""Safe UI diagnostics: no credentials, endpoint or server body in messages."""
import json
import socket
import ssl
from urllib.error import HTTPError, URLError


def explain_connection_failure(exc):
    if isinstance(exc, HTTPError):
        if exc.code in (401, 403):
            return "Authentification refusée (HTTP %s). Vérifiez le jeton et les autorisations." % exc.code
        if exc.code == 404:
            return "API de supervision introuvable (HTTP 404). Vérifiez la version du serveur."
        if exc.code in (408, 504):
            return "Délai de réponse du serveur dépassé (HTTP %s). Réessayez plus tard." % exc.code
        if exc.code == 429:
            return "Trop de requêtes (HTTP 429). Réessayez plus tard."
        if 500 <= exc.code <= 599:
            return "Serveur indisponible (HTTP %s). Réessayez ou contactez l'administrateur." % exc.code
        return "Réponse HTTP non attendue (HTTP %s)." % exc.code
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "Délai de connexion dépassé. Vérifiez l'accès réseau et le serveur."
    if isinstance(exc, ssl.SSLError):
        return "Échec de validation TLS. Vérifiez le certificat du serveur."
    if isinstance(exc, URLError):
        return "Connexion impossible. Vérifiez le réseau, le DNS et le certificat TLS."
    if isinstance(exc, json.JSONDecodeError):
        return "Réponse JSON invalide. Vérifiez la compatibilité du serveur."
    if isinstance(exc, ValueError):
        known = {
            "INVALID_ORIGIN": "Adresse du serveur invalide. Utilisez une origine HTTP(S) sans chemin ni identifiants.",
            "TLS_REQUIRED": "Connexion HTTPS obligatoire pour un serveur distant.",
            "INVALID_TIMEOUT": "Délai de connexion invalide.",
            "REDIRECT_REFUSED": "Redirection du serveur refusée pour protéger le jeton API.",
            "INVALID_PORT": "Port du serveur invalide.",
            "INVALID_TOKEN": "Jeton invalide : format ou longueur incorrects.",
            "INVALID_REGISTRY_CONTRACT": "Contrat API du registre non conforme.",
            "INVALID_REGISTRY_ITEMS": "Liste des jobs invalide ou trop volumineuse.",
            "INVALID_REGISTRY_JOB": "Job mal formé dans la réponse API.",
            "INVALID_REGISTRY_ID": "Identifiant de job absent, invalide ou dupliqué.",
            "INVALID_REGISTRY_STATE": "État de job non reconnu.",
            "INVALID_JSON": "Réponse JSON invalide.",
            "REPORT_TOO_LARGE": "Réponse du serveur trop volumineuse.",
            "INVALID_CONTENT_TYPE": "Le serveur n'a pas retourné du JSON.",
            "UNEXPECTED_HTTP_STATUS": "Réponse HTTP inattendue.",
        }
        return known.get(str(exc), "Réponse ou configuration invalide. Vérifiez la connexion.")
    return "Erreur de consultation. Consultez les journaux du serveur si nécessaire."
