"""ODMM V205.5 — client HTTPS lecture seule, API ONTAP / PowerScale.
Les chemins sont des profils de collecte minimaux à qualifier selon firmware.
Auteur : Abdelhalim Talbi.
"""
import json, ssl, urllib.request, urllib.error, urllib.parse, ipaddress, hashlib
from dataclasses import dataclass

ENDPOINTS = {"netapp_ontap": "/api/cluster", "dell_powerscale": "/platform/1/cluster/config"}
MAX_RESPONSE = 1024 * 1024

class CollectionError(Exception): pass

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CollectionError("Redirection HTTP interdite")

@dataclass(frozen=True)
class CollectorConfig:
    vendor: str
    host: str
    token: str
    timeout: float = 8.0
    allow_hosts: tuple = ()

def collect(config, opener=None):
    if config.vendor not in ENDPOINTS: raise CollectionError("Constructeur inconnu")
    host = config.host
    if not isinstance(host, str) or not host or any(c in host for c in '/:@?#\\ '):
        raise CollectionError("Nom hôte invalide")
    if host not in config.allow_hosts: raise CollectionError("Hôte non autorisé")
    if not isinstance(config.token,str) or not config.token or '\n' in config.token or '\r' in config.token:
        raise CollectionError("Jeton invalide")
    if not (0.5 <= config.timeout <= 30): raise CollectionError("Timeout invalide")
    url = 'https://' + host + ENDPOINTS[config.vendor]
    req = urllib.request.Request(url, headers={'Authorization':'Bearer '+config.token,'Accept':'application/json','User-Agent':'ODMM-readonly/205.5'}, method='GET')
    client = opener or urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
    try:
        with client.open(req,timeout=config.timeout) as r:
            if r.status != 200: raise CollectionError('Réponse HTTP non 200')
            if 'json' not in r.headers.get('Content-Type','').lower(): raise CollectionError('Type de contenu non JSON')
            data = r.read(MAX_RESPONSE+1)
            if len(data)>MAX_RESPONSE: raise CollectionError('Réponse trop volumineuse')
    except (urllib.error.URLError,TimeoutError) as exc:
        raise CollectionError('Erreur de transport HTTPS') from exc
    try: payload=json.loads(data)
    except (ValueError,UnicodeError) as exc: raise CollectionError('JSON invalide') from exc
    if not isinstance(payload,dict): raise CollectionError('Objet JSON attendu')
    return {'vendor':config.vendor,'host':host,'endpoint':ENDPOINTS[config.vendor],
            'provenance':'authenticated_https_get','response_sha256':hashlib.sha256(data).hexdigest(),
            'reported_keys':sorted(str(k) for k in payload.keys()),
            'status':'UNVERIFIED','acl_fidelity_verified':False,
            'effective_access_verified':False,'cutover_authorized':False,
            'raw_payload':payload}
