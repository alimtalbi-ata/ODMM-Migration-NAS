"""ODMM V205.6 — collecte API contrôlée, provenance et route protégée.
Auteur : Abdelhalim Talbi. Lecture seule. Aucune persistance des secrets.
"""
import hashlib
import json
from datetime import datetime, timezone
from odmm_vendor_api_readonly_v2055 import CollectorConfig, CollectionError, collect

class ServiceError(ValueError):
    pass

def collect_inventory(vendor, host, *, token_provider, allow_hosts, opener=None):
    if not callable(token_provider):
        raise ServiceError('Fournisseur de jetons requis')
    if not isinstance(allow_hosts, (tuple, list, frozenset)):
        raise ServiceError('Liste blanche requise')
    if host not in allow_hosts:
        raise ServiceError('Hôte non autorisé')
    token = token_provider(vendor, host)
    if not isinstance(token, str) or not token:
        raise ServiceError('Jeton absent')
    response = collect(CollectorConfig(vendor=vendor, host=host, token=token, allow_hosts=tuple(allow_hosts)), opener=opener)
    # Ne jamais renvoyer la réponse brute du constructeur dans l'interface.
    return {'schema': 'odmm.collection.v2056', 'vendor': response['vendor'],
            'host': response['host'], 'endpoint': response['endpoint'],
            'provenance': response['provenance'], 'collected_at': datetime.now(timezone.utc).isoformat(),
            'response_sha256': response['response_sha256'],
            'reported_keys': response['reported_keys'],
            'status': 'UNVERIFIED', 'acl_fidelity_verified': False,
            'effective_access_verified': False, 'cutover_authorized': False,
            'warnings': ['Les API et firmwares ne sont pas certifiés', 'Aucun test ACL ou accès effectif']}

def attach_collection_api(app, *, authorize, token_provider, allow_hosts, collector=collect_inventory):
    """Enregistre POST /api/v1/qualification/collect (lecture seule côté NAS).
    Requiert une autorisation explicite et un fournisseur de jetons externe.
    """
    if not callable(authorize) or not callable(token_provider):
        raise ServiceError('Autorisation et fournisseur de jetons obligatoires')
    from fastapi import HTTPException, Request
    from fastapi.responses import JSONResponse
    @app.post('/api/v1/qualification/collect')
    async def collect_route(request: Request):
        if authorize(request) is not True:
            raise HTTPException(status_code=403, detail='Accès interdit')
        if request.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json':
            raise HTTPException(status_code=415, detail='JSON requis')
        if request.headers.get('content-length', '0').isdigit() and int(request.headers.get('content-length', '0')) > 4096:
            raise HTTPException(status_code=413, detail='Requête trop volumineuse')
        body = await request.body()
        if len(body) > 4096:
            raise HTTPException(status_code=413, detail='Requête trop volumineuse')
        try:
            data = json.loads(body)
            if not isinstance(data, dict) or set(data) != {'vendor', 'host'}:
                raise ServiceError('Seuls vendor et host sont acceptés')
            if not isinstance(data['vendor'], str) or not isinstance(data['host'], str):
                raise ServiceError('Paramètres invalides')
            report = collector(data['vendor'], data['host'], token_provider=token_provider, allow_hosts=allow_hosts)
        except (ValueError, CollectionError, ServiceError):
            raise HTTPException(status_code=422, detail='Collecte refusée ou impossible')
        return JSONResponse(report, headers={'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})
    return collect_route
