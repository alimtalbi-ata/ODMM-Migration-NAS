# ODMM V197.3 / Compact V4.8.3 — OIDC HTTP composition

Auteur : Abdelhalim Talbi

`odmm_oidc_http_entrypoint.create_from_environment()` compose le portail et les routes de consultation cloisonnées avec le vérificateur RS256 V197.0. Aucun endpoint d’écriture ni route historique n’est monté.

Configuration obligatoire : `ODMM_REGISTRY_DB`, `ODMM_GRANTS_DB`, `ODMM_OIDC_ISSUER` (https), `ODMM_OIDC_AUDIENCE`, `ODMM_OIDC_JWKS_PATH` (fichier local de clés publiques approuvées).

Exemple de démarrage sur interface locale seulement :

```bash
python -m uvicorn odmm_oidc_http_entrypoint:create_from_environment --factory --host 127.0.0.1 --port 8787
```

Ne pas exposer directement sur Internet. Un reverse proxy TLS, la gestion du cycle de vie des clés JWKS, un véritable parcours OIDC Authorization Code + PKCE et les tests multi-processus restent à qualifier. L'API nécessite un jeton Bearer signé RS256. Le CLI historique reste non cloisonné et ne doit pas être distribué aux utilisateurs multi-tenant.
