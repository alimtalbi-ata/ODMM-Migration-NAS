# ODMM V198.8 / Compact V4.9.8 — Keycloak TLS laboratory
Auteur : Abdelhalim Talbi

This is a reproducible **operator-started laboratory**, not production hardening.
Requires Docker Compose, reviewed immutable Keycloak and Nginx digests,
trusted `fullchain.pem` and `privkey.pem` with SAN localhost, and a secret-managed
KC_ADMIN_PASSWORD. Do not commit secrets or private keys.

Run from this directory:
`docker compose -f compose.yaml -f compose.qualify.yaml config`
`docker compose -f compose.yaml -f compose.qualify.yaml up -d`

Set `KEYCLOAK_IMAGE`, `NGINX_IMAGE`, `OIDC_TLS_CERT_DIR`, `KC_ADMIN_USER`,
`KC_ADMIN_PASSWORD` before running. Nginx exposes only loopback 8443;
Keycloak has no published port. Do not use `-k`/`--insecure` with curl.
Check:
`python ../../odmm_oidc_live_probe.py --issuer https://localhost:8443/realms/odmm-lab --output oidc-qualification.json`

This checks discovery and JWKS only. Login/PKCE exchange, JWT signature verification,
logout, revocation, rotation and application route authorization remain manual or
future integration work. Keycloak `start-dev` must never be used for production.
The realm contains no test users and no credentials.
No migration engine files are changed.
