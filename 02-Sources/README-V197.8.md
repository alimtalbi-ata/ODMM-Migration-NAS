# ODMM V197.8 / Compact V4.8.8 — JWKS hot reload
Auteur : Abdelhalim Talbi

On-demand local reload on each bearer verification, SHA-256 content detection, pinned issuer/audience, RSA key validation, fail closed if JWKS disappears or becomes invalid, symlink and unsafe permissions rejected. No network access, no token-directed URLs. This is not a real Keycloak integration or TLS proxy qualification. Every HTTP worker reads the same local JWKS; do not use without protected shared filesystem and deployment-controlled rotation.

Test: `python -m unittest test_odmm_oidc_hot_reload_v1978 -q`.

Limits: reading and hashing JWKS per request incurs I/O; next version should add trusted push notifications or bounded refresh cache, test Keycloak in Docker, configure TLS reverse proxy and complete production security review. Historical unscoped entrypoints still included for compatibility.
