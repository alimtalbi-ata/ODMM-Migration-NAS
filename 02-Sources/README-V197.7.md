# ODMM V197.7 / Compact V4.8.7 — Controlled JWKS rotation
Auteur : Abdelhalim Talbi

## Implemented
- `odmm_jwks_rotation.py`: explicit offline candidate JWKS validation, pinned issuer/audience, RSA 2048-bit minimum through existing verifier, no network fetch, no token-driven key URLs.
- Default dry-run with change plan; explicit `--apply`; retirements additionally require `--allow-retirement`.
- Rejects a changed public key under the same `kid`, symbolic links and group/world-writable JWKS files.
- Atomic same-filesystem replacement and fsync; no production application writes.

## Example
```bash
python -m odmm_jwks_rotation --current /etc/odmm/jwks.json --candidate /etc/odmm/jwks-next.json --issuer https://keycloak.example/realms/odmm --audience odmm
python -m odmm_jwks_rotation --current /etc/odmm/jwks.json --candidate /etc/odmm/jwks-next.json --issuer https://keycloak.example/realms/odmm --audience odmm --apply
```

**Important**: Running ODMM processes currently hold JWKS keys in memory. Rotation of the on-disk file does not hot-reload existing processes. Use a controlled restart/rolling restart and maintain overlapping keys until previously issued tokens expire. Back up the existing trusted JWKS and use a change-management process. Only accept a candidate JWKS from a separately authenticated administrator-controlled channel. This utility does not independently authenticate the provenance of the candidate file.

## Reverse proxy design guidance (not a deployable production configuration)
Use a trusted HTTPS reverse proxy bound to the public origin and forward only to ODMM's 127.0.0.1 listener. Terminate TLS with managed certificates, restrict ingress, configure timeouts and request size limits, disable caching of `/auth/*`, and preserve Host/origin validation. Do not expose port 8787 externally. Validate session cookies and redirect URI with the actual identity provider.

## Verification
`python -m unittest test_odmm_jwks_rotation_v1977 -q`

## Not yet qualified
No live Keycloak integration, no automatic JWKS refresh/hot reload, no TLS reverse proxy deployment, no cross-host HA, no full end-to-end browser penetration testing. The cumulative archive still includes historical unscoped entrypoints. Development release only.
