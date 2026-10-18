# ODMM V197.9 / Compact V4.8.9 — JWKS bounded cache and Keycloak test plan
Auteur : Abdelhalim Talbi

## JWKS reload cache
`ODMM_JWKS_CHECK_INTERVAL=0` (default) reads and validates the pinned file for each verification, preserving the V197.8 fail-closed semantics. Optional interval between 0 and 5 seconds reduces disk reads. **Security trade-off:** until the deadline, a removed or compromised JWKS file/key may still be accepted. Set 0 for immediate revocation needs. An invalid file at the next check fails closed. No remote JWKS fetching is performed.

## Keycloak end-to-end qualification (not yet executed)
1. Deploy a pinned Keycloak version on an isolated test network behind TLS with a trusted certificate.
2. Create realm `odmm-test`, confidential client `odmm-browser`, strict redirect URI and allowed origins, authorization code + PKCE S256, and explicit role mapping.
3. Export realm JWKS over the operator-approved channel into a permission-restricted local file; never trust `jku`/`x5u` from a token.
4. Verify login, nonce/state mismatch, code reuse, expiry, role separation, logout, simultaneous sessions, JWKS rotation, revoked keys and reverse-proxy headers.
5. Run independent tests for Debian and Windows Compact and capture evidence before claiming production readiness.

No Keycloak integration test or TLS proxy was executed in this increment. Native migration engine unchanged. No automatic cutover or fallback.
