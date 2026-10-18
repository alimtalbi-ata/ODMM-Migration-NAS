# ODMM V197.5 / Compact V4.8.5 — OIDC Authorization Code + PKCE
Auteur : Abdelhalim Talbi

## Delivered
- `odmm_oidc_browser.py`: Authorization Code + PKCE S256; random state and nonce; single-use state; backchannel HTTPS token exchange with no automatic redirects and no environment proxy trust; signed RS256 ID and access tokens; nonce, issuer, audience, subject and token expiry checks; opaque Secure/HttpOnly/SameSite=Lax cookie; session expiry bounded to both tokens; POST logout with strict Origin check.
- Portal remains read-only; POST logout is available at /auth/logout for an integrating client. Scope enforcement uses existing `odmm_scoped_app` and `job_grants` database.
- `test_odmm_oidc_browser_v1975.py`: HTTP integration tests including replay and unauthorized scope.

## Integration (not a standalone production deployment)
Configure `BrowserOIDCConfig` with exact HTTPS authorization/token URLs, client ID, public HTTPS origin and callback. Construct `OIDCVerifier` using pinned issuer/audience/JWKS and call `create_browser_app(registry_path=...,grants_path=...,verifier=...,config=...)`. Run behind a correctly configured TLS reverse proxy; configure IdP to allow only exact callback and PKCE S256. Existing `odmm_secure_deploy` still starts the **bearer-only** entrypoint, not this browser flow.

## Critical limitations
- Browser sessions and pending authorization transactions are in-process dictionaries: **single worker only**; restart invalidates sessions; no cross-process sharing or persistence; no eviction of expired entries except when accessed; unsuitable for large-scale production without a bounded external session store.
- Token verification requires `roles` in both ID and access tokens; many IdPs do not put roles in ID tokens. Configure the IdP explicitly; do not weaken verification to accommodate arbitrary untrusted claims.
- Authorization endpoint and token endpoint must be independently provisioned from trusted IdP metadata. No automatic discovery/JWKS rotation; no signed metadata verification.
- Requires secure TLS termination and browser access over HTTPS. No real IdP end-to-end test, security penetration test, reverse proxy config, Windows packaging qualification, HA or production release gate.
- Existing legacy CLI and unscoped entrypoints remain in cumulative source archive; **do not distribute the entire source archive as a hardened production image**.
- No destructive operation, cutover, data movement, automatic remediation or silent external-tool fallback added.
