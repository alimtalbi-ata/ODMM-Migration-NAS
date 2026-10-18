# ODMM V198.1 Full / Compact V4.9.1
Auteur : Abdelhalim Talbi

## Scope
Cumulative V198.0 source baseline plus additive OIDC session policy module and tests. Native migration engine untouched. No claim of live Keycloak/TLS qualification.

## Integration contract
Call `require_csrf` for every cookie-authenticated unsafe request (including logout), after trusted reverse-proxy origin normalization and before side effects. Generate cryptographically random per-session CSRF secrets, store server-side or in a correctly bound signed double-submit construction, and compare with submitted `X-CSRF-Token`. Do not expose CSRF tokens to third-party origins. Enforce SameSite, Secure, HttpOnly session cookies. Call `require_fresh_session` when constructing the authenticated principal. Protect authorization checks independently of CSRF.

## Key rotation/revocation
JWKS refresh must authenticate issuer metadata and enforce pinned issuer, expected audience, alg and key use; unknown `kid` fails closed. JWT expiration alone cannot provide immediate revocation: use server-side session invalidation or short-lived tokens and explicit revocation strategy. Logout must invalidate local session.

## Release gate
Offline unit/regression tests only. Live Keycloak, real HTTPS certificates, callback and logout flows, key rotation and revocation require an isolated deployment and evidence capture before production approval.
