# V198.0 — OIDC isolated qualification lab
Auteur : Abdelhalim Talbi

This is a **lab recipe**, not a qualified or runnable production deployment. Keycloak `start-dev` is intentionally isolated on an internal Docker network, with **no published ports**. A real HTTPS test requires an operator-managed TLS ingress into that network, trusted certificates, a Keycloak realm/client and a JWKS export. Never publish this development service to the Internet. Set `KEYCLOAK_IMAGE` to a reviewed `image@sha256:...` reference and supply admin credentials through your own secret management; do not commit them.

The Nginx template is for the **ODMM application** on a Debian host, not a complete Keycloak ingress. Install the trusted certificate and key, substitute `odmm.example.invalid`, validate with `nginx -t`, and start ODMM using `python -m odmm_browser_deploy --host 127.0.0.1`. The ODMM process must remain bound to loopback. Only enable this behind an operator-managed HTTPS proxy.

Acceptance checklist: issuer and audience match actual tokens; browser code+PKCE flow; login CSRF/state/nonce negative tests; cookie expiry and logout; per-job authorization; key rotation and revocation; certificate validation; Debian/Windows Compact parity; concurrency and restart tests. None of these are claimed as a live Keycloak test by this package.
