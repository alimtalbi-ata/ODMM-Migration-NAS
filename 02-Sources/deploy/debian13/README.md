# Debian 13 remote witness — deployment blueprint (not executed)

1. Provision a **separate Debian 13 host** and firewall inbound witness TCP to authorized clients only.
2. Create unprivileged `odmm-witness` service account without login shell; install Python modules in `/opt/odmm-witness` (root-owned, non-writable by service account).
3. Create `/etc/odmm-witness` (root-owned), provision independently signed server certificate, private key, client CA and a **random >=32-byte HMAC key**. Restrict key and config to mode 0600 with ownership accessible to the dedicated service account (consider a separate service-readable group and ACL; `secure_file` rejects group-readable secrets).
4. Set config JSON fields: `host`, `port`, `db_path`, `certfile`, `keyfile`, `cafile`, `hmac_key_file`. Set db_path under `/var/lib/odmm-witness`, owned by service account, mode 0700 directory.
5. Copy `odmm-witness.service` into `/etc/systemd/system`, `systemctl daemon-reload`, then `systemctl enable --now odmm-witness` **only after manual review**.
6. Verify certificate SAN, expiry, key rotation and mTLS from a second host; test firewall, crash/restart and read-only requests. Back up database and HMAC material separately under independent administrative controls.

The network listener is **read-only**. `RemoteWitnessStore.publish` is not exposed by this daemon. Publication remains an out-of-band supervised operation. systemd hardening here is a baseline, not a security certification. Certificate revocation (CRL/OCSP) and key rollover are NOT implemented. No automatic migration or cutover.
