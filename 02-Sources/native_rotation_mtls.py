"""V196.2: verified TLS client identity configuration for vendor read-only transport.

Loads a client certificate/key pair into a fresh validating SSLContext. Certificate
chain verification and client-certificate acceptance remain responsibilities of the
TLS peer. This module does not assert that the remote endpoint accepted the cert.
"""
from pathlib import Path
import ssl

class MTLSConfigurationRejected(ValueError):
    pass


def make_mtls_context(*, ca_file, certificate_file, private_key_file, minimum_version=ssl.TLSVersion.TLSv1_2):
    paths = (ca_file, certificate_file, private_key_file)
    if any(not isinstance(p, (str, Path)) or not str(p) or "\x00" in str(p) for p in paths):
        raise MTLSConfigurationRejected("TLS_PATH_INVALID")
    if minimum_version not in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
        raise MTLSConfigurationRejected("TLS_VERSION_INVALID")
    try:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_file))
        ctx.minimum_version = minimum_version
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        ctx.load_cert_chain(certfile=str(certificate_file), keyfile=str(private_key_file))
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise MTLSConfigurationRejected("TLS_MATERIAL_INVALID") from exc
    return ctx


def make_mtls_vendor_get(*, approved_origins, ca_file, certificate_file, private_key_file,
                         timeout=5.0, max_response_bytes=65536, connection_factory=None):
    from native_rotation_https_transport import make_https_get_transport
    ctx = make_mtls_context(ca_file=ca_file, certificate_file=certificate_file,
                            private_key_file=private_key_file)
    return make_https_get_transport(approved_origins=approved_origins, ssl_context=ctx,
        timeout=timeout, max_response_bytes=max_response_bytes,
        connection_factory=connection_factory, require_json=True)
