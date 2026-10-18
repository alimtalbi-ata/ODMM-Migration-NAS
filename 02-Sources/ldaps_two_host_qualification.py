"""V188.3: explicit, read-only two-host witness qualification harness.

Operator supplies endpoints and certificate paths. No network call occurs on
construction. A successful probe is evidence only, never a cutover permit.
"""
import ipaddress
import json
import socket
import time
from pathlib import Path
from ldaps_ipc_persistent_identity import IdentityPinError
from ldaps_remote_witness import RemoteWitnessVerifier


def validate_target(host, port, *, resolver=socket.getaddrinfo):
    if not isinstance(host, str) or not host or any(c.isspace() for c in host):
        raise IdentityPinError('TWO_HOST_TARGET_INVALID')
    if type(port) is not int or not 1 <= port <= 65535:
        raise IdentityPinError('TWO_HOST_PORT_INVALID')
    try:
        records = resolver(host, port, type=socket.SOCK_STREAM)
    except (OSError, ValueError) as exc:
        raise IdentityPinError('TWO_HOST_DNS_UNAVAILABLE') from exc
    if not records:
        raise IdentityPinError('TWO_HOST_DNS_EMPTY')
    addresses = []
    for record in records:
        try:
            addr = ipaddress.ip_address(record[4][0].split('%')[0])
        except (IndexError, ValueError, TypeError) as exc:
            raise IdentityPinError('TWO_HOST_DNS_INVALID') from exc
        if addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local:
            raise IdentityPinError('TWO_HOST_NOT_INDEPENDENT_ENDPOINT')
        addresses.append(str(addr))
    return tuple(sorted(set(addresses)))


class TwoHostQualification:
    def __init__(self, *, host, port, cafile, certfile, keyfile, witness_key,
                 server_name=None, resolver=socket.getaddrinfo, verifier_factory=RemoteWitnessVerifier,
                 clock=time.time):
        self.host, self.port, self.resolver = host, port, resolver
        self.clock = clock
        self.verifier_factory = verifier_factory
        self.verifier_options = dict(host=host, port=port, cafile=cafile,
                                     certfile=certfile, keyfile=keyfile,
                                     witness_key=witness_key, server_name=server_name,
                                     timeout=3.0)

    def preflight(self):
        addresses = validate_target(self.host, self.port, resolver=self.resolver)
        for name in ('cafile', 'certfile', 'keyfile'):
            path = Path(self.verifier_options[name])
            if path.is_symlink() or not path.is_file():
                raise IdentityPinError('TWO_HOST_CREDENTIAL_MISSING')
        # Instantiate the real verifier for input validation, without opening sockets.
        self.verifier_factory(**self.verifier_options)
        return {'status':'TWO_HOST_PREFLIGHT_READY', 'resolved_addresses':addresses,
                'network_tested':False, 'remote_independence_proven':False,
                'cutover_authorized':False}

    def probe(self, *, expected_count, expected_last_mac, incident_id, operator_confirmed=False):
        if operator_confirmed is not True:
            raise IdentityPinError('TWO_HOST_OPERATOR_CONFIRMATION_REQUIRED')
        if not isinstance(incident_id, str) or not 1 <= len(incident_id) <= 128 or any(ord(c) < 32 for c in incident_id):
            raise IdentityPinError('TWO_HOST_INCIDENT_INVALID')
        ready = self.preflight()
        verifier = self.verifier_factory(**self.verifier_options)
        result = verifier.verify(expected_count=expected_count, expected_last_mac=expected_last_mac)
        if result.get('status') != 'REMOTE_WITNESS_VERIFIED':
            raise IdentityPinError('TWO_HOST_WITNESS_UNVERIFIED')
        return {'status':'TWO_HOST_REMOTE_PROBE_VERIFIED', 'incident_id':incident_id,
                'addresses':ready['resolved_addresses'], 'count':result['count'],
                'checked_at_unix':int(self.clock()), 'network_tested':True,
                'remote_independence_proven':False, 'manual_review_required':True,
                'recovery_authorized':False, 'publication_authorized':False,
                'cutover_authorized':False}
