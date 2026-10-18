"""V192.9 embeddable read-only evidence panel; never a standalone portal."""
import html
import json
from native_benchmark_evidence_manifest import verify_manifest


def cockpit_panel(manifest, *, manifest_keys, trusted_manifest_sha256=None):
    """Render a safe fragment only after independent HMAC verification."""
    verified = verify_manifest(manifest, manifest_keys=manifest_keys,
                               trusted_manifest_sha256=trusted_manifest_sha256)
    payload = manifest['payload']
    evidence = payload['evidence']
    stages = payload['stages']
    if not isinstance(evidence, dict) or not isinstance(stages, dict) or not isinstance(stages.get('entries'), list):
        raise ValueError('COCKPIT_PAYLOAD_INVALID')
    if len(stages['entries']) > 1000:
        raise ValueError('COCKPIT_ENTRIES_LIMIT')
    esc = lambda value: html.escape(str(value), quote=True)
    rows = ''.join('<tr><td>'+esc(item['name'])+'</td><td>'+esc(item['status'])+'</td><td>'+esc(item['bytes'])+'</td><td><code>'+esc(item.get('sha256') or '—')+'</code></td></tr>'
                   for item in stages['entries'] if isinstance(item, dict) and {'name','status','bytes'} <= item.keys())
    if len(rows) > 250000:
        raise ValueError('COCKPIT_HTML_LIMIT')
    status = esc(payload['status'])
    digest = esc(verified['sha256'])
    return ('<section class="odmm-evidence-panel" aria-label="Intégrité des preuves ODMM">'
            '<h2>Intégrité des preuves</h2><p>État : <strong>'+status+'</strong></p>'
            '<p>Journal : '+esc(evidence['status'])+' · SHA-256 : <code>'+esc(evidence.get('evidence_sha256') or '—')+'</code></p>'
            '<p>Manifeste authentifié : <code>'+digest+'</code></p>'
            '<p>Fichiers temporaires : '+esc(stages['count'])+'</p>'
            '<table><caption>Preuves conservées (lecture seule)</caption><thead><tr><th>Fichier</th><th>État</th><th>Octets</th><th>SHA-256</th></tr></thead><tbody>'+rows+'</tbody></table>'
            '<p>Réparation, nettoyage et cutover interdits depuis ce panneau.</p></section>')


def cockpit_status(manifest, *, manifest_keys, trusted_manifest_sha256=None):
    """Return a minimal verified backend contract; no mutations or approval endpoint."""
    result = verify_manifest(manifest, manifest_keys=manifest_keys,
                             trusted_manifest_sha256=trusted_manifest_sha256)
    return {'schema': 'odmm.cockpit.evidence_status.v1', 'status': result['evidence_status'],
            'manifest_sha256': result['sha256'], 'requires_human_review': result['requires_human_review'],
            'read_only': True, 'cleanup_authorized': False, 'cutover_authorized': False}
