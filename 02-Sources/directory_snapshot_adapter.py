"""Fail-closed offline AD/LDAP export normalization and atomic RBAC synchronization.

NOT a live directory connector: snapshots must be supplied by a trusted operator.
No authentication or authorization for production cutover is performed.
"""
import hashlib
import json
import re
from human_approval_registry import ApprovalError
from review_identity_policy import IdentityPolicyLedger, ROLES, _id

_GROUPS = frozenset(('ODMM_SECURITY_REVIEWERS', 'ODMM_OPERATIONS_REVIEWERS'))

def normalize_directory_export(export):
    if not isinstance(export, dict) or set(export) != {'source', 'version', 'accounts'}:
        raise ApprovalError('INVALID_DIRECTORY_EXPORT')
    if export['source'] not in ('AD_EXPORT', 'LDAP_EXPORT'):
        raise ApprovalError('INVALID_DIRECTORY_SOURCE')
    version = _id(export['version'])
    if not isinstance(export['accounts'], list) or not export['accounts']:
        raise ApprovalError('EMPTY_DIRECTORY_EXPORT')
    seen = set(); rows = []
    for item in export['accounts']:
        if not isinstance(item,dict) or set(item) != {'id','enabled','groups'}:
            raise ApprovalError('INVALID_DIRECTORY_ACCOUNT')
        account = _id(item['id'])
        if account in seen: raise ApprovalError('DUPLICATE_DIRECTORY_ACCOUNT')
        seen.add(account)
        if type(item['enabled']) is not bool or not isinstance(item['groups'],list) or any(not isinstance(g,str) or g not in _GROUPS for g in item['groups']):
            raise ApprovalError('INVALID_DIRECTORY_MEMBERSHIP')
        if len(item['groups']) != len(set(item['groups'])):
            raise ApprovalError('DUPLICATE_DIRECTORY_GROUP')
        if len(item['groups']) > 1: raise ApprovalError('CONFLICTING_REVIEW_ROLES')
        role = {'ODMM_SECURITY_REVIEWERS':'security','ODMM_OPERATIONS_REVIEWERS':'operations'}[item['groups'][0]] if item['groups'] else None
        rows.append({'reviewer':account,'role':role,'active':item['enabled'] and role is not None})
    rows.sort(key=lambda x:x['reviewer'])
    canonical = {'source':export['source'],'version':version,'accounts':rows}
    digest = hashlib.sha256(json.dumps(canonical,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return {'normalized':canonical,'sha256':digest,'authenticated':False,'cutover_authorized':False}

class DirectorySnapshotPolicyLedger(IdentityPolicyLedger):
    def __init__(self,path,*,issuer_secret):
        super().__init__(path,issuer_secret=issuer_secret)
        self.db.execute("""CREATE TABLE IF NOT EXISTS directory_sync_state (
            source TEXT PRIMARY KEY, version TEXT NOT NULL, digest TEXT NOT NULL)""")

    def apply_export(self,export,*,expected_previous_digest=None):
        bundle=normalize_directory_export(export)
        source=bundle['normalized']['source']; version=bundle['normalized']['version']
        if expected_previous_digest is not None and (not isinstance(expected_previous_digest,str) or not re.fullmatch('[0-9a-f]{64}',expected_previous_digest)):
            raise ApprovalError('INVALID_EXPECTED_DIGEST')
        try:
            self.db.execute('BEGIN IMMEDIATE')
            old=self.db.execute('SELECT version,digest FROM directory_sync_state WHERE source=?',(source,)).fetchone()
            if old is None:
                if expected_previous_digest is not None: raise ApprovalError('DIRECTORY_SNAPSHOT_CONFLICT')
            elif expected_previous_digest != old[1]:
                raise ApprovalError('DIRECTORY_SNAPSHOT_CONFLICT')
            if old and old[0] == version and old[1] != bundle['sha256']:
                raise ApprovalError('DIRECTORY_VERSION_REUSED')
            # One authoritative snapshot replaces all prior reviewers, failing closed for omitted identities.
            self.db.execute('UPDATE reviewer_directory SET active=0')
            for row in bundle['normalized']['accounts']:
                self.db.execute("""INSERT INTO reviewer_directory(reviewer,role,active,directory_version)
                    VALUES(?,?,?,?) ON CONFLICT(reviewer) DO UPDATE SET
                    role=excluded.role,active=excluded.active,directory_version=excluded.directory_version""",
                    (row['reviewer'],row['role'] or 'security',int(row['active']),version))
            self.db.execute("""INSERT INTO directory_sync_state(source,version,digest) VALUES(?,?,?)
                ON CONFLICT(source) DO UPDATE SET version=excluded.version,digest=excluded.digest""",
                (source,version,bundle['sha256']))
            self.db.execute('COMMIT')
            return {'status':'OFFLINE_DIRECTORY_SNAPSHOT_APPLIED','sha256':bundle['sha256'],
                    'reviewer_count':len(bundle['normalized']['accounts']),
                    'authenticated':False,'cutover_authorized':False}
        except BaseException:
            if self.db.in_transaction: self.db.execute('ROLLBACK')
            raise
