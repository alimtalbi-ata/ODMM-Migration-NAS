"""SQLite single-host migration ownership epochs. Author: Abdelhalim Talbi.

Advisory ownership only; not distributed fencing, and not sufficient for NAS cutover.
"""
import hashlib
import hmac
import json
import sqlite3
import time
from dataclasses import dataclass

class OwnershipBlocked(RuntimeError):
    pass

@dataclass(frozen=True)
class Claim:
    resource: str
    owner: str
    epoch: int
    expires_ns: int

class OwnershipRegistry:
    def __init__(self, path, *, clock=None):
        self.db = sqlite3.connect(path, timeout=10, isolation_level=None)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS ownership(resource TEXT PRIMARY KEY, owner TEXT NOT NULL, epoch INTEGER NOT NULL CHECK(epoch>0), expires_ns INTEGER NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS ownership_events(id INTEGER PRIMARY KEY AUTOINCREMENT, resource TEXT NOT NULL, owner TEXT NOT NULL, epoch INTEGER NOT NULL, action TEXT NOT NULL, time_ns INTEGER NOT NULL)')
        self.clock = clock or time.time_ns

    @staticmethod
    def _validate(resource, owner):
        if not all(isinstance(v,str) and 0 < len(v) <= 256 and not any(ord(c)<32 for c in v) for v in (resource,owner)):
            raise OwnershipBlocked('INVALID_IDENTITY')

    def _now(self):
        now = self.clock()
        if type(now) is not int or now <= 0:
            raise OwnershipBlocked('INVALID_CLOCK')
        return now

    def _event(self, claim, action, now):
        self.db.execute('INSERT INTO ownership_events(resource,owner,epoch,action,time_ns) VALUES(?,?,?,?,?)', (claim.resource,claim.owner,claim.epoch,action,now))

    def claim(self, resource, owner, *, ttl_ns):
        self._validate(resource, owner)
        if type(ttl_ns) is not int or not 1_000_000 <= ttl_ns <= 86_400_000_000_000:
            raise OwnershipBlocked('INVALID_TTL')
        now = self._now()
        self.db.execute('BEGIN IMMEDIATE')
        try:
            row = self.db.execute('SELECT owner,epoch,expires_ns FROM ownership WHERE resource=?',(resource,)).fetchone()
            if row and row[2] > now:
                raise OwnershipBlocked('RESOURCE_OWNED')
            epoch = (row[1]+1) if row else 1
            if epoch >= 2**63:
                raise OwnershipBlocked('EPOCH_EXHAUSTED')
            claim = Claim(resource,owner,epoch,now+ttl_ns)
            self.db.execute('INSERT INTO ownership VALUES(?,?,?,?) ON CONFLICT(resource) DO UPDATE SET owner=excluded.owner,epoch=excluded.epoch,expires_ns=excluded.expires_ns', (resource,owner,epoch,claim.expires_ns))
            self._event(claim,'CLAIM',now)
            self.db.commit()
            return claim
        except Exception:
            self.db.rollback()
            raise

    def verify(self, claim):
        if not isinstance(claim,Claim):
            return False
        now = self._now()
        row = self.db.execute('SELECT owner,epoch,expires_ns FROM ownership WHERE resource=?',(claim.resource,)).fetchone()
        return bool(row and row[0]==claim.owner and row[1]==claim.epoch and row[2]==claim.expires_ns and row[2]>now)

    def renew(self, claim, *, ttl_ns):
        if not isinstance(claim,Claim) or type(ttl_ns) is not int or not 1_000_000 <= ttl_ns <= 86_400_000_000_000:
            raise OwnershipBlocked('INVALID_RENEWAL')
        now = self._now()
        self.db.execute('BEGIN IMMEDIATE')
        try:
            row = self.db.execute('SELECT owner,epoch,expires_ns FROM ownership WHERE resource=?',(claim.resource,)).fetchone()
            if row != (claim.owner,claim.epoch,claim.expires_ns) or claim.expires_ns <= now:
                raise OwnershipBlocked('STALE_OWNER')
            new = Claim(claim.resource,claim.owner,claim.epoch,now+ttl_ns)
            if new.expires_ns <= claim.expires_ns:
                raise OwnershipBlocked('NON_EXTENDING_RENEWAL')
            self.db.execute('UPDATE ownership SET expires_ns=? WHERE resource=?',(new.expires_ns,claim.resource))
            self._event(new,'RENEW',now)
            self.db.commit()
            return new
        except Exception:
            self.db.rollback()
            raise

    def release(self, claim):
        if not isinstance(claim,Claim):
            raise OwnershipBlocked('INVALID_CLAIM')
        now = self._now()
        self.db.execute('BEGIN IMMEDIATE')
        try:
            row = self.db.execute('SELECT owner,epoch,expires_ns FROM ownership WHERE resource=?',(claim.resource,)).fetchone()
            if row != (claim.owner,claim.epoch,claim.expires_ns) or claim.expires_ns <= now:
                raise OwnershipBlocked('STALE_OWNER')
            self.db.execute('UPDATE ownership SET expires_ns=? WHERE resource=?',(now,claim.resource))
            self._event(claim,'RELEASE',now)
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def audit_export(self):
        rows = self.db.execute('SELECT id,resource,owner,epoch,action,time_ns FROM ownership_events ORDER BY id').fetchall()
        events = [dict(zip(('id','resource','owner','epoch','action','time_ns'),r)) for r in rows]
        payload = json.dumps(events,sort_keys=True,separators=(',',':')).encode()
        return {'events':events,'sha256':hashlib.sha256(payload).hexdigest(),'tamper_evident':False,'cutover_authorized':False}

    def close(self):
        self.db.close()
