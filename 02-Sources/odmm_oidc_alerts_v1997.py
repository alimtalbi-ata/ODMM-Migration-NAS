"""Deterministic OIDC incident transitions and bounded retention. Author: Abdelhalim Talbi.

Does not make assumptions about migration engine health or Keycloak authentication state.
"""
import datetime as dt
import sqlite3
from pathlib import Path

STATES={"UNKNOWN","RECOVERING","AVAILABLE","DEGRADED","UNAVAILABLE"}
BAD={"DEGRADED","UNAVAILABLE"}

def reconcile(db_path, *, retain=10000):
    if type(retain) is not int or not 10 <= retain <= 1000000:
        raise ValueError("INVALID_RETENTION")
    path=Path(db_path)
    if not path.is_file():
        raise FileNotFoundError(path)
    db=sqlite3.connect(str(path),timeout=5)
    try:
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("BEGIN IMMEDIATE")
        db.execute("CREATE TABLE IF NOT EXISTS oidc_alert_events (observation_id INTEGER PRIMARY KEY, observed_utc TEXT NOT NULL, event TEXT NOT NULL, previous_state TEXT, current_state TEXT NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS oidc_alert_cursor (id INTEGER PRIMARY KEY CHECK(id=1), last_observation_id INTEGER NOT NULL)")
        cursor=db.execute("SELECT last_observation_id FROM oidc_alert_cursor WHERE id=1").fetchone()
        last=cursor[0] if cursor else 0
        rows=db.execute("SELECT id,observed_utc,state FROM oidc_observations WHERE id>? ORDER BY id",(last,)).fetchall()
        previous=db.execute("SELECT state FROM oidc_observations WHERE id<=? ORDER BY id DESC LIMIT 1",(last,)).fetchone()
        prior=previous[0] if previous else None
        events=[]
        for ident,stamp,state in rows:
            if state not in STATES: raise ValueError("INVALID_STATE")
            event=None
            if state in BAD and prior not in BAD: event="OIDC_DEGRADED"
            elif state == "AVAILABLE" and prior in BAD: event="OIDC_RECOVERED"
            elif state == "UNAVAILABLE" and prior == "DEGRADED": event="OIDC_OUTAGE"
            if event:
                db.execute("INSERT INTO oidc_alert_events VALUES(?,?,?,?,?)",(ident,stamp,event,prior,state))
                events.append({"observation_id":ident,"observed_utc":stamp,"event":event,"previous_state":prior,"current_state":state})
            prior=state
        if rows:
            db.execute("INSERT INTO oidc_alert_cursor(id,last_observation_id) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET last_observation_id=excluded.last_observation_id",(rows[-1][0],))
        # Preserve the cursor, but retain only the most recent bounded observation/event history.
        db.execute("DELETE FROM oidc_observations WHERE id NOT IN (SELECT id FROM oidc_observations ORDER BY id DESC LIMIT ?)",(retain,))
        db.execute("DELETE FROM oidc_alert_events WHERE observation_id NOT IN (SELECT observation_id FROM oidc_alert_events ORDER BY observation_id DESC LIMIT ?)",(retain,))
        db.commit()
        return {"author":"Abdelhalim Talbi","scope":"OIDC provider observations only","migration_engine_status":"NOT_MEASURED","new_events":events,"processed":len(rows)}
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()

def history(db_path,limit=100):
    if type(limit) is not int or not 1 <= limit <= 1000: raise ValueError("INVALID_LIMIT")
    db=sqlite3.connect(str(db_path),timeout=5)
    try:
        rows=db.execute("SELECT observation_id,observed_utc,event,previous_state,current_state FROM oidc_alert_events ORDER BY observation_id DESC LIMIT ?",(limit,)).fetchall()
        return [dict(zip(("observation_id","observed_utc","event","previous_state","current_state"),r)) for r in rows]
    finally:db.close()
