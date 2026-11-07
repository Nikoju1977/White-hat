"""SQLite durability and repository functions; never stores agent tokens in cleartext."""
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS credentials (
    device_id TEXT PRIMARY KEY, name TEXT NOT NULL, token_sha TEXT NOT NULL UNIQUE,
    active INTEGER NOT NULL DEFAULT 1, created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY, name TEXT NOT NULL, platform TEXT NOT NULL,
    last_seen REAL NOT NULL, last_risk INTEGER NOT NULL DEFAULT 0,
    last_forecast INTEGER, last_model TEXT NOT NULL DEFAULT 'initialisation',
    metrics_json TEXT NOT NULL DEFAULT '{}', checks_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL,
    ts REAL NOT NULL, cpu REAL NOT NULL, memory REAL NOT NULL,
    established INTEGER NOT NULL, listener_count INTEGER NOT NULL, risk INTEGER NOT NULL,
    FOREIGN KEY(device_id) REFERENCES devices(device_id)
);
CREATE INDEX IF NOT EXISTS ix_snap_device ON snapshots(device_id, ts DESC);
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL,
    key TEXT NOT NULL, code TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
    description TEXT NOT NULL, evidence_json TEXT NOT NULL,
    first_seen REAL NOT NULL, last_seen REAL NOT NULL, occurrences INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'open', resolved_at REAL
);
CREATE INDEX IF NOT EXISTS ix_incident_status ON incidents(status, last_seen DESC);
CREATE INDEX IF NOT EXISTS ix_incident_device_key ON incidents(device_id,key,status);
CREATE TABLE IF NOT EXISTS ingest_receipts (
    device_id TEXT NOT NULL, sample_id TEXT NOT NULL, received_at REAL NOT NULL,
    response_json TEXT NOT NULL, PRIMARY KEY(device_id,sample_id)
);
CREATE INDEX IF NOT EXISTS ix_receipts_expire ON ingest_receipts(received_at);
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL NOT NULL,
    actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
    details_json TEXT NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL
);
"""


def initialize(path: str) -> None:
    dbfile = Path(path)
    dbfile.parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as con:
        con.executescript(SCHEMA)


@contextmanager
def connect(path: str):
    con = sqlite3.connect(path, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA busy_timeout=10000")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def issue_credential(path: str, device_id: str, name: str, token_sha: str) -> None:
    with connect(path) as con:
        con.execute("INSERT INTO credentials(device_id,name,token_sha,created) VALUES(?,?,?,?)", (device_id, name, token_sha, time.time()))


def rotate_credential(path: str, device_id: str, token_sha: str) -> bool:
    with connect(path) as con:
        cur = con.execute('UPDATE credentials SET token_sha=? WHERE device_id=? AND active=1',
                          (token_sha,device_id))
        return cur.rowcount == 1


def get_receipt(path: str, device_id: str, sample_id: str) -> dict | None:
    with connect(path) as con:
        row = con.execute('SELECT response_json FROM ingest_receipts WHERE device_id=? AND sample_id=?',
                          (device_id,sample_id)).fetchone()
        return json.loads(row['response_json']) if row else None


def credential_for_token(path: str, token_sha: str) -> dict | None:
    with connect(path) as con:
        row = con.execute("SELECT device_id,name FROM credentials WHERE token_sha=? AND active=1", (token_sha,)).fetchone()
        return dict(row) if row else None


def latest_history(con, device_id: str, limit: int = 100) -> list[dict]:
    rows = con.execute("SELECT ts,cpu,memory,established,listener_count,risk FROM snapshots WHERE device_id=? ORDER BY ts DESC LIMIT ?", (device_id, limit)).fetchall()
    return [dict(r) for r in reversed(rows)]


def save_snapshot(path: str, device_id: str, name: str, platform: str, metrics: dict, checks: dict,
                  risk: int, forecast: int | None, model: str, findings: list[dict],
                  sample_id: str | None = None, response: dict | None = None) -> dict | None:
    now = time.time()
    with connect(path) as con:
        if sample_id:
            existing = con.execute('SELECT response_json FROM ingest_receipts WHERE device_id=? AND sample_id=?',
                                   (device_id,sample_id)).fetchone()
            if existing:
                return json.loads(existing['response_json'])
        con.execute("""INSERT INTO devices(device_id,name,platform,last_seen,last_risk,last_forecast,last_model,metrics_json,checks_json)
           VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET name=excluded.name,platform=excluded.platform,
           last_seen=excluded.last_seen,last_risk=excluded.last_risk,last_forecast=excluded.last_forecast,
           last_model=excluded.last_model,metrics_json=excluded.metrics_json,checks_json=excluded.checks_json""",
           (device_id,name,platform,now,risk,forecast,model,json.dumps(metrics),json.dumps(checks)))
        con.execute("INSERT INTO snapshots(device_id,ts,cpu,memory,established,listener_count,risk) VALUES(?,?,?,?,?,?,?)",
                    (device_id, now, metrics.get('cpu',0),metrics.get('memory',0),metrics.get('established',0),metrics.get('listener_count',0),risk))
        for f in findings:
            existing = con.execute("SELECT id FROM incidents WHERE device_id=? AND key=? AND status='open' LIMIT 1", (device_id,f['key'])).fetchone()
            if existing:
                con.execute("UPDATE incidents SET last_seen=?,occurrences=occurrences+1,description=?,evidence_json=? WHERE id=?",
                            (now,f['description'],json.dumps(f.get('evidence',{})), existing['id']))
            else:
                con.execute("""INSERT INTO incidents(device_id,key,code,title,severity,description,evidence_json,first_seen,last_seen)
                        VALUES(?,?,?,?,?,?,?,?,?)""",(device_id,f['key'],f['code'],f['title'],f['severity'],
                                                         f['description'],json.dumps(f.get('evidence',{})),now,now))
        # Bounded retention: 30 days of measurements; preserve incident history for audit.
        con.execute("DELETE FROM snapshots WHERE ts < ?", (now - 30*86400,))
        con.execute("DELETE FROM ingest_receipts WHERE received_at < ?", (now - 30*86400,))
        if sample_id and response is not None:
            con.execute('INSERT INTO ingest_receipts(device_id,sample_id,received_at,response_json) VALUES(?,?,?,?)',
                        (device_id,sample_id,now,json.dumps(response)))
    return response
