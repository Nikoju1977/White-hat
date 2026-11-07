"""Best-effort tamper-evident administrative audit log (not tamper-proof).

The database owner can rewrite the whole chain; export checkpoints outside the
host for independent evidence. Never include passwords or bearer tokens.
"""
import hashlib
import json
import time


def canonical(event: dict) -> str:
    return json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def append(con, actor: str, action: str, target: str = '', details: dict | None = None) -> None:
    last = con.execute('SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1').fetchone()
    previous = last['event_hash'] if last else '0' * 64
    payload = {'timestamp': round(time.time(), 6), 'actor': actor[:60],
               'action': action[:80], 'target': target[:120],
               'details': details or {}}
    digest = hashlib.sha256((previous + canonical(payload)).encode('utf-8')).hexdigest()
    con.execute('''INSERT INTO audit_events(timestamp,actor,action,target,details_json,previous_hash,event_hash)
                 VALUES(?,?,?,?,?,?,?)''', (payload['timestamp'], payload['actor'], payload['action'],
                payload['target'], canonical(payload['details']), previous, digest))


def verify(rows: list[dict]) -> dict:
    """Verify the full chain, oldest event first; report first invalid event."""
    prev = '0' * 64
    for row in rows:
        payload = {'timestamp': row['timestamp'], 'actor': row['actor'],
                   'action': row['action'], 'target': row['target'],
                   'details': json.loads(row['details_json'])}
        expected = hashlib.sha256((prev + canonical(payload)).encode('utf-8')).hexdigest()
        if row['previous_hash'] != prev or row['event_hash'] != expected:
            return {'valid': False, 'broken_at': row['id']}
        prev = row['event_hash']
    return {'valid': True, 'checked': len(rows), 'tip': prev}
