"""Regression coverage for v0.2: administrative audit, token rotation, replay and FIM."""
import json
import uuid
from pathlib import Path

from fastapi.testclient import TestClient
from aegis.main import create_app
from aegis.security import hash_password
from aegis import storage, audit
from agent.integrity import monitor, file_hash


def api(tmp_path):
    app = create_app(str(tmp_path/'aegis.db'), hash_password('strong unique password for testing'), 'ab'*32)
    return TestClient(app), str(tmp_path/'aegis.db')


def sign_in(client):
    login = client.post('/api/login', json={'password':'strong unique password for testing'})
    assert login.status_code == 200
    return {'X-Aegis-CSRF': login.json()['csrf']}


def test_duplicate_ingestion_is_exactly_once(tmp_path):
    client, db = api(tmp_path)
    csrf = sign_in(client)
    enrollment=client.post('/api/enrollments',json={'name':'Server'},headers=csrf).json()
    auth={'Authorization':'Bearer '+enrollment['token']}
    payload={
        'sample_id':uuid.uuid4().hex,'device_id':enrollment['device_id'],
        'hostname':'real-host','platform':'Linux','cpu':30,'memory':50,'disk':50,
        'established':0,'listeners':[], 'ids_alerts':[{'source':'falco','signature':'Rule triggered','id':'abcd','severity':'warning'}],
        'firewall':'enabled','defender':'not_applicable'}
    first=client.post('/api/ingest',json=payload,headers=auth)
    second=client.post('/api/ingest',json=payload,headers=auth)
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    with storage.connect(db) as con:
        assert con.execute('SELECT COUNT(*) FROM snapshots').fetchone()[0] == 1
        assert con.execute('SELECT occurrences FROM incidents').fetchone()[0] == 1


def test_rotate_old_agent_token_no_longer_authorized(tmp_path):
    client, _ = api(tmp_path)
    csrf=sign_in(client)
    obj=client.post('/api/enrollments',json={'name':'PC'},headers=csrf).json()
    rotated=client.post('/api/enrollments/'+obj['device_id']+'/rotate',headers=csrf).json()
    assert rotated['token'] != obj['token']
    payload={'sample_id':uuid.uuid4().hex,'device_id':obj['device_id'],'hostname':'pc','platform':'Windows',
             'cpu':1,'memory':2,'disk':3,'established':0,'listeners':[],'ids_alerts':[]}
    assert client.post('/api/ingest',json=payload,headers={'Authorization':'Bearer '+obj['token']}).status_code==403
    assert client.post('/api/ingest',json=payload,headers={'Authorization':'Bearer '+rotated['token']}).status_code==200
    assert client.post('/api/enrollments/'+obj['device_id']+'/rotate').status_code==403


def test_audit_hash_chain_detects_change(tmp_path):
    client, db=api(tmp_path)
    csrf=sign_in(client)
    one=client.post('/api/enrollments',json={'name':'PC'},headers=csrf).json()
    client.delete('/api/enrollments/'+one['device_id'],headers=csrf)
    result=client.get('/api/audit').json()
    assert result['integrity']['valid'] and result['integrity']['checked']==2
    with storage.connect(db) as con:
        con.execute("UPDATE audit_events SET action='device.unrevoke' WHERE id=1")
    assert not client.get('/api/audit').json()['integrity']['valid']


def test_file_integrity_is_opt_in_and_change_only(tmp_path):
    monitored=tmp_path/'system.conf'
    monitored.write_text('secure=true')
    assert file_hash(monitored)
    alerts, baseline = monitor(str(monitored), {})
    assert alerts == [] and str(monitored) in baseline
    assert monitor(str(monitored), {'fim': baseline})[0] == []
    monitored.write_text('secure=false')
    alert, _ = monitor(str(monitored), {'fim': baseline})
    assert len(alert)==1 and alert[0]['source']=='fim'
    assert 'system.conf' in alert[0]['signature']


def test_does_not_read_oversized_file(tmp_path):
    f=tmp_path/'big.log'
    f.write_bytes(b'A'* (8*1024*1024+1))
    assert file_hash(f) is None
