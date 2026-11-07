import uuid
from fastapi.testclient import TestClient
from aegis.main import create_app
from aegis.security import hash_password


def init_client(tmp_path):
    app=create_app(str(tmp_path/'test.db'),hash_password('very strong test password 123'), 'ab'*32)
    return TestClient(app)


def test_auth_ingestion_and_real_dashboard(tmp_path):
    client=init_client(tmp_path)
    assert client.get('/api/overview').status_code==401
    assert client.get('/api/health').json()['data_source']=='real'
    login=client.post('/api/login',json={'password':'very strong test password 123'})
    assert login.status_code==200
    csrf=login.json()['csrf']
    assert client.get('/api/overview').json()['devices']==[]
    assert client.post('/api/enrollments',json={'name':'TEST'}).status_code==403
    issued=client.post('/api/enrollments',json={'name':'TEST'},headers={'X-Aegis-CSRF':csrf}).json()
    snap={'device_id':issued['device_id'],'hostname':'test-machine','platform':'Linux',
          'cpu':8,'memory':34,'disk':50,'established':1,'listeners':[],'ids_alerts':[],
          'firewall':'enabled','defender':'not_applicable'}
    assert client.post('/api/ingest',json=snap,headers={'Authorization':'Bearer invalid'}).status_code==401
    ingest=client.post('/api/ingest',json=snap,headers={'Authorization':'Bearer '+issued['token']})
    assert ingest.status_code==200 and ingest.json()['risk']==0
    overview=client.get('/api/overview').json()
    assert len(overview['devices'])==1 and overview['online_devices']==1
    assert client.delete('/api/enrollments/'+issued['device_id'],headers={'X-Aegis-CSRF':csrf}).status_code==200
    assert client.post('/api/ingest',json=snap,headers={'Authorization':'Bearer '+issued['token']}).status_code==403


def test_wrong_password_rejected(tmp_path):
    client=init_client(tmp_path)
    assert client.post('/api/login',json={'password':'not the password'}).status_code==401
