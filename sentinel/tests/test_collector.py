from agent.collector import validate_server_url,log_alerts
import pytest
import json


def test_transport_checks():
    assert validate_server_url('http://127.0.0.1:8765')=='http://127.0.0.1:8765'
    with pytest.raises(ValueError):validate_server_url('http://public.example.org:8765')
    assert validate_server_url('https://aegis.example.org')=='https://aegis.example.org'


def test_real_eve_json_reader(tmp_path):
    source=tmp_path/'eve.json'
    sample={'event_type':'alert','alert':{'signature':'Threat signal','signature_id':17,'severity':1}}
    source.write_text(json.dumps(sample)+'\n')
    alerts,state=log_alerts(str(source),'suricata',{})
    assert len(alerts)==1 and alerts[0]['signature']=='Threat signal'
    second,_=log_alerts(str(source),'suricata',state)
    assert second==[]

def test_wazuh_json_reader(tmp_path):
    source=tmp_path/'alerts.json'
    source.write_text(json.dumps({'rule':{'id':'200001','level':14,'description':'Unauthorized login'}})+'\n')
    alerts,_=log_alerts(str(source),'wazuh',{})
    assert alerts[0]['source']=='wazuh'
    assert alerts[0]['severity']=='14'
