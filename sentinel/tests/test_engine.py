from aegis.engine import CoordinatorAgent

def snapshot(cpu=8, memory=30, established=5, listeners=None, firewall='enabled', defender='enabled', ids_alerts=None):
    return {'metrics':{'cpu':cpu,'memory':memory,'disk':30,'established':established,'listener_count':len(listeners or [])},
            'listeners':listeners or [],'checks':{'firewall':firewall,'defender':defender},'ids_alerts':ids_alerts or []}

def test_no_false_result_with_no_telemetry():
    r=CoordinatorAgent().analyze(snapshot(),[])
    assert r['risk']==0 and r['forecast'] is None and not r['findings']
    assert 'Apprentissage' in r['model']

def test_rdp_network_bind_flagged_without_claiming_internet_exposure():
    r=CoordinatorAgent().analyze(snapshot(listeners=[{'ip':'0.0.0.0','port':3389,'process':'rdp'}]),[])
    assert any(f['code']=='SENSITIVE_PORT' for f in r['findings'])
    assert 'ne prouve pas' in r['findings'][0]['description']

def test_healthy_localhost_port_not_flagged():
    r=CoordinatorAgent().analyze(snapshot(listeners=[{'ip':'127.0.0.1','port':3389,'process':'local'}]),[])
    assert not r['findings']

def test_firewall_off_alerts():
    r=CoordinatorAgent().analyze(snapshot(firewall='disabled'),[])
    assert r['risk']>=34
    assert 'FIREWALL_DISABLED' in {f['code'] for f in r['findings']}

def test_suricata_alerts_are_not_fabricated():
    r=CoordinatorAgent().analyze(snapshot(ids_alerts=[{'source':'suricata','signature':'SUSPICIOUS DNS','id':'90001','severity':'1'}]),[])
    assert r['risk']>=34 and r['findings'][0]['evidence']['signature']=='SUSPICIOUS DNS'

def test_behavior_training_threshold():
    history=[{'cpu':10,'memory':30,'established':3,'listener_count':2,'risk':0} for _ in range(12)]
    r=CoordinatorAgent().analyze(snapshot(cpu=98),history)
    assert any(f['code']=='BEHAVIOR_SPIKE' for f in r['findings'])

def test_wazuh_level_maps_to_high():
    result=CoordinatorAgent().analyze(snapshot(ids_alerts=[{'source':'wazuh','signature':'Linux access denied','id':'1','severity':'14'}]),[])
    assert result['findings'][0]['severity']=='high'
