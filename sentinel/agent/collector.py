"""Endpoint telemetry collection: no shell execution from remote input, no auto-blocking.

For Windows, macOS and Linux. Phones/tablets only access the PWA dashboard.
"""
import argparse
import json
import os
import platform
import socket
import subprocess
import sys
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import psutil
from dotenv import load_dotenv
from .integrity import monitor

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / '.agent.env')


def run_output(command: list[str], timeout: int = 5) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True,timeout=timeout, check=False,
                                creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        return result.stdout.strip()[:12000] if result.returncode == 0 else ''
    except (OSError,subprocess.TimeoutExpired,UnicodeError):
        return ''


def firewall_status() -> str:
    sysname = platform.system()
    if sysname == 'Windows':
        raw = run_output(['powershell','-NoProfile','-NonInteractive','-Command',
                          'Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled | ConvertTo-Json -Compress'])
        try:
            value = json.loads(raw)
            statuses = value if isinstance(value,list) else [value]
            return 'enabled' if statuses and all(x is True for x in statuses) else 'disabled' if False in statuses else 'unknown'
        except (json.JSONDecodeError,TypeError):
            return 'unknown'
    if sysname == 'Darwin':
        output = run_output(['/usr/libexec/ApplicationFirewall/socketfilterfw','--getglobalstate']).lower()
        if 'enabled' in output or 'is on' in output:
            return 'enabled'
        if 'disabled' in output or 'is off' in output:
            return 'disabled'
        return 'unknown'
    if sysname == 'Linux':
        ufw = run_output(['ufw','status']).lower()
        if 'status: active' in ufw:
            return 'enabled'
        if 'status: inactive' in ufw:
            # A different firewall may be active; do not assert disabled.
            pass
        firewalld = run_output(['firewall-cmd','--state']).lower()
        if firewalld == 'running':
            return 'enabled'
        nft = run_output(['nft','list','ruleset'])
        if 'hook input' in nft and ('drop' in nft or 'reject' in nft):
            return 'enabled'
    return 'unknown'


def defender_status() -> str:
    if platform.system() != 'Windows':
        return 'not_applicable'
    raw = run_output(['powershell','-NoProfile','-NonInteractive','-Command',
                      'Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json -Compress'])
    try:
        value = json.loads(raw)
        if value.get('AntivirusEnabled') is False or value.get('RealTimeProtectionEnabled') is False:
            return 'disabled'
        if value.get('AntivirusEnabled') is True and value.get('RealTimeProtectionEnabled') is True:
            return 'enabled'
    except (ValueError,AttributeError):
        pass
    return 'unknown'


def interfaces():
    """Only metadata. No payload capture and no remote command input."""
    listeners = []
    established = 0
    seen = set()
    pid_cache = {}
    try:
        connections = psutil.net_connections(kind='inet')
    except (psutil.AccessDenied, psutil.Error, OSError):
        return listeners, established
    for conn in connections:
        if conn.status == 'ESTABLISHED':
            established += 1
        if conn.status != 'LISTEN' or not conn.laddr:
            continue
        ip = str(conn.laddr.ip)
        port = int(conn.laddr.port)
        key = (ip,port,conn.pid)
        if key in seen:
            continue
        seen.add(key)
        if conn.pid not in pid_cache:
            try:
                pid_cache[conn.pid] = psutil.Process(conn.pid).name() if conn.pid else ''
            except (psutil.Error,OSError):
                pid_cache[conn.pid] = ''
        listeners.append({'ip':ip[:80],'port':port,'process':pid_cache[conn.pid][:120]})
        if len(listeners)>=250:
            break
    return listeners, min(established,1000000)


def log_alerts(path: str, source: str, state: dict, max_alerts: int = 25) -> tuple[list[dict], dict]:
    """Read new newline-delimited JSON security alerts, with rotation-safe cursor."""
    alerts = []
    updated = dict(state)
    if not path:
        return alerts,updated
    fpath = Path(path)
    try:
        stat = fpath.stat()
        signature = f'{stat.st_dev}:{stat.st_ino}'
        old = state.get(source,{})
        offset = int(old.get('offset',0)) if old.get('signature') == signature else 0
        if offset > stat.st_size:
            offset = 0
        with fpath.open('r',encoding='utf-8',errors='replace') as handle:
            handle.seek(offset)
            # Bounded time and memory per cycle; keep continuation cursor.
            bytes_scanned = 0
            while len(alerts) < max_alerts and bytes_scanned < 250_000:
                start = handle.tell()
                line = handle.readline(10000)
                if not line:
                    break
                if not line.endswith('\n'):
                    # Incomplete line may still be growing. Skip *oversized* lines,
                    # otherwise resume safely on next run.
                    if len(line) >= 9999:
                        handle.readline(250_000)
                        bytes_scanned += 10000
                        continue
                    handle.seek(start)
                    break
                bytes_scanned += len(line)
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(obj,dict):
                    continue
                if source == 'suricata' and obj.get('event_type') == 'alert':
                    a = obj.get('alert',{})
                    if isinstance(a,dict):
                        alerts.append({'source':'suricata','signature':str(a.get('signature','Alerte réseau'))[:250],
                                       'id':str(a.get('signature_id',''))[:80], 'severity':str(a.get('severity',3))[:30]})
                elif source == 'wazuh' and isinstance(obj.get('rule'),dict):
                    rule = obj['rule']
                    alerts.append({'source':'wazuh','signature':str(rule.get('description','Alerte Wazuh'))[:250],
                                   'id':str(rule.get('id',''))[:80], 'severity':str(rule.get('level',0))[:30]})
                elif source == 'falco' and ('rule' in obj or 'priority' in obj):
                    alerts.append({'source':'falco','signature':str(obj.get('rule','Alerte comportementale'))[:250],
                                   'id':str(obj.get('rule',''))[:80], 'severity':str(obj.get('priority','warning'))[:30]})
            updated[source] = {'signature':signature,'offset':handle.tell()}
    except (OSError,ValueError):
        pass
    return alerts,updated


def osquery_alerts() -> list[dict]:
    """Optional osquery integration: only one fixed, read-only documented SQL query."""
    executable = os.getenv('AEGIS_OSQUERY_BIN','')
    if not executable:
        return []
    raw = run_output([executable,'--json','SELECT pid, name, path FROM processes WHERE on_disk = 0 LIMIT 20;'],timeout=8)
    try:
        rows = json.loads(raw)
    except ValueError:
        return []
    if not isinstance(rows,list):
        return []
    alerts = []
    for item in rows[:20]:
        if not isinstance(item,dict):
            continue
        name = str(item.get('name','processus'))[:100]
        pid = str(item.get('pid',''))[:20]
        alerts.append({'source':'osquery','signature':f'Processus avec binaire absent du disque : {name} (PID {pid})',
                       'id':f'{pid}:{name}'[:80],'severity':'medium'})
    return alerts


def collect(state: dict) -> tuple[dict,dict]:
    listeners, established = interfaces()
    try:
        disk_root = Path(os.environ.get('SYSTEMDRIVE','C:') + '\\' if platform.system()=='Windows' else '/')
        disk_percent = psutil.disk_usage(str(disk_root)).percent
    except (psutil.Error,OSError):
        disk_percent = 0
    suricata,st = log_alerts(os.getenv('AEGIS_SURICATA_EVE_PATH',''),'suricata',state)
    falco,st = log_alerts(os.getenv('AEGIS_FALCO_JSON_PATH',''),'falco',st)
    wazuh,st = log_alerts(os.getenv('AEGIS_WAZUH_ALERTS_JSON_PATH',''),'wazuh',st)
    osquery = osquery_alerts()
    fim, fim_state = monitor(os.getenv('AEGIS_FIM_PATHS', ''), state)
    st['fim'] = fim_state
    payload = {'sample_id': uuid.uuid4().hex, 'device_id':os.environ['AEGIS_DEVICE_ID'],
               'hostname':socket.gethostname()[:120] or 'unknown',
               'platform':f'{platform.system()} {platform.release()}'[:120],
               'cpu':round(psutil.cpu_percent(interval=0.3),1),
               'memory':round(psutil.virtual_memory().percent,1),
               'disk':round(disk_percent,1),
               'established':established,
               'listeners':listeners,
               'firewall':firewall_status(),
               'defender':defender_status(),
               'ids_alerts':(suricata+falco+wazuh+osquery+fim)[:50]}
    return payload,st


def validate_server_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('AEGIS_SERVER_URL invalide')
    if parsed.scheme == 'http' and parsed.hostname not in ('127.0.0.1','localhost','::1'):
        raise ValueError('HTTPS obligatoire vers un serveur distant')
    if parsed.path not in ('','/') or parsed.query or parsed.fragment:
        raise ValueError('AEGIS_SERVER_URL doit être une origine, sans chemin')
    return url.rstrip('/')


def publish(snapshot: dict) -> dict:
    server = validate_server_url(os.environ['AEGIS_SERVER_URL'])
    token = os.environ['AEGIS_AGENT_TOKEN']
    if len(token)<40:
        raise ValueError('Jeton agent invalide')
    data = json.dumps(snapshot,separators=(',',':')).encode()
    req = urllib.request.Request(server+'/api/ingest', data=data,
                                 headers={'Content-Type':'application/json','Authorization':f'Bearer {token}'},method='POST')
    with urllib.request.urlopen(req,timeout=12) as resp:
        if resp.status != 200:
            raise RuntimeError(f'Serveur HTTP {resp.status}')
        return json.loads(resp.read(4096))


def load_state(path: Path) -> dict:
    try:
        data=json.loads(path.read_text(encoding='utf-8'))
        return data if isinstance(data,dict) else {}
    except (FileNotFoundError,ValueError,OSError):
        return {}


def save_state(path: Path, state: dict):
    path.parent.mkdir(parents=True,exist_ok=True)
    temp = path.with_suffix('.tmp')
    with temp.open('w',encoding='utf-8') as f:
        json.dump(state,f)
    os.chmod(temp,0o600)
    temp.replace(path)


def main():
    p = argparse.ArgumentParser(description='Collecteur AEGIS en lecture seule')
    p.add_argument('--once',action='store_true',help='Une collecte, puis arrêt')
    p.add_argument('--interval',type=int,default=int(os.getenv('AEGIS_INTERVAL','60')))
    args = p.parse_args()
    if not all(os.getenv(k) for k in ('AEGIS_SERVER_URL','AEGIS_AGENT_TOKEN','AEGIS_DEVICE_ID')):
        raise SystemExit('Configurer .agent.env (jeton depuis le tableau de bord)')
    if args.interval < 30:
        raise SystemExit('Intervalle minimum : 30 secondes')
    statepath = Path(os.environ.get('AEGIS_AGENT_STATE',str(ROOT/'agent'/'.state.json')))
    while True:
        try:
            prev = load_state(statepath)
            snapshot, current = collect(prev)
            pending = prev.get('pending', [])
            if not isinstance(pending, list):
                pending = []
            pending = [p for p in pending if isinstance(p, dict) and p.get('sample_id')]
            pending.append(snapshot)
            # Keep a bounded local spool. Always disclose data loss on overflow.
            if len(pending) > 96:
                dropped = len(pending)-96
                print(f"ATTENTION : file d'attente pleine, {dropped} mesure(s) ancienne(s) supprimée(s)",
                      file=sys.stderr,flush=True)
                pending = pending[-96:]
            current['pending'] = pending
            save_state(statepath, current)
            sent = 0
            for queued in pending[:20]:
                result = publish(queued)
                pending.pop(0)
                current['pending'] = pending
                save_state(statepath,current)
                sent += 1
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {sent} mesure(s) confirmée(s) ; file d'attente {len(pending)}",flush=True)
        except (OSError,urllib.error.URLError,ValueError,KeyError,RuntimeError) as exc:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] collecte non transmise : {type(exc).__name__}: {exc}",file=sys.stderr,flush=True)
        if args.once:
            break
        time.sleep(args.interval)


if __name__=='__main__':
    main()
