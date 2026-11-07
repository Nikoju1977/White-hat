"""AEGIS secure-first web API. Localhost by default; use TLS reverse proxy for remote devices."""
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import storage, audit
from .engine import CoordinatorAgent
from .security import check_password, sha_token, sign_session, verify_session

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / '.env')


class LoginRequest(BaseModel):
    password: str = Field(min_length=1, max_length=512)


class EnrollmentRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)


class Listener(BaseModel):
    ip: str = Field(max_length=80)
    port: int = Field(ge=0, le=65535)
    process: str = Field(default='', max_length=120)


class IDSAlert(BaseModel):
    source: str = Field(max_length=30)
    signature: str = Field(max_length=250)
    id: str = Field(default='', max_length=80)
    severity: str | int = Field(default=3)


class Snapshot(BaseModel):
    sample_id: str | None = Field(default=None, pattern=r'^[0-9a-f]{32}$')
    device_id: str = Field(min_length=1, max_length=80)
    hostname: str = Field(min_length=1, max_length=120)
    platform: str = Field(min_length=1, max_length=120)
    cpu: float = Field(ge=0,le=100)
    memory: float = Field(ge=0,le=100)
    disk: float = Field(ge=0,le=100)
    established: int = Field(ge=0,le=1000000)
    listeners: list[Listener] = Field(default_factory=list, max_length=250)
    ids_alerts: list[IDSAlert] = Field(default_factory=list, max_length=50)
    firewall: str = Field(default='unknown', pattern=r'^(enabled|disabled|unknown)$')
    defender: str = Field(default='unknown', pattern=r'^(enabled|disabled|unknown|not_applicable)$')


class IncidentAction(BaseModel):
    status: str = Field(pattern=r'^(open|resolved)$')


def create_app(db_path: str | None = None, password_hash: str | None = None, secret: str | None = None) -> FastAPI:
    db_path = db_path or os.environ.get('AEGIS_DB_PATH',str(ROOT / 'data' / 'aegis.db'))
    password_hash = password_hash or os.environ.get('AEGIS_PASSWORD_HASH','')
    secret = secret or os.environ.get('AEGIS_SECRET','')
    if len(secret) != 64 or not password_hash.startswith('scrypt$'):
        raise RuntimeError('Initialisation requise : python -m aegis.cli init')
    try:
        bytes.fromhex(secret)
    except ValueError as exc:
        raise RuntimeError('AEGIS_SECRET invalide') from exc
    storage.initialize(db_path)
    app = FastAPI(title='AEGIS SENTINEL AI', docs_url=None, redoc_url=None, openapi_url=None)
    hosts = [x.strip() for x in os.environ.get('AEGIS_ALLOWED_HOSTS','127.0.0.1,localhost,testserver').split(',') if x.strip()]
    app.add_middleware(TrustedHostMiddleware,allowed_hosts=hosts)
    app.state.db_path = db_path
    app.state.failed_logins = defaultdict(deque)
    coordinator = CoordinatorAgent()

    @app.middleware('http')
    async def security_headers(request: Request, call_next):
        host = (request.url.hostname or '').lower()
        local = host in ('localhost','127.0.0.1','::1','testserver')
        if not local and request.url.scheme != 'https':
            return Response('HTTPS obligatoire pour les accès distants',status_code=403)
        if request.url.path.startswith('/api/'):
            clen = request.headers.get('content-length')
            if clen and (not clen.isdigit() or int(clen) > 1_000_000):
                return Response('Requête trop volumineuse',status_code=413)
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store' if request.url.path.startswith('/api/') else 'no-cache'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        if request.url.scheme == 'https':
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response

    def admin(request: Request, require_csrf: bool = False):
        payload = verify_session(secret, request.cookies.get('aegis_session'))
        if not payload:
            raise HTTPException(401,'Session manquante ou expirée')
        if require_csrf:
            supplied = request.headers.get('X-Aegis-CSRF','')
            if not hmac.compare_digest(supplied,payload['csrf']):
                raise HTTPException(403,'Jeton CSRF incorrect')
        return payload

    @app.post('/api/login')
    def login(body: LoginRequest, request: Request, response: Response):
        remote = request.client.host if request.client else 'unknown'
        now = time.monotonic()
        attempts = app.state.failed_logins[remote]
        while attempts and attempts[0] < now - 900:
            attempts.popleft()
        if len(attempts) >= 5:
            raise HTTPException(429,'Trop de tentatives : réessayez dans 15 minutes')
        if not check_password(body.password,password_hash):
            attempts.append(now)
            raise HTTPException(401,'Identifiants invalides')
        attempts.clear()
        cookie, csrf = sign_session(secret)
        response.set_cookie('aegis_session',cookie,httponly=True,secure=request.url.scheme=='https',
                            samesite='strict',max_age=28800,path='/')
        return {'authenticated':True,'csrf':csrf}

    @app.get('/api/me')
    def me(request: Request):
        auth = admin(request)
        return {'authenticated':True,'csrf':auth['csrf'],'mode':'read-write'}

    @app.post('/api/logout')
    def logout(request: Request, response: Response):
        admin(request,require_csrf=True)
        response.delete_cookie('aegis_session',path='/')
        return {'ok':True}

    @app.get('/api/health')
    def health():
        return {'service':'AEGIS Sentinel','status':'running','data_source':'real'}

    @app.get('/api/audit')
    def audit_events(request: Request):
        admin(request)
        with storage.connect(db_path) as con:
            all_rows = [dict(r) for r in con.execute('SELECT * FROM audit_events ORDER BY id ASC')]
        integrity = audit.verify(all_rows)
        visible = [{k: v for k, v in r.items() if k != 'details_json'} |
                   {'details': json.loads(r['details_json'])} for r in all_rows[-100:]]
        return {'integrity': integrity, 'events': list(reversed(visible)),
                'note': 'Chaîne de hachage locale : un administrateur du serveur peut la réécrire.'}

    @app.get('/api/overview')
    def overview(request: Request):
        admin(request)
        with storage.connect(db_path) as con:
            devices = con.execute('SELECT * FROM devices ORDER BY last_seen DESC LIMIT 250').fetchall()
            entries = []
            for r in devices:
                d = dict(r)
                d['metrics'] = json.loads(d.pop('metrics_json'))
                d['checks'] = json.loads(d.pop('checks_json'))
                d['online'] = time.time() - d['last_seen'] < 210
                entries.append(d)
            open_count = con.execute("SELECT COUNT(*) FROM incidents WHERE status='open'").fetchone()[0]
            critical_count = con.execute("SELECT COUNT(*) FROM incidents WHERE status='open' AND severity IN ('critical','high')").fetchone()[0]
            authorized = con.execute("SELECT COUNT(*) FROM credentials WHERE active=1").fetchone()[0]
        return {'devices':entries,'open_incidents':open_count,'urgent_incidents':critical_count,
                'enrolled_agents':authorized,'online_devices':sum(d['online'] for d in entries),
                'generated_at':time.time()}

    @app.get('/api/incidents')
    def incidents(request: Request, limit: int = 100, status: str = 'all'):
        admin(request)
        if status not in ('all','open','resolved'):
            raise HTTPException(400,'Statut incorrect')
        limit = max(1,min(limit,250))
        query = 'SELECT * FROM incidents'
        args = []
        if status != 'all':
            query += ' WHERE status=?'
            args.append(status)
        query += ' ORDER BY last_seen DESC LIMIT ?'
        args.append(limit)
        with storage.connect(db_path) as con:
            rows = con.execute(query,args).fetchall()
            return [{**dict(r),'evidence':json.loads(r['evidence_json'])} for r in rows]

    @app.post('/api/incidents/{incident_id}/status')
    def resolve(incident_id: int, body: IncidentAction, request: Request):
        admin(request,require_csrf=True)
        with storage.connect(db_path) as con:
            cur = con.execute('UPDATE incidents SET status=?,resolved_at=? WHERE id=?',
                              (body.status,time.time() if body.status=='resolved' else None,incident_id))
            if cur.rowcount < 1:
                raise HTTPException(404,'Incident introuvable')
            audit.append(con,'admin','incident.status',str(incident_id),{'status':body.status})
        return {'ok':True,'status':body.status}

    @app.get('/api/history/{device_id}')
    def history(device_id: str, request: Request):
        admin(request)
        with storage.connect(db_path) as con:
            exists = con.execute('SELECT 1 FROM devices WHERE device_id=?',(device_id,)).fetchone()
            if not exists:
                raise HTTPException(404,'Appareil inconnu')
            return storage.latest_history(con,device_id,120)

    @app.post('/api/advice')
    def advice(request: Request):
        admin(request,require_csrf=True)
        from .advisor import local_advice
        with storage.connect(db_path) as con:
            devices = [dict(r) for r in con.execute('SELECT name,platform,last_risk,last_model FROM devices ORDER BY last_seen DESC LIMIT 25')]
            incidents = [dict(r) for r in con.execute("SELECT title,severity,description FROM incidents WHERE status='open' ORDER BY last_seen DESC LIMIT 15")]
        try:
            return local_advice(devices,incidents)
        except RuntimeError as exc:
            raise HTTPException(503,str(exc)) from exc

    @app.get('/api/enrollments')
    def enrollments(request: Request):
        admin(request)
        with storage.connect(db_path) as con:
            return [dict(x) for x in con.execute('SELECT device_id,name,active,created FROM credentials ORDER BY created DESC')]

    @app.post('/api/enrollments')
    def enroll(body: EnrollmentRequest, request: Request):
        admin(request,require_csrf=True)
        device_id = uuid.uuid4().hex
        token = secrets.token_urlsafe(48)
        with storage.connect(db_path) as con:
            con.execute('INSERT INTO credentials(device_id,name,token_sha,created) VALUES(?,?,?,?)',
                        (device_id,body.name.strip(),sha_token(token),time.time()))
            audit.append(con,'admin','device.enroll',device_id,{'name':body.name.strip()})
        return {'device_id':device_id,'token':token,'warning':'Jeton affiché une seule fois. Ne pas le publier.'}

    @app.post('/api/enrollments/{device_id}/rotate')
    def rotate(device_id: str, request: Request):
        admin(request, require_csrf=True)
        token = secrets.token_urlsafe(48)
        with storage.connect(db_path) as con:
            cur = con.execute('UPDATE credentials SET token_sha=? WHERE device_id=? AND active=1',
                              (sha_token(token),device_id))
            if cur.rowcount != 1:
                raise HTTPException(404,'Appareil non trouvé ou révoqué')
            audit.append(con,'admin','device.rotate',device_id)
        return {'device_id':device_id,'token':token,
                'warning':'Ancien jeton invalidé. Ne stockez pas ce nouveau jeton dans un dépôt Git.'}

    @app.delete('/api/enrollments/{device_id}')
    def revoke(device_id: str, request: Request):
        admin(request,require_csrf=True)
        with storage.connect(db_path) as con:
            cur = con.execute('UPDATE credentials SET active=0 WHERE device_id=?',(device_id,))
            if cur.rowcount < 1:
                raise HTTPException(404,'Appareil inconnu')
            audit.append(con,'admin','device.revoke',device_id)
        return {'ok':True}

    @app.post('/api/ingest')
    def ingest(body: Snapshot, request: Request):
        auth = request.headers.get('Authorization','')
        scheme, _, token = auth.partition(' ')
        if scheme.lower() != 'bearer' or len(token) < 40 or len(token) > 256:
            raise HTTPException(401,'Jeton collecteur absent')
        cred = storage.credential_for_token(db_path,sha_token(token))
        if not cred or not hmac.compare_digest(cred['device_id'],body.device_id):
            raise HTTPException(403,'Collecteur non autorisé')
        if body.sample_id:
            replay = storage.get_receipt(db_path, body.device_id, body.sample_id)
            if replay is not None:
                return replay
        data = body.model_dump()
        metrics = {key:data[key] for key in ('cpu','memory','disk','established')}
        metrics['listener_count'] = len(data['listeners'])
        checks = {'firewall':data['firewall'],'defender':data['defender']}
        snapshot = {'metrics':metrics,'checks':checks,'listeners':data['listeners'],'ids_alerts':data['ids_alerts']}
        with storage.connect(db_path) as con:
            history = storage.latest_history(con,body.device_id,100)
        result = coordinator.analyze(snapshot,history)
        response = {'accepted':True,'risk':result['risk'],'forecast':result['forecast'],
                    'finding_count':len(result['findings']),'model':result['model']}
        return storage.save_snapshot(db_path,body.device_id,body.hostname,body.platform,metrics,checks,
                                     result['risk'],result['forecast'],result['model'],result['findings'],
                                     sample_id=body.sample_id,response=response)

    app.mount('/static',StaticFiles(directory=str(ROOT / 'web')),name='static')

    @app.get('/')
    def index():
        return FileResponse(ROOT / 'web' / 'index.html')

    @app.get('/manifest.webmanifest')
    def manifest():
        return FileResponse(ROOT / 'web' / 'manifest.webmanifest',media_type='application/manifest+json')

    @app.get('/service-worker.js')
    def service_worker():
        response = FileResponse(ROOT / 'web' / 'service-worker.js',media_type='text/javascript')
        response.headers['Service-Worker-Allowed'] = '/'
        return response

    return app


# ASGI entry point only after a deliberate secure init.
app = create_app() if os.environ.get('AEGIS_SECRET') else None
