"""Secure local bootstrap: explicit setup, no hardcoded credentials."""
import argparse
import getpass
import os
import secrets
import uuid
from pathlib import Path
from dotenv import load_dotenv

from . import storage
from .security import hash_password, sha_token

ROOT = Path(__file__).resolve().parent.parent


def create_init(password: str | None = None):
    env = ROOT / '.env'
    agent_env = ROOT / '.agent.env'
    if env.exists():
        raise SystemExit('.env existe déjà ; initialisation annulée pour préserver les clés')
    if agent_env.exists():
        raise SystemExit('.agent.env existe déjà ; initialisation annulée')
    if password is None:
        password = getpass.getpass('Mot de passe administrateur (12 caractères minimum) : ')
        repeated = getpass.getpass('Confirmez le mot de passe : ')
        if password != repeated:
            raise SystemExit('Les mots de passe ne correspondent pas')
    pw_hash = hash_password(password)
    server_secret = secrets.token_hex(32)
    db_path = str(ROOT / 'data' / 'aegis.db')
    device_id = uuid.uuid4().hex
    token = secrets.token_urlsafe(48)
    try:
        with env.open('x',encoding='utf-8') as f:
            f.write(f'AEGIS_SECRET={server_secret}\nAEGIS_PASSWORD_HASH={pw_hash}\nAEGIS_DB_PATH={db_path}\nAEGIS_ALLOWED_HOSTS=127.0.0.1,localhost\n')
        os.chmod(env,0o600)
        storage.initialize(db_path)
        storage.issue_credential(db_path,device_id,'Appareil local',sha_token(token))
        with agent_env.open('x',encoding='utf-8') as f:
            f.write(f'AEGIS_SERVER_URL=http://127.0.0.1:8765\nAEGIS_DEVICE_ID={device_id}\nAEGIS_AGENT_TOKEN={token}\nAEGIS_INTERVAL=60\n')
        os.chmod(agent_env,0o600)
    except Exception:
        if agent_env.exists():
            agent_env.unlink()
        if env.exists():
            env.unlink()
        raise
    print('AEGIS initialisé. Secrets conservés dans .env et .agent.env (non versionnés).')
    print('Exécuter le serveur : uvicorn aegis.main:app --host 127.0.0.1 --port 8765')
    print('Exécuter le collecteur : python -m agent.collector --once')


def main():
    parser = argparse.ArgumentParser(description='AEGIS Sentinel secure initialization')
    parser.add_argument('command',choices=['init'])
    args = parser.parse_args()
    if args.command == 'init':
        create_init()


if __name__=='__main__':
    main()
