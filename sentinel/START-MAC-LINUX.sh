#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
if [ ! -f .env ]; then
  echo 'Installation des bibliothèques Python et génération des clés locales...'
  python3 -m pip install -r requirements.txt
  python3 -m aegis.cli init
fi
echo 'Console privée sur http://127.0.0.1:8765'
python3 -m uvicorn aegis.main:app --host 127.0.0.1 --port 8765
