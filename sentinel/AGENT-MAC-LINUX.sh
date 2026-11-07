#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
if [ ! -f .agent.env ]; then
  echo 'Fichier .agent.env absent. Enrôler ce terminal depuis la console.' >&2
  exit 1
fi
python3 -m agent.collector --interval 60
