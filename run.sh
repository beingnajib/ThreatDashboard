#!/usr/bin/env bash
# Local development: Django API on :8000 and the Vite dev server on :5173
# (which proxies /api to Django). Ctrl+C stops both.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d backend/.venv ]; then
  python3 -m venv backend/.venv
  backend/.venv/bin/pip install -r backend/requirements.txt
fi
if [ ! -d frontend/node_modules ]; then
  (cd frontend && npm install)
fi

export DJANGO_DEBUG=1
backend/.venv/bin/python backend/manage.py migrate
if [ "${SEED_DEMO:-0}" = "1" ]; then
  backend/.venv/bin/python backend/manage.py seed_demo --create-users
fi

backend/.venv/bin/python backend/manage.py runserver 127.0.0.1:8000 &
API_PID=$!
trap 'kill $API_PID 2>/dev/null' EXIT
(cd frontend && npm run dev)
