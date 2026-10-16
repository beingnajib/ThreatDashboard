"""Vercel entry point: exposes the Django WSGI application as ``app``."""
import os
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
os.environ.setdefault("THREATDASH_SERVERLESS", "1")

import django  # noqa: E402

django.setup()

from django.core.wsgi import get_wsgi_application  # noqa: E402

from threats.bootstrap import bootstrap  # noqa: E402

bootstrap()
app = get_wsgi_application()
