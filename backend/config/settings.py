"""
Django settings for the ThreatDashboard project.

All deployment-specific values are read from environment variables so the same
code runs in development, CI and production. See `.env.example` for the list.
"""
import os
import sys
from pathlib import Path

import dj_database_url
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent


def env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_list(name, default=""):
    return [item.strip() for item in os.environ.get(name, default).split(",") if item.strip()]


def env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


TESTING = len(sys.argv) > 1 and sys.argv[1] == "test"
DEBUG = env_bool("DJANGO_DEBUG", False)

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "")
if not SECRET_KEY:
    if DEBUG or TESTING:
        # Development/test-only fallback; production refuses to start without a key.
        SECRET_KEY = "django-insecure-development-key-do-not-use-in-production"  # nosec B105
    else:
        raise ImproperlyConfigured("DJANGO_SECRET_KEY must be set when DJANGO_DEBUG is off.")

ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]")
if TESTING:
    ALLOWED_HOSTS.append("testserver")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "corsheaders",
    "rest_framework",
    "rest_framework.authtoken",
    "django_filters",
    "threats",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

DATABASES = {
    "default": dj_database_url.config(
        default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}",
        conn_max_age=env_int("DATABASE_CONN_MAX_AGE", 60),
        conn_health_checks=True,
    )
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 10}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = os.environ.get("DJANGO_TIME_ZONE", "UTC")
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {
        "BACKEND": (
            "django.contrib.staticfiles.storage.StaticFilesStorage"
            if DEBUG or TESTING
            else "whitenoise.storage.CompressedManifestStaticFilesStorage"
        )
    },
}

# Generated reports are stored here and served only through the authenticated
# download endpoint, never as public media.
MEDIA_ROOT = Path(os.environ.get("DJANGO_MEDIA_ROOT", BASE_DIR / "media"))
MEDIA_URL = "media/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- Upload limits -----------------------------------------------------------
THREATDASH_MAX_IMPORT_BYTES = env_int("THREATDASH_MAX_IMPORT_BYTES", 20 * 1024 * 1024)
THREATDASH_MAX_IMPORT_ROWS = env_int("THREATDASH_MAX_IMPORT_ROWS", 100_000)
FILE_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024
DATA_UPLOAD_MAX_MEMORY_SIZE = THREATDASH_MAX_IMPORT_BYTES + 1024 * 1024

# --- API tokens ----------------------------------------------------------------
# Tokens older than this are rejected and must be renewed by signing in (0 = never).
THREATDASH_TOKEN_TTL_HOURS = env_int("THREATDASH_TOKEN_TTL_HOURS", 12)

# --- Threat scoring ----------------------------------------------------------
THREATDASH_RISK_HALF_LIFE_DAYS = env_int("THREATDASH_RISK_HALF_LIFE_DAYS", 30)
THREATDASH_DEFAULT_INDICATOR_TTL_DAYS = env_int("THREATDASH_DEFAULT_INDICATOR_TTL_DAYS", 90)
THREATDASH_EXFIL_BYTES = env_int("THREATDASH_EXFIL_BYTES", 500 * 1024 * 1024)

# --- Organisation profile (external risk monitoring) -------------------------
THREATDASH_ORG_NAME = os.environ.get("THREATDASH_ORG_NAME", "Example Corp")
THREATDASH_ORG_DOMAINS = env_list("THREATDASH_ORG_DOMAINS", "example.com")

# --- Response automation -----------------------------------------------------
# "simulated" updates platform state only; "webhook" forwards actions to your
# EDR/SOAR (signed with HMAC-SHA256) which performs them on real devices.
THREATDASH_RESPONSE_CONNECTOR = os.environ.get("THREATDASH_RESPONSE_CONNECTOR", "simulated")
THREATDASH_RESPONSE_WEBHOOK_URL = os.environ.get("THREATDASH_RESPONSE_WEBHOOK_URL", "")
THREATDASH_RESPONSE_WEBHOOK_SECRET = os.environ.get("THREATDASH_RESPONSE_WEBHOOK_SECRET", "")
THREATDASH_RESPONSE_TIMEOUT_SECONDS = env_int("THREATDASH_RESPONSE_TIMEOUT_SECONDS", 15)

# --- Threat feeds ------------------------------------------------------------
THREATDASH_FEED_TIMEOUT_SECONDS = env_int("THREATDASH_FEED_TIMEOUT_SECONDS", 30)
THREATDASH_FEED_MAX_BYTES = env_int("THREATDASH_FEED_MAX_BYTES", 50 * 1024 * 1024)
# Feeds may not target private/loopback/link-local addresses (SSRF guard) unless enabled.
THREATDASH_FEED_ALLOW_PRIVATE_NETWORKS = env_bool("THREATDASH_FEED_ALLOW_PRIVATE_NETWORKS", False)

# --- Natural-language query (optional LLM translation) -----------------------
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
THREATDASH_NLQ_MODEL = os.environ.get("THREATDASH_NLQ_MODEL", "claude-opus-5-5")

# --- Django REST framework ---------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "threats.permissions.ExpiringTokenAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_FILTER_BACKENDS": [
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
        "rest_framework.filters.OrderingFilter",
    ],
    "DEFAULT_PAGINATION_CLASS": "threats.pagination.StandardPagination",
    "PAGE_SIZE": 25,
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": os.environ.get("THREATDASH_THROTTLE_ANON", "30/min"),
        "user": os.environ.get("THREATDASH_THROTTLE_USER", "600/min"),
        "login": os.environ.get("THREATDASH_THROTTLE_LOGIN", "10/min"),
        "ingest": os.environ.get("THREATDASH_THROTTLE_INGEST", "600/min"),
    },
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"]
    + (["rest_framework.renderers.BrowsableAPIRenderer"] if DEBUG else []),
    "TEST_REQUEST_DEFAULT_FORMAT": "json",
}
if TESTING:
    # Keep throttling out of the way of the test-suite.
    REST_FRAMEWORK["DEFAULT_THROTTLE_CLASSES"] = []

# --- CORS / CSRF -------------------------------------------------------------
CORS_ALLOWED_ORIGINS = env_list("DJANGO_CORS_ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
CSRF_TRUSTED_ORIGINS = env_list("DJANGO_CSRF_TRUSTED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")

# --- Security hardening ------------------------------------------------------
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = env_bool("DJANGO_SECURE_COOKIES", not DEBUG and not TESTING)
CSRF_COOKIE_SECURE = SESSION_COOKIE_SECURE
SECURE_SSL_REDIRECT = env_bool("DJANGO_SECURE_SSL_REDIRECT", False)
# The container healthcheck calls the API over plain HTTP from inside the container.
SECURE_REDIRECT_EXEMPT = [r"^api/health/$"]
# Once HTTPS is enforced, send HSTS too unless explicitly configured otherwise.
SECURE_HSTS_SECONDS = env_int("DJANGO_SECURE_HSTS_SECONDS", 31536000 if SECURE_SSL_REDIRECT else 0)
SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool("DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS", False)
SECURE_HSTS_PRELOAD = env_bool("DJANGO_SECURE_HSTS_PRELOAD", False)
BEHIND_PROXY = env_bool("DJANGO_BEHIND_PROXY", False)
if BEHIND_PROXY:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    USE_X_FORWARDED_HOST = True
# Number of trusted proxies that append to X-Forwarded-For (nginx = 1; add one per
# load balancer in front of it). The client IP is read that many entries from the
# right, so anything the client puts in the header itself is ignored. Used for
# rate limiting and audit logging.
REST_FRAMEWORK["NUM_PROXIES"] = env_int("DJANGO_NUM_PROXIES", 1) if BEHIND_PROXY else 0

# --- Cache -------------------------------------------------------------------
# Rate-limit counters must be shared by every gunicorn worker and survive
# restarts, so production uses a database table (created by migration 0002).
CACHES = {
    "default": (
        {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
        if TESTING
        else {"BACKEND": "django.core.cache.backends.db.DatabaseCache", "LOCATION": "threatdash_cache"}
    )
}

# --- Logging -----------------------------------------------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {"format": "%(asctime)s %(levelname)s %(name)s %(message)s"},
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "standard"},
    },
    "root": {"handlers": ["console"], "level": os.environ.get("DJANGO_LOG_LEVEL", "INFO")},
    "loggers": {
        "django.request": {"handlers": ["console"], "level": "WARNING", "propagate": False},
        "threats": {"handlers": ["console"], "level": os.environ.get("THREATDASH_LOG_LEVEL", "INFO"), "propagate": False},
    },
}
