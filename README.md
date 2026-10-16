# ThreatDashboard

![GitHub top language](https://img.shields.io/github/languages/top/beingnajib/ThreatDashboard)
![GitHub issues](https://img.shields.io/github/issues/beingnajib/ThreatDashboard)
[![GitHub stars](https://img.shields.io/github/stars/beingnajib/ThreatDashboard)](https://github.com/beingnajib/ThreatDashboard/stargazers)
![License](https://img.shields.io/badge/license-MIT-green)

ThreatDashboard is a threat monitoring, intelligence and response platform. It fuses telemetry from endpoints, cloud, identity, network and email into one view. Related detections become prioritised incidents. Analysts can attribute activity, contain hosts and track audit readiness in the same place.

- **Backend:** Django 5 + Django REST Framework (PostgreSQL or SQLite)
- **Frontend:** React 18 + Vite + Chart.js
- **Deployment:** Docker Compose (PostgreSQL, gunicorn API, scheduler worker, nginx)

## Features

### Visibility and data integration
- **Cross-domain data fusion.** One normalised event schema for endpoint/EDR, AWS CloudTrail, Microsoft Entra ID sign-ins, Azure activity logs, firewall/NDR and email gateways. Log shippers push to `/api/events/ingest/` using per-connector ingestion keys; only the key hashes are stored.
- **Automated asset discovery.** Assets are built passively from agent, cloud and network telemetry. Devices seen only on the wire are flagged as **shadow IT**.
- **Attack-path visualisation.** Each incident gets a node graph laid out by MITRE ATT&CK tactic. It shows the entry point, lateral movement, C2 and where data left the network.

### Analytics and triage
- **Incident deduplication.** Alerts that share an asset, identity, external IP or indicator within 48 hours are bundled into one case. Each case is prioritised by severity, kill-chain breadth, asset criticality and attribution.
- **Dynamic risk scoring.** Indicator risk combines severity or CVSS, confidence, Admiralty source reliability, recency decay, sightings, ATT&CK context and enrichment (DGA heuristics, suspicious TLDs, executable downloads). Asset risk adds open alerts, CVSS, shadow-IT status and a behavioural baseline z-score.
- **Behavioural detections:** brute force and password spraying, impossible travel, data exfiltration volume, cloud logging tampering, IAM privilege escalation, and volume anomalies and trending threat categories.
- **Natural-language querying.** Questions like *"failed sign-ins by country in the last 24 hours"* become a whitelisted query spec, which is executed and charted. A keyword parser always works. If `ANTHROPIC_API_KEY` is set, Claude does the translation using structured output against the same schema, so it can never produce raw SQL.

### Threat intelligence and attribution
- **Indicator management:** IPv4/IPv6, domains, URLs, MD5/SHA-1/SHA-256, emails and CVEs. Defanged input is refanged automatically. Includes bulk lookup, related-indicator pivoting and CSV/JSON/**STIX 2.1** export.
- **Imports:** CSV, JSON / JSON Lines, XML (parsed with `defusedxml`), STIX 2.1 bundles and plain-text lists. Column aliases cover most feed formats, and re-imports merge sightings.
- **Global IoC feeds.** The scheduler pulls abuse.ch URLhaus, Feodo Tracker, SSLBL, OpenPhish and the CISA KEV catalogue on configurable intervals (all disabled until you enable them).
- **Firewall blocklists.** `/api/indicators/blocklist/?type=ip|domain|url|hash` serves an EDL-style list for perimeter blocking.
- **Actor attribution.** Incidents and indicators are scored against threat actors (APT28, APT29, Lazarus, FIN7, Sandworm, LockBit, Scattered Spider…) on shared infrastructure, TTP overlap and malware families.
- **External risk:** typosquat generation with 10 fuzzers (optionally DNS-resolved), leaked-credential ingestion (plaintext passwords are discarded; only a 5-character SHA-1 prefix is kept) and dark-web/leak-site telemetry.

### Response and automation
- **One-click host isolation** and release, plus process kill, forensic collection, indicator blocking, account disable, password reset and session revocation.
- **SOAR playbooks**, e.g. *Contain compromised host*, *Compromised account response*, *Force global password reset* (requires explicit confirmation) and *Block indicator at perimeter*.
- **Live response console:** a browser terminal for managed endpoints. Commands are allow-listed (`ps`, `netstat`, `memdump`, `hash`, `getfile`, `autoruns`…) and shell metacharacters are rejected.
- Every action is recorded as a `ResponseAction` and in the append-only **audit log**. Running actions requires the `responders` group; the terminal requires `forensics`.

> **About real-world effect.** By default, response actions use the **simulated** connector: platform state changes (assets are marked isolated, indicators are tagged as blocked) but no device is touched. Set `THREATDASH_RESPONSE_CONNECTOR=webhook` to POST HMAC-signed actions to your EDR/SOAR (CrowdStrike, Defender, SentinelOne, Tines, XSOAR…). That system then isolates the host or runs the command and replies `{"status": "succeeded", "output": "…"}`.

### Business intelligence and compliance
- **Executive view:** a 0-100 corporate posture score with a 30-day trend, a business-unit × security-domain **risk heatmap**, and findings written in plain language.
- **Compliance tracking.** Controls from **NIST CSF 2.0, ISO/IEC 27001:2022, SOC 2 and GDPR** are mapped to automated checks on live data: asset inventory, EDR coverage, vulnerabilities, threat intel freshness, monitoring coverage, detection timeliness, incident response, credential exposure and the 72-hour breach window. Manual controls and overrides are supported.
- **Reports** in PDF, DOCX, XLSX, CSV and JSON, served only through an authenticated download endpoint.

## Quick start

### Docker (production-style)

```bash
cp .env.example .env            # set DJANGO_SECRET_KEY and POSTGRES_PASSWORD
docker compose up -d --build
docker compose exec backend python manage.py createsuperuser
docker compose exec backend python manage.py seed_demo   # optional demo dataset
```

Open <http://localhost:8080>.

### Local development

```bash
SEED_DEMO=1 ./run.sh            # creates venv + node_modules, migrates, seeds, starts both servers
```

Open <http://localhost:5173>. `seed_demo --create-users` prints random passwords for `admin` (staff), `responder` and `analyst`.

Running the pieces by hand:

```bash
cd backend && python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
DJANGO_DEBUG=1 python manage.py migrate
DJANGO_DEBUG=1 python manage.py seed_demo --create-users
DJANGO_DEBUG=1 python manage.py runserver
# in another terminal
cd frontend && npm install && npm run dev
```

## Sending telemetry

Create a connector under **Feeds & connectors** (staff only) and copy the key that is shown once. Then:

```bash
curl -X POST https://threatdash.example.com/api/events/ingest/ \
  -H "X-Ingest-Key: tdk_..." -H "Content-Type: application/json" \
  -d '[{"domain": "endpoint", "event_type": "process_start", "hostname": "ws-01",
        "username": "alice@example.com", "process": "powershell.exe -enc ...", "severity": "high"}]'
```

The connector's format decides the parser:

| Format | Payload |
| --- | --- |
| `generic`, `edr`, `firewall`, `email_gateway` | list or `{"events": [...]}` with `domain`, `event_type`, `timestamp`, `hostname`, `username`, `src_ip`, `dst_ip`, `domain_name`, `url`, `file_hash`, `process`, `bytes_out`, `mitre_technique`, … |
| `aws_cloudtrail` | CloudTrail `{"Records": [...]}` |
| `azure_signin` | Entra ID sign-in logs (Graph or diagnostic-settings shape) |
| `azure_activity` | Azure activity log (`{"value": [...]}` or records) |
| `dark_web` | `[{"title", "detail", "severity", "kind", "url", "observed_at"}]` → external exposures |

## Background jobs

The `scheduler` service runs `python manage.py run_scheduler`. Every minute it pulls due feeds. Every 15 minutes it expires stale indicators, recomputes time-decayed risk scores and re-evaluates compliance. Once a day it runs a typosquat scan. The same jobs can be run on demand with `pull_feeds` and `threat_maintenance`.

## Configuration

All settings are environment variables; see [`.env.example`](.env.example). The most important:

| Variable | Purpose |
| --- | --- |
| `DJANGO_SECRET_KEY` | Required whenever `DJANGO_DEBUG` is off |
| `DATABASE_URL` | e.g. `postgres://user:pass@host:5432/db` (SQLite by default) |
| `DJANGO_ALLOWED_HOSTS`, `DJANGO_CSRF_TRUSTED_ORIGINS`, `DJANGO_CORS_ALLOWED_ORIGINS` | Hosting |
| `DJANGO_SECURE_COOKIES`, `DJANGO_SECURE_SSL_REDIRECT`, `DJANGO_SECURE_HSTS_SECONDS` | Turn on when served over HTTPS |
| `THREATDASH_ORG_DOMAINS` | Domains watched for typosquats and leaked credentials |
| `THREATDASH_RESPONSE_CONNECTOR` / `_WEBHOOK_URL` / `_WEBHOOK_SECRET` | Response automation |
| `ANTHROPIC_API_KEY`, `THREATDASH_NLQ_MODEL` | Optional Claude translation for natural-language queries (default model `claude-opus-5-5`) |

## Security notes

- Token and session authentication. API tokens expire after `THREATDASH_TOKEN_TTL_HOURS` (default 12). Login is throttled (10/min), failed logins are audited, and log ingestion is rate-limited per connector. Deletes, connectors, feeds and playbook edits require staff.
- SSRF protection for outbound requests: feeds may only use http(s), every redirect hop is re-checked, and private, loopback and cloud-metadata addresses are refused unless `THREATDASH_FEED_ALLOW_PRIVATE_NETWORKS=1`. The response webhook refuses redirects.
- URLs and ATT&CK IDs that get rendered as links are validated, so stored `javascript:` links are rejected.
- Hardened XML parsing (`defusedxml`), upload size and row limits, rejection of nested-quantifier regexes in rules, and spreadsheet formula-injection escaping in CSV/XLSX exports.
- Reports and the raw media directory are never served publicly. nginx sends CSP, `X-Frame-Options`, `nosniff` and a referrer policy.
- Webhook calls are signed with HMAC-SHA256 (`X-ThreatDash-Signature`). A failed connector never marks a host as isolated.

## Project layout

```
backend/
  config/                 Django settings, URLs, WSGI
  threats/
    models/               intel, telemetry & assets, incidents/actors/exposure/feeds, response & compliance
    services/             ioc, enrichment, scoring, importers, telemetry, incidents, attribution,
                          exposure, feeds, response, compliance, executive, analytics, nlq, reports, exports
    management/commands/  seed_demo, run_scheduler, pull_feeds, threat_maintenance
    tests/                105 tests (services, API, security)
frontend/
  src/pages/              17 screens (overview, executive, incidents, telemetry, assets, response, …)
  src/components/         attack-path graph, charts, tables, overlays
  src/__tests__/          Vitest + Testing Library
```

## Testing

```bash
cd backend && python manage.py test threats        # SQLite, or set DATABASE_URL for PostgreSQL
cd frontend && npm run lint && npm test && npm run build
```

GitHub Actions runs on every push and pull request: the backend suite against PostgreSQL 16, `pip-audit`, `bandit`, `npm audit`, and the frontend lint, tests and build.

## License

MIT; see [LICENSE](LICENSE).

## Contact

Questions: hello@pakistanredteam.com
