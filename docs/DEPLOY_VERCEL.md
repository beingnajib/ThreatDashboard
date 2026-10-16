# Deploying ThreatDashboard on Vercel (step by step)

This guide puts ThreatDashboard online on [Vercel](https://vercel.com) with a free hosted PostgreSQL database from **Neon**, your own domain and automatic HTTPS. It is the quickest way to get a **test** instance running: no server to manage, and it takes about 15 minutes.

> **Good for testing and demos.** For production, prefer the Docker setup ([User Guide §7.2](USER_GUIDE.md#72-option-b--install-on-a-server-docker)) or a paid Vercel plan. See [Limits on Vercel](#limits-on-vercel) before relying on it.

## What runs where

| Part | Where it runs on Vercel |
| --- | --- |
| Web pages (the dashboard) | Vercel's global CDN |
| Backend / API | A Vercel **Python serverless function** (`api/index.py`) |
| Database | **Neon Postgres**, added from Vercel's Storage tab (free tier) |
| Background jobs | A **Vercel Cron** job, once a day |
| Generated reports | Stored in the database (Vercel has no permanent disk) |
| HTTPS certificate | Automatic, including for your own domain |

Everything is already configured in the repository (`vercel.json`, `api/index.py`, `requirements.txt`). You only click through Vercel's screens and paste a few settings.

---

## Step 1 — Create the project
1. Go to [vercel.com](https://vercel.com) and **sign up / log in with GitHub**.
2. Click **Add New… → Project**.
3. Find **ThreatDashboard** in the list and click **Import**. If you don't see it, click *Adjust GitHub App Permissions* and give Vercel access to the repository.
4. On the configuration screen:
   - **Framework Preset:** leave as **Other**. The repository's `vercel.json` sets the build commands.
   - **Root Directory:** leave as `./`.
   - Open **Environment Variables** and add the variables from Step 2 now. You can also add them later.
5. Click **Deploy**. The build takes 2–4 minutes.

> The first deployment will show errors when you open it. That's expected: there is no database yet. Step 3 fixes it.

## Step 2 — Settings (environment variables)
In your project: **Settings → Environment Variables**. Add each of these for **Production** (and Preview if you want preview links to work):

| Name | Value | Notes |
| --- | --- | --- |
| `DJANGO_SECRET_KEY` | a long random string | Generate one with `python3 -c "import secrets; print(secrets.token_urlsafe(50))"`, or use any password generator (50+ characters). Keep it secret. |
| `DJANGO_SUPERUSER_USERNAME` | e.g. `admin` | Your first administrator account, created automatically. |
| `DJANGO_SUPERUSER_PASSWORD` | a strong password | At least 10 characters. Only used to *create* the account. Changing it later does **not** change the password (use the admin site for that). |
| `DJANGO_SUPERUSER_EMAIL` | your email | Optional. |
| `CRON_SECRET` | another long random string | Protects the daily background-job endpoint. Vercel sends it automatically. |
| `THREATDASH_ORG_NAME` | your company name | Optional. |
| `THREATDASH_ORG_DOMAINS` | e.g. `yourcompany.com` | Your domains, used for look-alike-domain and leaked-credential checks. |

You don't need to set the database URL, allowed hosts or HTTPS settings. They are filled in automatically on Vercel.

## Step 3 — Add the database (Neon)
1. In your project, open the **Storage** tab → **Create Database** (or *Connect Store*) → choose **Neon** (Serverless Postgres) → accept the free plan.
2. Pick a **region close to your Vercel functions**. Vercel's default is Washington, D.C. (`iad1`), so choose **US East (N. Virginia)**. Keeping them together makes the app noticeably faster.
3. Connect it to your project, ticking all environments. This adds `DATABASE_URL` / `POSTGRES_URL` automatically.
4. Go to **Deployments**, open the latest deployment's **⋯** menu → **Redeploy**.

On the first request after a deploy, the app sets up its database tables and creates your administrator. That first page load can take 10–20 seconds; after that it's quick.

## Step 4 — Sign in
Open the address Vercel shows (like `https://threatdashboard-yourname.vercel.app`), then sign in with the username and password from Step 2.

- The Django **admin site** for managing users is at `/admin/` on the same address.
- Check health at `/api/health/`. It should say `"status": "ok"`.

## Step 5 (optional) — Load the demo data
To explore with a realistic sample attack, load the demo data. This runs on GitHub's servers, so you don't need anything installed:

1. Copy your database connection string. In Vercel: **Storage → your Neon database → .env.local / Quickstart**, copy the value of `DATABASE_URL` (it starts with `postgresql://`).
2. On GitHub, open the repository → **Settings → Secrets and variables → Actions → New repository secret**. Set the name to `DATABASE_URL`, paste the value, and click **Add secret**.
3. Go to the **Actions** tab → **Hosted database tasks** → **Run workflow** → choose **seed-demo-data** → **Run workflow**.
4. Wait for the green tick (1–2 minutes), then refresh the dashboard.

The same workflow can also run **migrate** (set up or upgrade database tables) or **run-maintenance** (the background jobs) on demand.

> Demo data uses reserved example addresses. To start clean later, delete the Neon database and create a new one; you'll get a fresh empty install with only your admin account.

## Step 6 — Use your own domain (automatic HTTPS)
1. In your project: **Settings → Domains → Add**, then type your domain, e.g. `threatdash.yourcompany.com`.
2. Vercel shows a DNS record to create. It is usually a **CNAME** for a subdomain (pointing at a Vercel target such as `cname.vercel-dns.com`), or an **A** record for a root domain. Add it at your domain registrar or DNS provider (GoDaddy, Namecheap, Cloudflare…).
3. Wait until Vercel shows **Valid Configuration**. This is usually minutes, but DNS can take up to a few hours. Vercel issues the HTTPS certificate automatically.
4. Add two environment variables and redeploy:

   | Name | Value |
   | --- | --- |
   | `DJANGO_ALLOWED_HOSTS` | `threatdash.yourcompany.com` |
   | `DJANGO_CSRF_TRUSTED_ORIGINS` | `https://threatdash.yourcompany.com` |

   Vercel's own `*.vercel.app` addresses keep working automatically.

> If you use Cloudflare for DNS, set the record to **DNS only** (grey cloud) while Vercel verifies the domain.

## Step 7 — Background jobs
`vercel.json` schedules `/api/cron/run/` **once a day at 05:00 UTC**. It pulls due threat feeds, expires old indicators, refreshes risk scores and re-checks compliance. You can see runs under **Settings → Cron Jobs** (or the project's *Logs*), and trigger one manually with the **Run** button there.

The free Hobby plan allows daily cron jobs. To run more often, upgrade to Pro and change the `schedule` in `vercel.json`, for example `"0 * * * *"` for hourly.

## Updating
Every push to the `main` branch on GitHub deploys automatically. Database changes are applied on the first request after the deploy. To apply them right away, run the **migrate** task in GitHub Actions.

## Limits on Vercel

| Limit | Effect | Workaround |
| --- | --- | --- |
| Requests are capped at 4.5 MB | Import files are limited to **4 MB** | Split big files, or use the Docker install for large imports. |
| Functions run at most 60 seconds | Very large imports or reports may time out | Keep imports modest; use the GitHub Actions tasks for heavy jobs. |
| Cron runs once a day on Hobby | Feeds refresh daily, not hourly | Upgrade to Pro, or press **Pull now** on *Feeds & connectors*. |
| No permanent disk | Reports are stored in the database instead | Nothing to do; this is automatic. |
| Cold starts | The first request after a quiet period takes a few seconds | Normal for serverless. Neon's free tier also pauses when idle. |
| Hobby plan terms | Vercel's free plan is for personal, non-commercial use | Use Vercel Pro or the Docker install for company production use. |

These work exactly as on a server:
- Logins, roles and audit log
- Alerts, incidents and attack paths
- Log ingestion through connectors (`https://<your-address>/api/events/ingest/`)
- Firewall block lists
- Reports and compliance

**Response actions** still run in simulated mode until you set `THREATDASH_RESPONSE_CONNECTOR=webhook` and the webhook variables, the same as any install ([User Guide §9.4](USER_GUIDE.md#94-making-response-buttons-act-on-real-devices)).

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Every page shows an error right after the first deploy | No database yet: do Step 3, then **Redeploy**. |
| Function logs say *"Serverless deployments need a hosted database"* | The Neon store isn't connected to this environment (Production / Preview). Connect it and redeploy. |
| Function logs say *"DJANGO_SECRET_KEY must be set"* | Add `DJANGO_SECRET_KEY` (Step 2) and redeploy. |
| **Bad Request (400)** on your own domain | Add the domain to `DJANGO_ALLOWED_HOSTS` and redeploy (Step 6). |
| **CSRF verification failed** when using `/admin/` on your domain | Add `https://your-domain` to `DJANGO_CSRF_TRUSTED_ORIGINS`. |
| Can't sign in as admin | Check `DJANGO_SUPERUSER_USERNAME` / `PASSWORD` were set *before* the first successful request. If the account already exists with another password, reset it through the admin site, or run the GitHub workflow on a fresh database. |
| Pages are slow | Put the function region (**Settings → Functions → Function Region**) in the same region as the Neon database. |
| "Hosted database tasks" fails with *Add a repository secret named DATABASE_URL* | Do Step 5.2. |

Where to look: **Vercel project → Logs** shows the backend's messages and errors in real time.
