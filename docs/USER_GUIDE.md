# ThreatDashboard — The Plain-English Guide

This guide explains what ThreatDashboard does, how to use every screen, and how to install and configure it. It assumes **no security or programming background**. Where a technical word is unavoidable, it is explained the first time it appears, and there is a [glossary](#12-glossary) at the end.

**Contents**

1. [What is ThreatDashboard?](#1-what-is-threatdashboard)
2. [How it works, in one picture](#2-how-it-works-in-one-picture)
3. [Signing in and finding your way around](#3-signing-in-and-finding-your-way-around)
4. [A tour of every screen](#4-a-tour-of-every-screen)
5. [Step-by-step: common tasks](#5-step-by-step-common-tasks)
6. [People, roles and permissions](#6-people-roles-and-permissions)
7. [Installing ThreatDashboard](#7-installing-threatdashboard)
8. [Configuration settings explained](#8-configuration-settings-explained)
9. [Connecting your systems](#9-connecting-your-systems)
10. [Looking after it: backups, updates and background jobs](#10-looking-after-it)
11. [Troubleshooting and FAQ](#11-troubleshooting-and-faq)
12. [Glossary](#12-glossary)

---

## 1. What is ThreatDashboard?

Think of ThreatDashboard as a **security control room** for your organisation.

Every computer, cloud account, login system, firewall and email server you own produces a constant stream of records ("logs") about what is happening: who logged in, which programs ran, which websites were visited, which files were sent out. Separately, security researchers around the world publish lists of things known to be dangerous: bad websites, hacker-controlled computers, fingerprints of malicious files.

ThreatDashboard brings those two things together in one place and keeps watch for you. It:

- **Collects** activity records from all your systems into one view.
- **Compares** that activity against known threats, and against what "normal" looks like.
- **Raises alerts** when something looks wrong, and **groups related alerts into one case** so you are not buried in noise.
- **Shows the story** of an attack as a picture: where the attacker got in, where they moved, and what they took.
- **Lets you act**: cut a compromised computer off the network, force password resets, block a dangerous website.
- **Reports** the overall security picture in simple terms for management, and tracks how ready you are for audits such as ISO 27001 or SOC 2.

Who uses it:

| Person | What they use it for |
| --- | --- |
| **Security analyst** | Watching alerts, investigating cases, closing them. |
| **Incident responder** | Containing attacks: isolating computers, resetting accounts. |
| **IT administrator** | Installing it, connecting data sources, managing users. |
| **Manager / executive** | The Executive view: one score, a heatmap, plain-language findings. |
| **Auditor / compliance officer** | The Compliance screen and reports. |

---

## 2. How it works, in one picture

```
  YOUR SYSTEMS                       THREATDASHBOARD                              YOU
 ───────────────               ─────────────────────────────               ─────────────────
  Laptops & servers ─┐
  AWS / Azure cloud ─┤   logs     1. Collect & tidy the records
  Microsoft sign-ins ┼──────────► 2. Discover devices (incl. unknown ones)
  Firewall           ┤           3. Compare with known threats ◄─── global threat feeds
  Email gateway     ─┘           4. Spot unusual behaviour
                                  5. Raise alerts → group them into cases ─────► Dashboard,
                                  6. Score how dangerous each one is              alerts, cases,
                                                                                  reports
  Your EDR / SOAR tool ◄───────── 7. Response actions (isolate, reset…) ◄──────── One-click buttons
```

**Two important honesty notes**

1. ThreatDashboard only sees what you connect to it. On a fresh install it knows nothing about your network until you connect log sources (see [section 9](#9-connecting-your-systems)), or load the demo data to explore.
2. Out of the box, response buttons (isolate a computer, reset passwords, the live terminal) run in **simulated mode**: they are recorded and shown in the dashboard, but **nothing happens to a real device**. To make them real, connect your endpoint-security or automation tool ([section 9.4](#94-making-response-buttons-act-on-real-devices)).

---

## 3. Signing in and finding your way around

1. Open the address your administrator gave you, for example `https://threatdash.yourcompany.com`, or `http://localhost:8080` on a test install.
2. Enter your username and password and click **Sign in**.
3. For your protection you are signed out automatically after **12 hours** (configurable). After 10 wrong passwords in a minute, sign-in is paused briefly.

**The layout**

- **Left menu**, grouped into *Monitor*, *Visibility*, *Intelligence*, *Respond* and *Govern*. Red numbers next to **Incidents** and **Alerts** show how many serious items are waiting.
- **Top bar**: a green dot labelled **Live monitoring**, a sun/moon button to switch between dark and light themes, and **Sign out**.
- On a phone, the menu is hidden behind the ☰ button at the top left.

**Colours mean the same thing everywhere**

| Colour | Meaning |
| --- | --- |
| 🟢 Green | Low / OK / resolved |
| 🟡 Yellow | Medium / needs attention soon |
| 🟠 Orange | High / act today |
| 🔴 Red | Critical / act now |

**Risk scores** run from 0 (harmless) to 100 (extremely dangerous) and appear as a small bar next to a number.

---

## 4. A tour of every screen

### Monitor

#### SOC overview (home page)
*"SOC" means Security Operations Centre, the team that watches for attacks.* This is your morning check.

- **Top tiles**:
  - **Threat posture**: one score for how "under attack" you are right now.
  - **Open incidents** and **Open alerts**.
  - **Critical active IoCs**: dangerous items currently relevant to you.
  - **Events (24h)**: how much activity was collected in the last day.
  - **MTTR**: "mean time to resolve", how fast your team closes alerts on average.
- **Yellow "Volume anomaly" banner**: appears when far more new threats appeared on one day than usual. It is worth a look.
- **Blue "Trending" banner**: a type of threat (for example phishing) is suddenly much more common than normal.
- **Charts**:
  - **Detection timeline**: new threats and alerts per day.
  - **Active by severity**: the split between low, medium, high and critical.
  - **Threat categories**: which kinds of threat you are seeing.
  - **Telemetry by domain**: which kinds of system are sending activity.
  - **Top MITRE ATT&CK techniques**: the hacker techniques seen most. Each one links to an official explanation.
- **Priority incidents** and **Highest-risk indicators**: shortcuts into the most urgent work.
- Use the **Last 30 days** menu to change the time window. **Auto-refresh** updates the page every 30 seconds.

#### Executive view
Built for managers. No technical knowledge needed.

- **Corporate security posture**: a single 0–100 score with a label (Low, Guarded, Elevated, High, Severe) and a 30-day trend line. Lower is better.
- **What leadership needs to know**: a short list of findings in plain sentences, for example *"8% of devices are unmanaged shadow IT"*.
- **Risk heatmap**: rows are your departments (Finance, HR…), columns are kinds of system (Endpoint, Cloud, Identity, Network, Email). Darker red squares are where the risk is concentrated. Hover over a square for details.
- **Audit readiness**: a progress bar per compliance framework.
- **Print / save PDF** produces a copy for a board pack.

#### Incidents
An **incident** (or "case") is a bundle of related alerts that together tell one story. For example, a phishing click, a suspicious login and a large upload from the same laptop become one incident instead of three separate alarms.

- The list is sorted by **Priority** (0–100). Priority considers severity, how many attack stages are involved, how important the affected computers are, and whether a known hacker group is suspected.
- Filter by open or closed, status, or severity. Click any row to open it.

#### Incident detail
Everything you need to handle one case:

- **Case management**: change the status (New → Triage → Contained → Eradicated → Closed) and click **Assign to me**. Closing an incident automatically resolves its alerts.
- **Attack path**: a diagram read left to right, one column per attack stage (getting in, running code, stealing passwords, moving to other computers, communicating with the attacker, stealing data). The node types are:
  - **U**: a user account
  - **H**: one of your computers
  - **IP** or **DNS**: an outside address
  - **ENTRY**: where the attacker got in

  A red ring marks something known to be malicious, or the place data was sent. Solid arrows come from alerts; dashed arrows are related activity. Tick **Alerted paths only** to simplify the picture, and hover over anything for details.
- **Alert timeline**: each alert in the case, in time order.
- **Actor attribution**: which known hacker group the evidence most resembles, with a confidence percentage and the reasons. **Apply ≥50%** records the likely groups on the case. Treat this as a strong hint, not proof.
- **Respond**: buttons per affected computer and user, for example **Isolate**, **Contain compromised host** and **Compromised account response**, plus **Force global password reset**. Every action asks you to confirm first. See [section 5.3](#53-contain-a-compromised-computer).
- **Response history**: everything that has been done on this case, by whom, and the result.

#### Alerts
Individual detections, newest first. Each alert shows where it came from:

| Source | Meaning |
| --- | --- |
| Detection rule | Matched one of your watch-list rules. |
| IoC match | A known-bad address or file was seen in your own activity. |
| Behavioural | Unusual behaviour: many failed logins, logins from two countries too quickly, a very large upload. |
| Source detection | Your security product itself reported something serious. |

Buttons: **Ack** ("I'm looking at it"), **Resolve** (dealt with), **Dismiss** (not a real problem) and **Reopen**.

#### Ask the data
Type a question in normal English and get a chart or table. For example:

- *Failed sign-ins by country in the last 24 hours*
- *Top 5 countries with critical indicators*
- *Open alerts by severity*
- *List shadow IT devices*
- *Leaked credentials*

Click any example button to try it. Under the result, **Query spec** shows exactly how your question was understood. The system can only *read* data this way; it can never change or delete anything. If your administrator has added an Anthropic API key, Claude understands more complex questions; otherwise a built-in keyword matcher is used.

### Visibility

#### Telemetry
*Telemetry* means the raw activity records arriving from your systems.

- Tiles show how many events arrived in the last 24 hours from each kind of system. A tile reading **"no data in 24h"** means that source has gone quiet, which may be a broken connection.
- The **Event stream** can be searched and filtered. Tick **IoC matches only** to see just the activity that matched a known threat.
- Click any event to see every detail, including the original raw record.

#### Assets & shadow IT
An **asset** is any device or system: laptops, servers, cloud machines. **Shadow IT** means devices nobody registered or protected; ThreatDashboard noticed them on the network but they have no security agent.

- Assets are discovered **automatically** from the activity coming in. You don't need to type them in.
- Each asset has a **risk score** based on how important it is, its open alerts, its known software weaknesses (CVSS), whether it is shadow IT, and whether its activity suddenly changed from its normal pattern.
- Click an asset to see details, its risk breakdown and its recent activity. Buttons:
  - **Isolate host**: cut it off the network.
  - **Release**: reconnect it.
  - **Mark as managed**: once it has been registered and protected.
  - **Live response**: open a remote command console.

### Intelligence

#### Indicators
An **indicator of compromise (IoC)** is a clue that something bad is involved: a malicious web address, the IP address of a hacker's server, the fingerprint (hash) of a virus file, a phishing email address, or a known software weakness (CVE).

- **Add**: type or paste one, including "defanged" forms such as `hxxp://evil[.]example`. Defanging is how security people write dangerous links so nobody clicks them by accident; ThreatDashboard understands it.
- **Lookup**: paste a list (for example from an email you were sent) and instantly see which items are already known to be bad.
- **CSV / JSON / STIX 2.1**: export the list. STIX is the standard format for sharing threat information with other organisations.
- Click an indicator to see:
  - why it has its risk score
  - automatic background information (for example whether a domain name looks machine-generated, as malware often uses)
  - which hacker group it is linked to
  - where it was seen in your own activity
  - related indicators

  You can also change its status, or **Block** it.

#### Threat actors
Profiles of known hacking groups (for example APT29 and LockBit): who they are, what they want, the techniques they use and the infrastructure linked to them. Incidents are compared against these profiles automatically.

#### External risk
Dangers *outside* your network that target you:

- **Leaked credentials**: your staff's email addresses (and sometimes passwords) found in data stolen from other websites. ThreatDashboard **never stores the actual password**. It keeps only a short code that lets you tell whether two leaks share the same password.
- **Dark-web mentions**: your company named on criminal forums or ransomware "leak sites".
- **Look-alike domains** (typosquatting): web addresses made to look like yours, such as `examp1e.com` for `example.com`, often used to trick staff or customers.

Buttons:
- **Typosquat scan**: generates hundreds of possible look-alikes of your domain. It reports the ones already seen in your network traffic or threat data, and, if you tick **Resolve candidates in DNS**, the ones that are actually registered on the internet. The scheduler runs this check daily as well.
- **Ingest credential dump**: paste breach data.

Change each finding's status as you deal with it.

#### Feeds & connectors
- **Threat feeds**: free public lists of known threats, updated automatically. They are **off until you switch them on**. Tick **Enabled**, and **Pull now** fetches one immediately.
- **Log connectors**: how your systems send their activity to ThreatDashboard. Staff only. See [section 9](#9-connecting-your-systems).

#### Import
Upload a file of threats: CSV (spreadsheet), JSON, XML, STIX, or a plain text list with one item per line. The importer recognises most common column names. Items already known are merged (seen again, worst severity kept) rather than duplicated. Bad rows are listed with the reason, and the rest are still imported.

### Respond

#### Response center
- **Playbooks**: ready-made multi-step responses. Each card lists its steps; click **Run playbook**, choose the target and confirm.
  - *Contain compromised host*: collect evidence, isolate, notify.
  - *Compromised account response*: sign the user out everywhere, reset their password, disable the account.
  - *Force global password reset*: everyone must change their password. This affects the whole organisation and needs an extra confirmation.
  - *Block indicator at perimeter*: add a bad address to your firewall's block list.
- **Live response console**: a remote command window on a protected computer, used by forensic investigators to collect evidence. Only safe, pre-approved commands are accepted (type `help` to list them). Anything else is refused, and every command is recorded.
- **Action history**: every action taken, by whom, and the outcome.

If you see a blue banner saying **simulated mode**, actions are recorded but do not reach real devices; see [section 9.4](#94-making-response-buttons-act-on-real-devices).

#### Detection rules
Your own watch-lists. A rule says, for example: *"alert me about any ransomware indicator of medium severity or above"*. All the conditions you fill in must match.

- **Dry run** shows how many current items the rule would match before you save it.
- **Run** checks every existing item against the rule ("retro-hunt").
- New and updated threats are checked against all enabled rules automatically.

### Govern

#### Compliance
Shows how ready you are for audits against four frameworks:

| Framework | What it is |
| --- | --- |
| **NIST CSF 2.0** | US government cybersecurity framework, widely used everywhere. |
| **ISO/IEC 27001:2022** | International information-security standard. |
| **SOC 2** | Common requirement for service providers. |
| **GDPR** | EU data-protection law. |

Most controls are **checked automatically** from live data. For example, *"Are all devices inventoried?"* is checked against the asset list, and *"Is there a critical incident open beyond the 72-hour breach-notification window?"* is checked against the incident list. Each control shows Pass, Partial or Fail, a score and the evidence. Some controls cannot be checked by software; they show **Manual**, and you set their status yourself with **Override**.

Click **Re-evaluate now** to refresh. It also runs automatically every 15 minutes.

> This shows *readiness*. It helps you prepare for an audit; it is not a certificate.

#### Reports
Choose a title, format (**PDF**, **Word**, **Excel**, **CSV** or **JSON**), date range and minimum severity, then click **Generate & download**. Reports include an executive summary, compliance readiness, incidents, external exposure and the top threats. Earlier reports stay in the archive for re-download.

---

## 5. Step-by-step: common tasks

### 5.1 The 5-minute morning check
1. Open **SOC overview**. Note the **Threat posture** score and any yellow or blue banners.
2. Open **Incidents**. Work from the top (highest priority).
3. Glance at **Telemetry**. Any source showing "no data in 24h" may be disconnected; tell your administrator.
4. Check **External risk** for new leaked credentials.

### 5.2 Investigate an incident
1. **Incidents** → click the incident.
2. Click **Assign to me** and set the status to **Triage**.
3. Read the **Attack path** left to right: where did it start, and which computers and accounts are involved?
4. Read the **Alert timeline** and check **Actor attribution**.
5. Decide: real attack → contain it (5.3). False alarm → set the status to **Closed** (its alerts are resolved automatically).

### 5.3 Contain a compromised computer
1. In the incident (or on **Assets** → click the computer), click **Isolate** (or **Isolate host**).
2. Confirm. The computer is now cut off from everything except the security tooling. It shows a green dashed ring in the attack path and an **isolated** badge.
3. Prefer **Contain compromised host**: it also collects evidence first.
4. When the machine is cleaned, click **Release**.

> Devices marked **shadow IT / no agent** cannot run the evidence-collection or terminal steps (there is no agent on them), but they can still be isolated at network level.

### 5.4 Respond to a stolen account
1. In the incident, find the user under **Respond** → **Compromised account response**, and confirm.
2. The user is signed out everywhere, their password is reset, and the account is disabled until reviewed.

### 5.5 Check a suspicious email
1. **Indicators** → **Lookup**.
2. Paste the sender address, any links and any attachment fingerprints (one per line).
3. Anything shown with a severity badge is already known to be bad.

### 5.6 Import a threat list someone sent you
1. **Import** → drop the file in the box (or click to choose it).
2. Optionally name the source and pick how trustworthy it is (A = completely reliable … F = unknown).
3. Click **Import** and read the summary: new items, merged items, rows with errors and their reasons.

### 5.7 Create an alert rule
1. **Detection rules** → **New rule**.
2. Give it a name and fill in only the conditions you care about, for example *Threat types: Phishing*, *Min confidence: 60*.
3. Click **Dry run** to see how many items it would match, then **Save**. Click **Run** to check existing data now.

### 5.8 Send a report to management
1. **Reports** → set the title, choose **PDF**, set the dates → **Generate & download**.
2. Or open the **Executive view** and use **Print / save PDF**.

### 5.9 Prepare for an audit
1. **Compliance** → **Re-evaluate now**.
2. Pick a framework and work through the **Fail** and **Partial** rows. The *Evidence* column says what to fix.
3. For manual controls, set **Override** once you have the evidence.
4. Generate an **Excel** report; its *Compliance* sheet lists every framework.

---

## 6. People, roles and permissions

| Role | Can do | How to give it |
| --- | --- | --- |
| **Analyst** (any signed-in user) | View everything; add and import threats; manage alerts, incidents, rules, reports and exposures. | Create the user (below). |
| **Responder** | Everything an analyst can, **plus** run response actions and playbooks. | Add the user to the group named exactly `responders`. |
| **Forensics** | Responder rights **plus** the Live response console. | Add the user to the group named exactly `forensics`. |
| **Staff / administrator** | Everything, plus deleting records, managing connectors and feeds, editing playbooks and viewing the audit log. | Tick **Staff status** on the user. |

**Managing users** happens in the built-in admin site at `/admin/` (for example `https://threatdash.yourcompany.com/admin/`). Sign in with an administrator account, then:

- **Add a user**: *Users* → **Add user** → set a username and a strong password (at least 10 characters).
- **Create the groups** (first time only): *Groups* → **Add group** → name it `responders` and save. Repeat for `forensics`.
- **Give someone a role**: open the user → under *Groups*, move `responders` and/or `forensics` across → **Save**.

Every sign-in, failed sign-in, response action, export and other sensitive operation is written to an **audit log** that cannot be edited.

---

## 7. Installing ThreatDashboard

Choose one:

- **Option A: Try it on your own computer** (10 minutes, includes demo data).
- **Option B: Install on a server for real use** (recommended, uses Docker).
- **Option C: Put a test instance online on Vercel** (no server needed, free tier, automatic HTTPS): see the separate [Vercel deployment guide](DEPLOY_VERCEL.md).

### 7.1 Option A — Try it on your own computer

You need **Python 3.11 or newer**, **Node.js 20.19 or newer** and **Git**.

```bash
git clone https://github.com/beingnajib/ThreatDashboard.git
cd ThreatDashboard
SEED_DEMO=1 ./run.sh
```

The first run takes a few minutes to download everything. Watch the output for lines like:

```
Created 'admin' with password: Xy7…
Created 'responder' with password: …
Created 'analyst' with password: …
```

**Copy those passwords.** Then open <http://localhost:5173> and sign in. The demo contains a realistic attack story (a phishing email leading to data theft from the Finance department) so every screen has something to show. Press **Ctrl + C** in the terminal to stop.

> Demo data uses reserved example addresses (such as `example.com` and `203.0.113.x`), so no real company or website is labelled malicious.

### 7.2 Option B — Install on a server (Docker)

**What you need**
- A Linux server (2 CPU cores, 4 GB RAM and 20 GB disk is a good start).
- **Docker** with the **Compose** plugin installed ([docs.docker.com/engine/install](https://docs.docker.com/engine/install/)).
- Optionally a domain name (for example `threatdash.yourcompany.com`) pointing at the server.

**Step 1: Download**
```bash
git clone https://github.com/beingnajib/ThreatDashboard.git
cd ThreatDashboard
```

**Step 2: Create your settings file**
```bash
cp .env.example .env
```
Open `.env` in a text editor and set **at least** these two lines:

```
DJANGO_SECRET_KEY=<paste a long random string here>
POSTGRES_PASSWORD=<choose a strong database password>
```

To generate a good secret key, run:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(50))"
```

If you will use a domain name, also set:
```
DJANGO_ALLOWED_HOSTS=threatdash.yourcompany.com
DJANGO_CSRF_TRUSTED_ORIGINS=https://threatdash.yourcompany.com
DJANGO_CORS_ALLOWED_ORIGINS=https://threatdash.yourcompany.com
THREATDASH_ORG_NAME=Your Company Ltd
THREATDASH_ORG_DOMAINS=yourcompany.com,yourcompany.co.uk
```

**Step 3: Start it**
```bash
docker compose up -d --build
```
This starts four parts:

| Part | Job |
| --- | --- |
| `db` | The database (PostgreSQL), where everything is stored. |
| `backend` | The engine that does the analysis and serves data. |
| `scheduler` | A worker that pulls threat feeds, refreshes scores and runs checks on a timer. |
| `frontend` | The web pages, served on port **8080**. |

Check they are healthy (all should say `running` or `healthy` after about a minute):
```bash
docker compose ps
```

**Step 4: Create your administrator account**
```bash
docker compose exec backend python manage.py createsuperuser
```
Then open `http://<your-server>:8080` and sign in.

**Step 5 (optional): Load the demo data**
```bash
docker compose exec backend python manage.py seed_demo
```
Skip this on a real production system, or remove the demo data later with `seed_demo --flush`. Note that `--flush` also clears real threat data.

### 7.3 Turn on HTTPS (strongly recommended)
HTTPS encrypts traffic so passwords and data can't be read in transit. The usual approach is to put a "reverse proxy" in front of ThreatDashboard that handles certificates for you: **Caddy**, **Nginx Proxy Manager**, **Traefik**, or a cloud load balancer. Point it at `http://<server>:8080`.

Once HTTPS works, add these to `.env` and run `docker compose up -d` again:
```
DJANGO_SECURE_COOKIES=1
DJANGO_SECURE_SSL_REDIRECT=1
DJANGO_SECURE_HSTS_SECONDS=31536000
```
> Only enable these **after** HTTPS works. `HSTS` tells browsers to refuse plain HTTP for a year, so turning it on too early can lock you out.

If your HTTPS proxy is in front of the built-in nginx, configure it to pass the header `X-Forwarded-Proto: https`.

To use a port other than 8080, set `HTTP_PORT=…` in `.env`.

---

## 8. Configuration settings explained

All settings live in the `.env` file. After changing it, run `docker compose up -d` to apply. Lines beginning with `#` are switched off; remove the `#` to use them.

### Must set
| Setting | What it does | Example |
| --- | --- | --- |
| `DJANGO_SECRET_KEY` | A private random key used to secure sessions. Keep it secret, never share it. The app refuses to start without it. | long random string |
| `POSTGRES_PASSWORD` | The database password. | strong password |

### Your website address
| Setting | What it does | Example |
| --- | --- | --- |
| `DJANGO_ALLOWED_HOSTS` | Which web addresses the app answers to. Requests for any other name are refused. | `threatdash.yourcompany.com` |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | The full address(es) people open in their browser, including `https://`. | `https://threatdash.yourcompany.com` |
| `DJANGO_CORS_ALLOWED_ORIGINS` | Same as above; only needed if the pages are served from a different address than the API. | `https://threatdash.yourcompany.com` |
| `HTTP_PORT` | Port the web interface listens on. | `8080` |
| `DJANGO_SECURE_COOKIES`, `DJANGO_SECURE_SSL_REDIRECT`, `DJANGO_SECURE_HSTS_SECONDS` | HTTPS-only protections. Set them after HTTPS works ([7.3](#73-turn-on-https-strongly-recommended)). | `1`, `1`, `31536000` |

### Your organisation
| Setting | What it does | Example |
| --- | --- | --- |
| `THREATDASH_ORG_NAME` | Your organisation's name. | `Your Company Ltd` |
| `THREATDASH_ORG_DOMAINS` | Your email and web domains, comma-separated. Used to find look-alike domains and to keep only *your* staff's leaked credentials. | `yourcompany.com,yourco.io` |

### Response actions
| Setting | What it does |
| --- | --- |
| `THREATDASH_RESPONSE_CONNECTOR` | `simulated` (default): buttons record actions but touch nothing real. `webhook`: actions are sent to your security tool, which carries them out. |
| `THREATDASH_RESPONSE_WEBHOOK_URL` | Where actions are sent (in `webhook` mode). |
| `THREATDASH_RESPONSE_WEBHOOK_SECRET` | A shared secret used to sign each action so your tool can verify it really came from ThreatDashboard. |
| `THREATDASH_RESPONSE_TIMEOUT_SECONDS` | How long to wait for your tool to answer (default 15). |

### Optional AI for "Ask the data"
| Setting | What it does |
| --- | --- |
| `ANTHROPIC_API_KEY` | If set, Claude interprets questions on the *Ask the data* screen. Without it, a built-in keyword matcher is used. Only the question text is sent to Anthropic, never your data. |
| `THREATDASH_NLQ_MODEL` | Which Claude model to use (default `claude-opus-5-5`). |

### Security
| Setting | Default | What it does |
| --- | --- | --- |
| `THREATDASH_TOKEN_TTL_HOURS` | `12` | Hours before users are signed out automatically (`0` = never, not recommended). |
| `THREATDASH_THROTTLE_LOGIN` | `10/min` | Maximum sign-in attempts per minute. |
| `THREATDASH_THROTTLE_INGEST` | `600/min` | Maximum log deliveries per minute, per connector. |
| `THREATDASH_THROTTLE_USER` | `600/min` | Maximum requests per minute per signed-in user. |
| `THREATDASH_FEED_ALLOW_PRIVATE_NETWORKS` | `0` | Feeds may not point at internal addresses (this protects your internal systems). Set `1` only if you host your own feed inside your network. |

### Fine-tuning
| Setting | Default | What it does |
| --- | --- | --- |
| `THREATDASH_MAX_IMPORT_BYTES` | 20 MB | Largest file accepted on the Import screen. |
| `THREATDASH_MAX_IMPORT_ROWS` | 100,000 | Most rows read from one import file. |
| `THREATDASH_RISK_HALF_LIFE_DAYS` | `30` | How fast old threats lose importance. After 30 days a threat counts about half as much, unless it is seen again. |
| `THREATDASH_DEFAULT_INDICATOR_TTL_DAYS` | `90` | Threats not seen again for this long are marked *expired* automatically. |
| `THREATDASH_EXFIL_BYTES` | 500 MB | How much data one computer can send to one outside address within an hour before a "possible data theft" alert is raised. |
| `THREATDASH_FEED_TIMEOUT_SECONDS` / `THREATDASH_FEED_MAX_BYTES` | 30 s / 50 MB | Limits when downloading threat feeds. |
| `DJANGO_TIME_ZONE` | `UTC` | Server time zone. Your browser still shows times in your local time. |
| `DJANGO_LOG_LEVEL` | `INFO` | How much detail goes into the logs (`DEBUG`, `INFO`, `WARNING`). |

---

## 9. Connecting your systems

### 9.1 Send activity logs (connectors)
A **connector** is a named entry point with its own secret key, one per source. For example: "Office 365 sign-ins", "AWS production", "Head-office firewall".

1. Sign in as staff → **Feeds & connectors** → **New connector**.
2. Give it a name and pick the **Format** that matches the source:

| Format | Use it for |
| --- | --- |
| EDR / endpoint agent | Laptop and server security agents (CrowdStrike, Defender, SentinelOne…) |
| AWS CloudTrail | Amazon Web Services account activity |
| Microsoft Entra ID sign-ins | Microsoft 365 / Azure AD login records |
| Azure activity log | Changes made in your Azure cloud |
| Firewall / NDR | Firewalls and network sensors |
| Email security gateway | Email filtering products |
| Generic JSON | Anything else, in ThreatDashboard's simple format |
| Dark-web / external risk | Dark-web monitoring services |

3. Click **Create**. A **key** starting with `tdk_` is shown **once**. Copy it somewhere safe immediately; only a scrambled copy is stored. If you lose it, click **Rotate key** to issue a new one (the old key stops working).
4. Configure the source, or the log-shipping tool you already use (Fluent Bit, Vector, Logstash, Cribl, a cloud function…), to send its records by HTTPS POST to:

```
https://<your-address>/api/events/ingest/
Header:  X-Ingest-Key: tdk_…
Body:    a JSON list of events
```

A test you can run from any computer:
```bash
curl -X POST https://threatdash.yourcompany.com/api/events/ingest/ \
  -H "X-Ingest-Key: tdk_your_key_here" \
  -H "Content-Type: application/json" \
  -d '[{"domain": "endpoint", "event_type": "process_start", "hostname": "laptop-01",
        "username": "alice@yourcompany.com", "process": "powershell.exe", "severity": "low"}]'
```
A reply containing `"ingested": 1` means it worked. The event appears on **Telemetry**, and `laptop-01` appears on **Assets**.

**Generic format fields** (all optional except `domain` and `event_type`):

| Field | Meaning |
| --- | --- |
| `domain` | `endpoint`, `cloud`, `identity`, `network` or `email` |
| `event_type` | What happened, for example `process_start`, `login`, `dns_query`, `upload` |
| `timestamp` | When it happened, for example `2026-10-16T09:30:00Z` (defaults to now) |
| `severity` | `low`, `medium`, `high` or `critical` |
| `outcome` | `success` or `failure` |
| `hostname`, `asset_ip`, `os`, `department`, `owner`, `managed` | Describe the device. `managed: true` means it has a security agent. |
| `username` | Which account |
| `src_ip`, `dst_ip`, `dst_port` | Network addresses involved |
| `domain_name`, `url`, `file_hash`, `process` | Website, link, file fingerprint, program |
| `bytes_out` | Data sent out (used for data-theft detection) |
| `country` | Two-letter country code, for example `US` |
| `mitre_technique` | Hacker-technique ID, for example `T1059` |
| `target_hostname` | For movement between computers: the destination machine |
| `message` | A short human description |

For **AWS CloudTrail**, **Entra ID** and **Azure activity** connectors, send those services' own export format unchanged; ThreatDashboard translates it. Up to 5,000 events can be sent per request.

### 9.2 Turn on threat feeds
1. **Feeds & connectors** → tick **Enabled** on the feeds you want:
   - **URLhaus**: malware download links
   - **Feodo Tracker** and **SSLBL**: botnet control servers
   - **OpenPhish**: phishing sites
   - **CISA KEV**: software weaknesses attackers actively use
2. Click **Pull now** to fetch immediately. After that the scheduler refreshes each feed at its interval (every 1–12 hours).

Staff can add other feeds (for example a paid feed or a sharing-group feed) through the admin site under *Threat feeds*. They can be CSV, JSON, STIX or plain text, with an optional login header.

### 9.3 Block threats on your firewall automatically
Many firewalls (Palo Alto, Fortinet, Check Point and others) can download a block list from a web address on a schedule (often called an "External Dynamic List"). Point them at:

| List | Address |
| --- | --- |
| Bad IP addresses | `https://<your-address>/api/indicators/blocklist/?type=ip` |
| Bad domains | `https://<your-address>/api/indicators/blocklist/?type=domain` |
| Bad URLs | `https://<your-address>/api/indicators/blocklist/?type=url` |
| Bad file hashes | `https://<your-address>/api/indicators/blocklist/?type=hash` |

Send the header `X-Ingest-Key: tdk_…` using a connector made for the firewall. Add `&min_risk=80` to include only the most dangerous items (the default is 60). Anything you click **Block** on is always included.

### 9.4 Making response buttons act on real devices
ThreatDashboard doesn't control laptops directly. It hands each action to your **EDR** (endpoint security) or **SOAR** (automation) tool, which carries it out. Examples: CrowdStrike, Microsoft Defender, SentinelOne, Tines, Cortex XSOAR, Splunk SOAR, or a small script of your own.

1. In your automation tool, create a webhook (a web address that receives requests).
2. In `.env`, set:
   ```
   THREATDASH_RESPONSE_CONNECTOR=webhook
   THREATDASH_RESPONSE_WEBHOOK_URL=https://your-soar.example.com/hooks/threatdash
   THREATDASH_RESPONSE_WEBHOOK_SECRET=<a long random string, also entered in your tool>
   ```
   Then run `docker compose up -d`.
3. Each time someone clicks a response button, your tool receives a request like this:
   ```json
   {
     "action_id": 42,
     "action_type": "isolate_host",
     "requested_by": "alice",
     "requested_at": "2026-10-16T09:30:00+00:00",
     "asset": {"hostname": "laptop-07", "ip_address": "10.10.7.20", "mac_address": "", "cloud_resource_id": ""},
     "indicator": null,
     "target_user": null,
     "parameters": {}
   }
   ```
   Possible `action_type` values:

   | `action_type` | Meaning |
   | --- | --- |
   | `isolate_host` / `release_host` | Cut a computer off the network / reconnect it |
   | `collect_forensics` | Collect an evidence package |
   | `kill_process` | Stop a running program |
   | `block_indicator` | Block a bad address or file |
   | `disable_user` | Disable an account |
   | `reset_password` | Force a password reset (`"*"` in `target_user` means everyone) |
   | `revoke_sessions` | Sign the user out everywhere |
   | `terminal_command` | Run a live-response command (in `parameters.command`) |
   | `notify` | Send a notification |
4. **Check the request is genuine.** The header `X-ThreatDash-Signature: sha256=<code>` is an HMAC-SHA256 of the raw request body using your shared secret. Your tool should compute the same code and reject the request if it doesn't match. In Python:
   ```python
   import hashlib, hmac
   expected = "sha256=" + hmac.new(SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
   if not hmac.compare_digest(expected, request.headers["X-ThreatDash-Signature"]):
       reject()
   ```
5. **Reply** with JSON. ThreatDashboard shows `output` in the history and treats `succeeded`, `success`, `ok` or `queued` as success:
   ```json
   {"status": "succeeded", "output": "laptop-07 network-contained via EDR"}
   ```
   Any other status, an error, or no reply within the timeout marks the action **failed**. The computer is **not** shown as isolated unless your tool confirmed it.

---

## 10. Looking after it

### Background jobs (automatic)
The `scheduler` part runs these by itself:

| How often | Job |
| --- | --- |
| Every minute | Pull any threat feeds that are due. |
| Every 15 minutes | Mark old threats as expired, refresh risk scores (they fade over time), recalculate device risk, re-check compliance. |
| Once a day | Scan for new look-alike domains of your organisation. |

To run them by hand:
```bash
docker compose exec backend python manage.py pull_feeds --all
docker compose exec backend python manage.py threat_maintenance
```

### Backups (do this!)
Everything important is in the database. Make a backup:
```bash
docker compose exec db pg_dump -U threatdashboard threatdashboard > backup-$(date +%F).sql
```
Restore a backup into a fresh install:
```bash
cat backup-2026-10-16.sql | docker compose exec -T db psql -U threatdashboard threatdashboard
```
Generated reports are stored in the `media` Docker volume. Back that up too if you need old report files. Keep a safe copy of your `.env` file as well.

Schedule the backup command daily (for example with `cron`) and store copies on a different machine.

### Updating to a new version
```bash
cd ThreatDashboard
git pull
docker compose up -d --build
```
Database changes are applied automatically when the backend starts. Make a backup first.

### Checking it is healthy
- `docker compose ps`: all parts should be `running` / `healthy`.
- Open `https://<your-address>/api/health/`. It should say `"status": "ok"`.
- `docker compose logs -f backend` (or `scheduler`) shows live logs. Press Ctrl + C to stop watching.

---

## 11. Troubleshooting and FAQ

**The app won't start and the logs say "DJANGO_SECRET_KEY must be set".**
Set `DJANGO_SECRET_KEY` in `.env` ([7.2 step 2](#72-option-b--install-on-a-server-docker)), then run `docker compose up -d`.

**The browser shows "Bad Request (400)".**
The address you typed isn't listed in `DJANGO_ALLOWED_HOSTS`. Add it (just the name, no `https://`), then run `docker compose up -d`.

**Sign-in fails with "CSRF verification failed", or works on one address but not another.**
Add the exact address you use, *with* `https://`, to `DJANGO_CSRF_TRUSTED_ORIGINS`.

**I'm signed out every day.**
That is the 12-hour safety timeout. Change `THREATDASH_TOKEN_TTL_HOURS` if your policy allows.

**"Too many requests" when signing in.**
More than 10 attempts in a minute. Wait one minute and try again.

**I forgot the administrator password.**
```bash
docker compose exec backend python manage.py changepassword <username>
```

**The dashboard is empty.**
Nothing is connected yet. Connect log sources ([9.1](#91-send-activity-logs-connectors)), enable threat feeds ([9.2](#92-turn-on-threat-feeds)), or load the demo data to explore.

**A Telemetry tile says "no data in 24h".**
That source has stopped sending. Check the log shipper is running, that its key is correct (a wrong key returns `401`), and on **Feeds & connectors** check the connector's *Last event* time.

**A feed shows "Failed: Blocked … non-public address".**
The feed points at an internal address, which is blocked for safety. If it really is your own internal feed, set `THREATDASH_FEED_ALLOW_PRIVATE_NETWORKS=1`.

**A feed shows "Failed: Download failed".**
The server can't reach the internet, or the feed site is down. Check outbound internet access and any proxy (standard `HTTPS_PROXY` settings are honoured).

**Response buttons say "succeeded" but nothing happened on the laptop.**
You are in **simulated mode** (the blue banner on Response center). See [9.4](#94-making-response-buttons-act-on-real-devices).

**"Response actions require membership of the 'responders' group".**
Ask an administrator to add you to the `responders` group ([section 6](#6-people-roles-and-permissions)).

**Live response says the device has no endpoint agent.**
The device is shadow IT, so there is no agent to run commands on. Isolate it at network level, then register it and click **Mark as managed**.

**The terminal refused my command.**
Only pre-approved forensic commands are allowed, and characters such as `;`, `|`, `&`, `$` and `>` are always refused for safety. Type `help` for the list.

**Import says "Invalid or unsafe XML".**
The file uses XML features that can be abused (entities or DTDs), so it is refused on purpose. Export it again as plain XML, CSV or JSON.

**Can Claude / the AI see my data?**
Only if you set `ANTHROPIC_API_KEY`, and even then only the *question you type* on *Ask the data* is sent. Your records stay on your server; the AI only translates the question into a safe, read-only query.

**Is a "Pass" on the Compliance screen a certification?**
No. It shows how ready you are, based on what ThreatDashboard can measure. A real audit is still done by an accredited auditor.

**How sure is "Actor attribution"?**
It is an informed hint based on overlapping evidence (shared infrastructure, matching techniques, malware names). Attackers sometimes copy each other, so treat it as a lead, not a verdict.

---

## 12. Glossary

| Term | Plain meaning |
| --- | --- |
| **Alert** | A single "something looks wrong" signal. |
| **Asset** | Any device or system you own: laptop, server, cloud machine. |
| **Attack path** | The route an attacker took through your systems, shown as a diagram. |
| **ATT&CK / MITRE ATT&CK** | A public catalogue of hacker techniques; each has an ID such as `T1566` (phishing). |
| **Audit log** | A permanent record of who did what in ThreatDashboard. |
| **CVE** | An ID for a publicly known software weakness, for example `CVE-2024-3400`. |
| **CVSS** | A 0–10 score for how serious a software weakness is. |
| **Connector** | An entry point, with its own key, through which one system sends its logs. |
| **Dark web** | Hidden parts of the internet where criminals trade stolen data and access. |
| **Defanged** | A dangerous link written so it can't be clicked, for example `hxxp://evil[.]com`. |
| **DGA** | Malware that generates random-looking website names, for example `xkqzjwvbtrpl.com`. |
| **EDR** | Endpoint Detection & Response: security software on laptops and servers that can also isolate them. |
| **Exfiltration** | Data being stolen and sent out of your network. |
| **Feed** | A regularly updated public or paid list of known threats. |
| **Hash** | A unique fingerprint of a file; identical files have identical hashes. |
| **Incident** | A case: a group of related alerts that tell one story. |
| **IoC (indicator of compromise)** | A clue that something bad is involved: a bad address, file fingerprint, phishing email address… |
| **Isolation** | Cutting a computer off the network so an attacker can't use it, while security tools can still reach it. |
| **Lateral movement** | An attacker hopping from one of your computers to another. |
| **Phishing** | Fake emails or websites that trick people into giving passwords or running malware. |
| **Playbook** | A saved set of response steps run with one click. |
| **Posture score** | A single 0–100 number for how much active risk you face right now (lower is better). |
| **Ransomware** | Malware that locks your files and demands payment. |
| **Risk score** | A 0–100 rating of how dangerous an item or device is. |
| **Shadow IT** | Devices or services in use that IT didn't register or protect. |
| **SOAR** | Security automation software that carries out response steps across your tools. |
| **SOC** | Security Operations Centre: the team (or person) that watches for and handles attacks. |
| **STIX** | The standard file format for sharing threat information. |
| **Telemetry** | The raw activity records your systems produce. |
| **TLP** | Traffic Light Protocol: labels saying who you may share information with (CLEAR, GREEN, AMBER, RED). |
| **Typosquatting** | Registering look-alike web addresses, for example `examp1e.com`, to trick people. |
| **Webhook** | A web address that receives automatic messages from another system. |

---

*Need help? Contact hello@pakistanredteam.com. Technical details for developers are in the [README](../README.md).*
