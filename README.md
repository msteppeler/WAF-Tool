# General Information

This tool is AI generated, but human verified. If you are unsure, please review the code.

# WAF Monitor

A web tool for operating the NetScaler Web App Firewall (WAF/AppFW) via the NITRO API:
view policies and profiles, follow the WAF log live, create exception rules directly from
a logged hit, and link new objects (policies, profiles, signatures) via drag and drop.

For what each individual file does, see [`readme_components.md`](readme_components.md).

## Setup

### Requirements

- Python 3.10 or newer (or Docker/Docker Compose, if that's how you run the tool)
- Network access from the tool to the NetScaler's NITRO API (port 443/HTTPS)
- A NetScaler user with sufficient rights for the AppFW/vServer/signature objects

### The `.env` file

The tool reads exactly three environment variables, all optional (each has a sensible
default). **NetScaler credentials do NOT belong in `.env`** - IP, username and password
are entered at every login via the sign-in form and are kept only for the duration of the
session.

```bash
# .env
SECRET_KEY=<see below>
WAF_MONITOR_DB_PATH=/app/data/waf_monitor.db
NVD_API_KEY=<see below>
```

| Variable | Required? | What it's for |
|---|---|---|
| `SECRET_KEY` | Recommended | Signs the session cookies (login state). Without your own value, a hard-coded placeholder is used - not suitable for more than a quick, private test session, since anyone who knows this placeholder (it's right there in the source code) could forge valid session cookies. |
| `WAF_MONITOR_DB_PATH` | No | Path to the local SQLite database (signature categories, rule database). Without this, the file sits right next to `app.py`. Important for Docker: the directory holding this file must be mounted as a volume, otherwise the categories are gone after a container restart. |
| `NVD_API_KEY` | No | Raises the request limit against the NVD (CVE search for signature categories) from 5 to 50 requests per 30 seconds. The search still works without a key, just more slowly when running many search terms back to back. |

**How to generate the `SECRET_KEY` value:** it needs to be a long, random string that no
one else knows - not a password you need to remember, generate it once and put it in
`.env`. Easiest directly via Python:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

This prints a 64-character string; enter it unchanged after `SECRET_KEY=`. Changing the
value later invalidates all existing sessions (everyone would need to log in again) - this
is harmless, no data is lost.

**How to get an `NVD_API_KEY`:** register for free at
<https://nvd.nist.gov/developers/request-an-api-key>. The key arrives by email; just enter
it after `NVD_API_KEY=`. The signature-category search works fine without this step too,
just with the lower request limit.

### With Docker Compose

If your entire project directory is already bind-mounted into the container (as is usual
in this project, `volumes: [".:/app"]`), `waf_monitor.db` automatically ends up directly in
your project folder and survives every restart without needing any change to
`docker-compose.yaml`. Bring in the `.env` file as usual via `env_file: [.env]`.

Use `docker-compose build` to create the images. Afterwards use `docker-compose up -d` to start the containers.
As soon as the containers are up, you can use your Browser on port 8080 to access the login page.

## Logging in

On first visit, the tool asks for the NetScaler IP, username and password. These are
checked directly against the NITRO API and kept only for the current session (a server
restart or "Log out" requires logging in again).

The interface automatically appears in your browser's language (German, Italian, French,
English) - if none of those is set, it appears in English. Fully translated at the moment
are the login page, the navigation, and the Dashboard page; some labels on the Logging and
Configuration pages are still in German.

## What you can do on the three pages

### Dashboard

Overview of WAF policies as well as default and custom profiles.

- Clicking a policy shows details (bound vServers, rule expression, comment).
- Clicking a profile shows its security checks. For each check, Learning, Block, Stat and
  Log can be toggled directly - "Save" writes the change to the NetScaler immediately,
  "Discard" reverts the change without sending anything. Some checks don't support
  Learning according to NetScaler, so that checkbox is missing for them accordingly.

### Logging

The continuously updated view of `ns.log`.

- At the top you can search by keyword or transaction ID, filter by "Blocked"/"Not
  Blocked", and set the refresh interval.
- "Fetch now" retrieves new entries immediately; "Clear list" only hides the current
  display (without touching the actual `ns.log`).
- Clicking an entry shows details. For many hit types (SQL/command injection, XSS, cookie
  consistency, CSRF, buffer overflow, start URL, deny URL) a button also appears that
  suggests, and on request creates, a matching exception rule (relaxation rule) directly
  from that one hit.

### Configuration

Object-oriented management, all via drag and drop:

- **Signature categories**: use "+ Add" to create a category (e.g. IIS, Apache, OWA,
  SharePoint, WordPress, or a custom one) - this searches the NVD for matching CVEs.
  "Update rule database" downloads the public Citrix signature file once, so the tool
  knows which CVE maps to which NetScaler-internal rule ID. "Create in NetScaler" builds a
  real signature object from it on your appliance.
- **Signatures**: the (custom) signature objects that actually exist on the NetScaler.
  Dragging one onto a profile assigns that signature to the profile.
- **WAF profiles**: your own profiles. "+ Add" creates a new one. Dragging one onto a
  vServer creates a new policy for it and binds it directly.
- **vServers**: LB and CS vServers with their backends and bound policies, currently
  view-only.

Every delete or create action asks for confirmation first and shows a clear success or
error message afterward - if NetScaler itself reports an error, its exact text is shown
unchanged so you can see directly what's wrong.
