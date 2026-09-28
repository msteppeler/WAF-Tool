# WAF Monitor – Component Reference

This file describes what each individual file in the project is responsible for. For
usage instructions ("how do I..."), see `README.md`. For deeper technical background.

## Python – Backend

| File | Function |
|---|---|
| `app.py` | The Flask application itself: all routes (pages and the action endpoints called by JavaScript), login/logout, session handling, language selection per request. The central entry point. |
| `nitro.py` | The complete NetScaler API client (NITRO). Login against the NetScaler, all read and write calls (policies, profiles, vServers, services, signatures, files). No Flask or template logic. |
| `log_parser.py` | Reads and interprets `ns.log`: splits each line into its fields (CEF format), recognizes the respective security check type (SQL injection, XSS, cookie consistency, ...) and prepares the data the relaxation-rule buttons on the Logging page need. |
| `profile_parser.py` | Builds the structured view for the Dashboard page from the raw NITRO fields of an `appfwprofile` (which security checks are active, with which settings). |
| `objects_parser.py` | Assembles the object hierarchy for the Configuration page from vServers, services and policy bindings (who is connected to what). |
| `signature_db.py` | This tool's own local SQLite database (independent of the NetScaler): signature categories, their found CVEs, which profile a category is pending for, and the rule database built from the Citrix signature file (which NetScaler rule ID belongs to which CVE). |
| `signature_file_parser.py` | Downloads and parses the public Citrix signature file (XML). Can also build its own copy of this file with only certain rules enabled (the basis for "Create in NetScaler"). |
| `nvd_client.py` | Queries the NVD (National Vulnerability Database) for CVEs matching a keyword - the data source for the signature categories. |
| `translations.py` | The complete multi-language support (German/Italian/French/English): browser-language detection and all text strings translated so far. |

## Templates (pages)

| File | Function |
|---|---|
| `templates/base.html` | The shared HTML shell (head, `<html lang>`), extended by every other page. |
| `templates/login.html` | The sign-in page (NetScaler IP, username, password). |
| `templates/error.html` | A custom 404 error page matching the rest of the design. |
| `templates/dashboard.html` | The Dashboard page: policies, default and custom profiles with their security checks. |
| `templates/analysis.html` | The Logging page: the continuously refreshed list of `ns.log` entries with filter and search tools. |
| `templates/objects.html` | The Configuration page: signature categories, signatures, WAF profiles, vServers - all linkable via drag and drop. |

## Templates (reusable building blocks)

| File | Function |
|---|---|
| `partials/_sidebar.html` | The left-hand navigation bar, included on every page. |
| `partials/_flashes.html` | Shows short success/notice messages that a route has set via `flash()`. |
| `partials/_brand_mark.html` | The WAF Monitor logo (SVG), used by the login and error pages. |
| `partials/_kpi_row.html` | The three metric tiles at the top of the Dashboard (policy/default-/custom-profile counts). |
| `partials/_policy_row.html` | A single policy row on the Dashboard, with an expandable detail view. |
| `partials/_profiles_section.html` | Wrapper for a profile section (default or custom profiles) on the Dashboard. |
| `partials/_profile_row.html` | A single profile row on the Dashboard. |
| `partials/_profile_checks.html` | A profile's security-check list, including the editable Learning/Block/Stat/Log checkboxes. |
| `partials/_profile_general.html` | A profile's "General Profile Settings" (settings not tied to a specific check). |
| `partials/_field_value.html` | Formats a single field value for the detail view (e.g. rendering lists as chips). |
| `partials/_log_list.html` | The list of all Logging entries, or the "no entries" message. |
| `partials/_log_entry.html` | A single Logging entry with its summary and expandable details. |
| `partials/_buffer_overflow_actions.html` | Relaxation/create button for buffer-overflow hits. |
| `partials/_starturl_actions.html` | Relaxation button for start-URL hits. |
| `partials/_sql_injection_actions.html` | Relaxation button (with token selection) for SQL-injection hits. |
| `partials/_cmd_injection_actions.html` | Relaxation button (with token selection) for command-injection hits. |
| `partials/_cookie_consistency_actions.html` | Button for switching Cookie Consistency over to Transform. |
| `partials/_csrf_tag_actions.html` | Relaxation button for CSRF form-tagging hits. |
| `partials/_denyurl_actions.html` | Button to create a deny-URL rule from a logged request. |
| `partials/_vserver_row.html` | A single vServer row on the Configuration page, with its backends and bound policies. |

## Static files (CSS)

| File | Function |
|---|---|
| `static/css/base.css` | Base layout, color variables, sidebar styling - used by every page. |
| `static/css/login.css` | Styling for the login page. |
| `static/css/dashboard.css` | Styling for the Dashboard page (policy/profile rows, security-check checkboxes). |
| `static/css/analysis.css` | Styling for the Logging page (toolbar, log entries, all relaxation dialogs). |
| `static/css/objects.css` | Styling for the Configuration page (cards, drag-and-drop highlighting, rule-database bar). |

## Static files (JavaScript)

| File | Function |
|---|---|
| `static/js/dashboard.js` | Expanding/collapsing sections and detail rows, jumping to a profile via link. |
| `static/js/profile_checks.js` | The editable Learning/Block/Stat/Log checkboxes: detects changes, Save/Discard. |
| `static/js/analysis.js` | Drives the Logging page: auto-refresh, Fetch-now, Clear list, search/action filters. |
| `static/js/relaxation_actions.js` | Shared helpers (busy/success/error display on a button) for all relaxation buttons. |
| `static/js/buffer_overflow_actions.js` | Dialog/logic for the buffer-overflow button. |
| `static/js/starturl_actions.js` | Dialog/logic for the start-URL button. |
| `static/js/injection_token_dialog.js` | The shared token-selection dialog used by both SQL and command injection. |
| `static/js/sql_injection_actions.js` | SQL-injection-specific settings for the token dialog. |
| `static/js/cmd_injection_actions.js` | Command-injection-specific settings for the token dialog. |
| `static/js/cookie_consistency_actions.js` | Dialog for switching Cookie Consistency to Transform. |
| `static/js/csrf_tag_actions.js` | Dialog for the CSRF form-tagging relaxation. |
| `static/js/denyurl_actions.js` | Dialog for creating a deny-URL rule. |
| `static/js/objects.js` | The entire Configuration page: every drag-and-drop operation, every dialog (create/assign/delete profile/category/signature, show details). |

## Other files

| File | Function |
|---|---|
| `requirements.txt` | The two external Python packages that must be installed (Flask, requests). |
| `schema.sql` | The SQLite schema from `signature_db.py`, for reference only - it's created automatically on startup. |
| `.gitignore` | Excludes runtime files (`waf_monitor.db`, `.env`, `__pycache__`) from version control. |
| `README.md` | Usage guide: setup, `.env` values, what you can do on each page. |
| `TECHNICAL_NOTES.md` | Technical background, open/unverified assumptions, the history behind individual features. |
