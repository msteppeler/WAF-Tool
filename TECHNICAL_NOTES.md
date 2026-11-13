# NetScaler WAF Monitor – Technical Notes

**This file is not a user guide.** For "how do I use the tool" see `README.md`, for "what
does each file do" see `readme_components.md`. This file contains deeper technical
background: which assumptions are (still) unverified against a real appliance, which
NetScaler quirks surprised us along the way, and why certain things are built the way they
are and not some other way. Useful before changing something that looks "wrong" at first
glance but is actually intentional.

## Files and responsibilities

| File | Purpose | Change here when... |
|---|---|---|
| `app.py` | App setup, routes | adding a route, adjusting default profile names, poll intervals, log path |
| `nitro.py` | NITRO API client (login, requests, policies, profiles, vServer bindings, stats, system files) | new API endpoint, timeouts, HTTP/HTTPS |
| `profile_parser.py` | Splits a profile into security checks + grouped general settings | new check, new field mapping, new label |
| `log_parser.py` | Parses ns.log (CEF format), filters out WAF(AppFW) entries | new check-type label, extension-field label, severity/action coloring |
| `templates/base.html` | HTML skeleton shared by every page | global meta tags, font inclusion |
| `templates/dashboard.html` | Assembles the Dashboard building blocks | order of sections |
| `templates/analysis.html` | Logging page (toolbar + log list) | toolbar elements, page layout |
| `templates/partials/_policy_row.html` | one policy row incl. details | policy display |
| `templates/partials/_profiles_section.html` | profile section (shared by default + custom) | section layout |
| `templates/partials/_profile_row.html` | one profile row | profile header |
| `templates/partials/_profile_checks.html` | collapsible security-checks list | checkbox columns (Learning/Block/Stat/Log) |
| `templates/partials/_profile_general.html` | collapsible, grouped general settings | display of the groups |
| `templates/partials/_log_list.html` | log list, or error/empty state | rendered both on initial load AND during polling (one template, no duplication) |
| `templates/partials/_log_entry.html` | one single, clearly delimited log card | header/detail fields of a log card |
| `templates/partials/_buffer_overflow_actions.html` | relaxation/activate buttons for buffer-overflow hits | button text, display conditions |
| `templates/partials/_starturl_actions.html` | relaxation button for start-URL hits | button text, display condition |
| `static/css/base.css` | shared layout (sidebar, KPIs, flashes, sections, detail rows, chips) | loaded by both Dashboard AND Analysis |
| `static/css/dashboard.css` | Dashboard-specific styling (policy/profile/check cards) | layout, colors on the Dashboard |
| `static/css/analysis.css` | Analysis-specific styling (log cards, toolbar) | layout, colors on the Analysis page |
| `static/css/login.css` | styling of login/error page | layout, colors |
| `static/js/dashboard.js` | expand/collapse logic (`toggleDetails`, `toggleSection`), jump to profile | interaction on both pages (also loaded by Analysis) |
| `static/js/analysis.js` | polling logic of the Analysis page | interval behavior, error display |
| `static/js/buffer_overflow_actions.js` | relaxation/activate buttons: confirmation + NITRO write | confirmation text, success/error display |
| `static/js/starturl_actions.js` | relaxation button for Start URL: confirmation + NITRO write | confirmation text |
| `templates/partials/_sql_injection_actions.html` | relaxation button for blocked SQL-injection hits (HTML/XML/JSON) | button text, display condition |
| `templates/partials/_denyurl_actions.html` | deny-URL button for policy-hit entries ("not blocked") | button text, display condition |
| `static/js/denyurl_actions.js` | deny-URL dialog (editable pattern, live check) + NITRO write | dialog text |
| `static/js/injection_token_dialog.js` | generic "release individual pattern" dialog (SQL + command injection) | dialog layout, text via cfg |
| `static/js/sql_injection_actions.js` | SQL configuration of the dialog + simple confirmation dialog (XML/JSON) | SQL help text |
| `static/js/cmd_injection_actions.js` | command-injection configuration of the dialog (keyword/special string) | CMD help text |
| `templates/partials/_cookie_consistency_actions.html` | transform button for blocked cookie-consistency hits | button text |
| `templates/partials/_csrf_tag_actions.html` | relaxation button for blocked CSRF form-tagging hits | button text |
| `templates/partials/_profile_checks.html` | editable Learning/Block/Stat/Log checkboxes per security check (Dashboard) | save/discard |
| `static/js/profile_checks.js` | dirty tracking + save/discard for the check actions | - |
| `static/js/csrf_tag_actions.js` | two-field dialog (form-origin/form-action URL) + NITRO write | dialog text, origin suggestion |
| `static/js/cookie_consistency_actions.js` | Encrypt/Proxy/Flags dialog + PUT to appfwprofile | dialog text |
| `templates/partials/_cmd_injection_actions.html` | relaxation button for blocked command-injection hits | button text, display condition |
| `static/js/relaxation_actions.js` | shared helpers (busy/success/error display, POST wrapper) for all relaxation buttons | used by BOTH Buffer Overflow AND Start URL |
| `objects_parser.py` | Assembles the vServer/service/policy object hierarchy for the Objects page | vServer/service display |
| `templates/objects.html` | Objects page (vServer, WAF profiles, signatures, signature categories) | section layout, new sections |
| `static/js/objects.js` | drag & drop, all dialogs and live refreshes of the Objects page | pretty much every interaction on the Objects page |
| `static/css/objects.css` | styling of the Objects page (cards, dialogs, rule-database bar) | layout/colors on the Objects page |
| `signature_db.py` | Local SQLite persistence: signature categories, their CVEs, pending profile assignments, rule database (rule_id↔CVE) | new table/field, DB path (`WAF_MONITOR_DB_PATH`) |
| `nvd_client.py` | Searches CVEs for a keyword via the NVD API | search parameters, rate-limit handling |
| `signature_file_parser.py` | Parses the public Citrix signature file (rule ID/category/CVE) | XML schema changes, new fields |

## GitHub/setup files

- **`requirements.txt`** (new): Flask and requests (the externally-imported packages) plus
  gunicorn. **gunicorn is easy to overlook because no Python file imports it** - it's the
  production server the Docker container starts the app with. An earlier version of this
  file omitted it (derived from imports only), which made containers fail on startup with
  `exec: "gunicorn": executable file not found in $PATH`. Everything else in the project is
  Python standard library. An existing Dockerfile would
  need to reference `pip install -r requirements.txt` to use this file (not included here,
  since no Dockerfile from this project was provided).
- **`.gitignore`** (new): excludes `__pycache__/`, the runtime-generated `waf_monitor.db`
  (may contain real CVE/category data, doesn't belong in the repository), and `.env`
  (credentials).
- **`schema.sql`** (new): the same SQLite schema that `signature_db.init_db()` creates
  itself on first start anyway - purely for viewing/documentation without having to read
  Python, not strictly necessary to run manually. Tested with a direct comparison against
  `init_db()`: produces exactly the same schema (9 tables/index, identical wording).
- **Removed dead code:** `nitro.create_appfw_signature_object()` and
  `nitro.enable_appfw_signature_rule()` (the original, per Citrix unsupported clone
  approach, unused since switching to the file-upload approach) as well as the route
  `/policy/<name>/toggle` together with `nitro.toggle_waf_policy()` (unreachable since the
  Enable/Disable button was removed from the Dashboard). No functional change, just
  cleanup - confirmed with the full regression suite.

## Common tasks

**Name a new security check** → `profile_parser.py`, `CHECK_LABELS`
**Map a field to a security check** → `profile_parser.py`, `CHECK_EXTRA_FIELDS`
**Group a general setting** → `profile_parser.py`, `GENERAL_FIELD_GROUPS` (+ label in `GENERAL_FIELD_LABELS`)
**Default collapsed/expanded state of Dashboard sections** → `static/js/dashboard.js`, `defaultStates`
**Name a new AppFW check type in log analysis** → `log_parser.py`, `CHECK_TYPE_LABELS`
**Label a CEF field (cs2/cn1/...)** → `log_parser.py`, `EXTENSION_LABELS`
**Policy hit counter (Dashboard)** → `app.py`, `POLICY_HIT_FIELDS` / `extract_policy_hits`. NITRO returns the counter in `stat/appfwpolicy` as `pipolicyhits` (usually as a string); other field names are only a fallback.
**Change poll intervals** → `app.py`, `POLL_INTERVALS`
**Number of log entries shown** → `app.py`, `MAX_LOG_ENTRIES`
**Log file location/name** → `app.py`, `NS_LOG_LOCATION` / `NS_LOG_FILENAME`
**Fix buffer-overflow field mapping** → `log_parser.py`, `BUFFER_OVERFLOW_FIELD_MAP`
**Adjust buffer-overflow message pattern** → `log_parser.py`, `BUFFER_OVERFLOW_LENGTH_RE`
**Adjust start-URL rule suggestion (e.g. include the query string)** → `log_parser.py`, `_suggest_starturl_pattern`
**SQL message/field name not recognized (no button)** → `log_parser.py`, `SQL_MSG_STRICT_RE` / `SQL_MSG_LOOSE_RE`
**JSON SQL event name differs** → `log_parser.py`, `_sql_event_kind`
**Command-injection event/message not recognized (no button)** → `log_parser.py`, `_cmd_event_kind` or `SQL_MSG_STRICT_RE` / `SQL_MSG_LOOSE_RE`
**Adjust CSRF origin suggestion** → `log_parser.py`, `CSRF_ORIGIN_SUGGESTION`
**Which action tokens are valid** → `app.py`, `CHECK_ACTION_TOKENS`
**Adjust signature-file URL/field names of the NITRO import** → `app.py` `DEFAULT_SIGNATURE_FILE_URL`, `nitro.import_appfw_signature`
**Which checks have no Learning** → `profile_parser.py`, `CHECKS_WITHOUT_LEARN`
**Adjust deny-URL suggestion (e.g. include the query string)** → `log_parser.py`, `_parse_policy_hit`
**What counts as a "too broad" deny pattern and gets rejected** → `app.py`, `DENY_URL_SAMPLE_URLS` / `_deny_pattern_too_broad`

## Editing security checks (Dashboard): Learning / Block / Stat / Log

The four checkboxes per security check (`_profile_checks.html`) used to be purely
informational (`disabled`). They are now editable; a change immediately shows a
"Save"/"Discard" row on the respective check (dirty tracking via `checkbox.checked` vs.
`checkbox.defaultChecked`, see `static/js/profile_checks.js` - nothing is saved
automatically on every click). "Save" writes the check's `*action` field (e.g.
`sqlinjectionaction`) via a NITRO PUT to `appfwprofile` (route
`/profile/<profile>/check/<check>/action` in `app.py`); "Discard" resets the checkboxes
without any request.

**Important: profile-wide effect.** As with the Cookie-Consistency transform, a change
takes effect immediately for ALL requests going through this profile - unlike the
fine-grained relaxation buttons in Analysis, which only affect individual fields/URLs.

**Pre-existing bug found and fixed along the way:** the Stat checkbox used to check for the
token `stat`, but NetScaler actually returns and expects `stats` (plural, see the CLI
reference for all `*action` fields). As a result, "Stat" always showed "off" in the
read-only view, even when statistics were actually enabled. Fixed in `profile_parser.py`
(`structure_profile_checks`); affects display only, not any rule or route.

**Checks without Learning: the checkbox isn't shown at all.** For the following 19 checks -
named by the user and verified against the NetScaler CLI reference - NetScaler has no
Learning option (only Block/Log/Stats/None) - the checkbox is missing entirely there,
instead of being clickable and then rejected by NetScaler
(`profile_parser.CHECKS_WITHOUT_LEARN`, additionally enforced server-side in the route):
Deny URL, Cookie Hijacking, Buffer Overflow, Post Body Limit, Infer Content-Type XML
Payload, File Upload Types, (HTML) Command Injection, Block Keywords, XML Format, XML
Cross-Site Scripting, XML SQL Injection, XML Validation, XML SOAP Fault, JSON Denial of
Service, JSON Cross-Site Scripting, JSON SQL Injection, JSON Command Injection, REST API
Schema Validation, gRPC API Schema Validation.

**One found discrepancy, please double-check:** a published, real NetScaler profile
(blog post "Protecting WordPress based websites using Citrix NetScaler WAF") uses
`-XMLXSSAction learn log stats` - so Learning would work there, contradicting Citrix's own
stated behavior. Implemented as requested (checkbox removed); if XML Cross-Site Scripting
should offer Learning for you after all, remove `xmlxss` from `CHECKS_WITHOUT_LEARN`.

**Seven of the named checks were still completely missing from `CHECK_LABELS`**
(cookiehijacking, postbodylimit, infercontenttypexmlpayload, blockkeyword,
jsoncmdinjection, rest, grpc) - without that, the row would have displayed, but "Save"
would have failed with "Unknown security check" since the route only accepts known field
prefixes. Added.

For all other checks (incl. SQL Injection, XSS, Cookie Consistency, Field Consistency,
Field Format, CSRF Tagging, Start URL), all four checkboxes remain clickable; an invalid
combination is rejected by NetScaler itself and the error is shown 1:1, instead of
guessing locally beforehand (potentially incorrectly).

**All checkboxes off → explicit `none`:** per the CLI reference, a check is only fully
disabled by the token `none`, not by an empty action list - the route implements this
accordingly.

**Not tested against a real appliance:** only with simulated NITRO.

## CSRF form-tagging relaxation

**What the check does:** the CSRF Form Tagging check tags every served HTML form with a
hidden, random field (`as_fid`) and checks on submit whether that value still matches. This
protects against a foreign site submitting its own form against the protected application
(cross-site request forgery) - an attacker can't know this value because they never
received it from the server. The check only applies to server-delivered HTML forms (no
XML, no purely client-generated forms) and NOT when the form-origin and form-action URLs
have different domains (it can't technically check that).

**Why it blocks even though the request looks harmless - typical causes:**
- The Referer/Origin header is missing or was stripped by a proxy.
- The form was delivered outside a regular session (e.g. login form, form from cache,
  regenerated client-side via JavaScript) - then `as_fid` is missing or no longer matches.
- Multi-domain setup: the form comes from a different domain/subdomain than the action URL.

For **blocked** hits (`is_csrf_tag`, event name contains `CSRF`), the button "Create
relaxation rule (CSRF Form Tagging)" appears (`log_parser._parse_csrf_tag`, route
`/analysis/csrf-tag/relax`, NITRO object `appfwprofile_csrftag_binding`).

**Special feature compared to every other check: two required fields.** CSRF relaxations
need both a form-origin URL and a form-action URL (CLI: `-CSRFTag <originURL>
<actionURL>`). The dialog shows both, editable:
- **Form action URL:** anchored, escaped regex from the logged request URL, WITHOUT the
  query string - mandatory per Citrix support ("action URL without query has to be used
  ... adding a query ... will cause failure").
- **Form origin URL:** DELIBERATELY NOT derived from the logged URL, instead pre-filled
  with `^http://$`. In several real, Citrix-confirmed working configurations (support
  article, community threads), exactly this pattern is used when origin matches - NetScaler
  appears to report/expect the origin in this case only as a scheme without a host. This is
  a documented NetScaler quirk, not a guess by this app - still, be sure to test it against
  your own appliance (see below).

**Assumption that should be verified:** which of the two binding fields corresponds to
which URL is NOT confirmed with full certainty (the public NITRO docs on this are
inconsistent). This app assumes: `csrftag` = form-origin URL, `csrfformactionurl` =
form-action URL - derived from the naming convention of all other bindings (main field
without suffix + `formactionurl_<check>`) and the order of the CLI syntax. **Test:** create
the rule, resubmit the form - if it goes through, the mapping is correct; if it's still
blocked, check the profile to see whether the rule works with the values swapped (origin ↔
action), and let me know the result.

**Not tested against a real appliance:** only with simulated NITRO and log lines.

## Signature categories (matched against the NVD) - first part of the signature project

New section "Signature Categories" at the very top of the Objects page, with its own
"+ Add". **Deliberate state of this step:** NOTHING is written to the NetScaler yet -
neither a new appfwsignatures object created nor any existing policy/profile changed. The
import as a real NetScaler signature object (`import appfw signature ...`) is still open,
see the dedicated section below. What's built here is purely local groundwork: CVE research
per category and a noted assignment intention.

- **New dedicated data storage (`signature_db.py`, SQLite):** this tool's first persistence
  layer beyond the pure NetScaler session - three tables (`signature_categories`,
  `signature_category_cves`, `signature_category_assignments`). The file sits next to
  `app.py` by default; path overridable via the environment variable
  `WAF_MONITOR_DB_PATH`. **Important for Docker:** the directory holding this file must be
  mounted as a volume, otherwise the category list is empty after a container restart (the
  NetScaler connection itself is unaffected by this, it was always session-based only).
- **CVE source (`nvd_client.py`):** cve.org itself offers no searchable keyword API, only a
  complete file export. For "which CVEs affect product X", the NVD API (`keywordSearch`)
  is used instead - the same CVE data, made searchable. Without your own NVD API key, a
  limit of 5 requests/30s applies (environment variable `NVD_API_KEY` to raise it to
  50/30s). A failed search term returns an empty list instead of an error, so that a single
  network failure doesn't prevent the rest of the category data from being created.
- **NOT LIVE TESTED:** this environment has no network access to `services.nvd.nist.gov`
  (egress allowlist) - the client was only tested with simulated NVD responses in the
  documented response format. Unlike the NetScaler quirks in this project, though, the NVD
  API 2.0 is a mature, long-stable, publicly documented standard - I estimate the risk of a
  format surprise here, like the one with `appfwsignatures`, to be much lower, but please
  still double-check on the first real run.
- **5 predefined categories** (`app.py`, `SIGNATURE_CATEGORY_PRESETS`): IIS, Apache, OWA,
  SharePoint, WordPress. **OWA and SharePoint additionally search for "Microsoft IIS"** (at
  the user's request, since both run on IIS) - hits are deduplicated across all search
  terms of a category (the same CVE can, for example, show up under both "SharePoint" and
  "Microsoft IIS"). Custom categories with freely chosen search terms (max. 5) are also
  possible.
- **Category cards** are draggable, but the target is a **profile card**, not a vServer
  (same logic as with the signature objects: a signature/category belongs to a profile).
  The drop opens a confirmation dialog and, on confirmation, notes locally that this
  profile should receive the category (`/objects/signature-categories/<id>/assign`) -
  visible as "Pending: <category>" on the profile card. No delete/undo for a pending
  assignment via the UI (not yet needed since nothing real happens yet - easy to add later
  if needed).
- **"Show details" on every category card** opens a dialog with the complete list of
  associated CVEs: ID (linked to `nvd.nist.gov/vuln/detail/<CVE-ID>`, opens in a new tab),
  the search-term badge that found the CVE, publication date, and description text. The CVE
  data is embedded directly as JSON into a `data-cves` attribute of the card when the page
  is built (`list_categories()` now returns it including the individual CVE rows, not just
  the count) - no extra request needed when opening the dialog.

### "Show details" for the real signature objects too

The "Signatures" cards (`lab_waf_sig` etc.) now have the same "Show details" link as the
signature categories - but here **no CVE list**, since that data doesn't exist for real
NetScaler objects (only the free-text report, see above). Instead, the object metadata from
that very report, which used to be discarded during parsing:

`_parse_signature_objects_report()` (`nitro.py`) now, in addition to name/URL/is_default,
also reads: `date_label` ("Creation Date" for built-in sets, "Import Date" for custom ones
- depending on what's in the text) with `date_value`, `base_version`, `size` (bytes as
int), `comment`, `autoenable`, `encrypted_version`. All fields are optional since they're
present differently depending on the object type (built-in sets e.g. have no
"Comment"/"AutoEnable", custom ones often no "Encrypted Version") - the detail view only
shows what was actually in the report, no empty placeholder rows. `size` is converted to
KB/MB for display (`formatSignatureSize()` in `objects.js`).

Tested with the complete example response the user supplied via Postman (`lab_waf_sig`:
Import Date, Base Version 161, 2.65 MB, AutoEnable OFF, empty Comment - correctly not
displayed).

### Deleting: signature categories and real signature objects (only when unbound)

**Answer to the question of whether a category is a ready-made signature file: No.** A
category contains CVE numbers and their descriptions from the NVD - pure metadata about
vulnerabilities, not detection patterns (regex/rule structure) that the WAF engine actually
uses to recognize an attack in traffic. The real path to a deployable object remains
`import appfw signature DEFAULT <name> -sigRuleId ...` (activating existing NetScaler rules
by their internal ID) - the connection missing here remains CVE number → NetScaler-internal
rule ID, see the "Open" section below.

**Categories** (`templates/objects.html`, `static/js/objects.js`
`confirmDeleteCategory()`): "Delete" link next to "Show details". Deletes only locally
(SQLite), no NetScaler access needed. Blocked as long as the category is pending assignment
to at least one profile (`signature_db.count_assignments()`) - **there is currently no
function to remove a single pending assignment**, so an assigned category currently cannot
be deleted at all until this restriction is lifted (easy to add later if needed).

**Real signature objects** (`nitro.delete_appfw_signature_object()`, DELETE
`appfwsignatures/<name>`): before the actual NITRO call, the app itself checks whether any
profile has `signatures == <name>` set (`get_waf_profiles()`), and if so refuses with its
own clear message instead of passing through a raw NetScaler error - NetScaler itself would
refuse to delete a still-referenced object anyway, this check only duplicates that for a
better error message. A NITRO error during the actual deletion (e.g. permissions) is still
shown 1:1.

Tested with simulated NITRO: deleting without a binding (category + signature, each with a
live refresh of the card list without a full page reload), deletion blocked when bound
(both cases), and a rejected NITRO delete attempt (error message in the dialog, card
remains). **Not tested against a real appliance.**

### Implemented: building a real NetScaler signature object from a category

**The decisive breakthrough:** the user linked a real, public Citrix signature file
(`https://s3.amazonaws.com/NSAppFwSignatures/sigs/sig-r14.1b0v183s8.xml` - the same address
NetScaler's own auto-update mechanism downloads from, see the `SignatureUrl` setting
further above). This made it possible to verify the real XML schema for the first time,
instead of guessing:

```xml
<SignaturesFile schema_version="8" version="183">
  <Signatures>
    <SignatureRule id="509" category="web-misc" enabled="OFF" actions="block,log" ...>
      <LogString>WEB-MISC PCCS mysql database admin tool access</LogString>
      <PatternList>...</PatternList>   <!-- the actual detection patterns, not needed -->
      <Reference>bugtraq,1557</Reference>
      <Reference>cve,2000-0707</Reference>   <!-- "CVE-" prefix is missing in the file! -->
      <Reference>nessus,10783</Reference>
    </SignatureRule>
    ...
```

The `id` attribute is exactly the NetScaler-internal rule ID for `-sigRuleId`, and the
`<Reference>cve,...>` child elements provide the previously missing connection CVE number →
rule ID. Categories (Snort-derived) are generic as expected (`web-iis`, `web-misc`, ...),
not "OWA"/"WordPress" - so the CVE route remains the only path to an application-specific
selection.

**New building blocks:**

- **`signature_file_parser.py`** (new): `parse_signature_file()` parses the XML content
  (Python standard library `xml.etree.ElementTree`, no new dependency) into
  `{rule_id, category, log_string, severity, year, cve_ids}` per rule;
  `fetch_and_parse_signature_file(url)` additionally downloads via HTTP. CVE references are
  normalized from `"2000-0707"` to `"CVE-2000-0707"` (NVD format) so a direct comparison
  with the NVD CVE IDs stored in `signature_db` is possible. Tested with a real excerpt of
  the file supplied by the user (rule ID, category, multiple CVEs per rule, no-CVE case).
- **New tables in `signature_db.py`:** `signature_rules` (rule_id, category, log_string,
  severity, year), `signature_rule_cves` (mapping table rule_id↔cve_id, indexed by
  cve_id), `signature_rules_meta` (source, schema/file version, count, timestamp).
  `replace_signature_rules()` replaces the entire state on every refresh (the source file
  is itself the complete, authoritative state, no merge needed). `find_rule_ids_for_cve(s)()`
  returns the rule IDs for one/several CVEs. `get_category()`/`list_categories()` now
  enrich every CVE with `rule_ids`; new field `matched_rule_count` per category.
- **Route `/objects/signature-rules/refresh`** (POST, optional `{url}`, otherwise the
  default URL above): downloads and parses the file, replaces the local rule database. No
  NetScaler access needed, the file is publicly reachable. Only `https://` URLs allowed.
  Controlled via a new "Update rule database" button with a status line (rule count,
  schema/file version) above the category card list.
- **Update after third real appliance test - completely different approach, no more
  cloning:** the field for the rule IDs is `"ruleid"` (confirmed via the developer docs).
  The two-step attempt afterward (clone the object via `import ... DEFAULT <name>` WITHOUT
  any rule filtering, then activate rules individually via `update`) still failed with the
  SAME error as before: NITRO 3197 "Importing the resource failed", still shown in the
  NetScaler log as `Failed to parse Signatures file: /var/download/custom/apache`. **This
  showed: the problem wasn't the rule filtering, it was `import ... DEFAULT <name>` as
  such.** The user clarified this with Citrix's product manager: **there is no API command
  to clone an existing signature object.**

  **So now a fundamentally different approach** (the user's suggestion): download the
  public signature file locally, set only the desired `<SignatureRule>` entries to
  `enabled="ON"` directly in the file itself (all others to `"OFF"`), upload this own copy
  to the NetScaler and import FROM THERE - the only supported path documented by Citrix
  (`import appfw signatures local:signatures.xml MySignatures`):

  1. **`signature_file_parser.build_filtered_signature_xml()`** (new): takes the original
     file downloaded during the last "Update rule database" run (now also stored as raw
     bytes in `signature_db`, new table `signature_source_file`) and sets EVERY
     `<SignatureRule id="...">` to `enabled="ON"` if the ID matches the category, otherwise
     `"OFF"` - structure and all other rules remain unchanged. Tested with a real excerpt
     of the file, including a previously `enabled="ON"` rule that isn't needed and is
     correctly switched to `"OFF"`.
  2. **`nitro.upload_system_file()`** (new): uploads this modified file via the NITRO
     `systemfile` object - an officially documented, concrete example
     (`{"systemfile": {"filename", "filelocation", "filecontent": "<Base64>",
     "fileencoding": "BASE64"}}`), so unlike the appfwsignatures calls so far, a genuinely
     confirmed NITRO form.
  3. **`nitro.import_appfw_signature_from_file()`** (new): `POST
     appfwsignatures?action=import` with `{"name", "src": "local:<filename>"}` - now an
     import from a self-uploaded file instead of from "DEFAULT".

  The route `/objects/signature-categories/<id>/build` first checks whether an original
  signature file is available locally (otherwise a clear error message, run "Update rule
  database" again), then builds the filtered file, uploads it, imports it. If the upload
  fails, the import isn't attempted at all. If the import fails because the object already
  exists, that's reported along with a note that the uploaded file
  (`/var/tmp/<category>.xml`) can be removed manually if needed.
  `create_appfw_signature_object()`/`enable_appfw_signature_rule()` (the previous, per
  Citrix unsupported approach) were completely removed from `nitro.py` during later
  cleanup, not just left unused (see "GitHub/setup files" above).

  **Still NOT verified:** the target directory for the upload (`/var/tmp`,
  `app.SIGNATURE_UPLOAD_LOCATION`) nor whether `"src": "local:<filename>"` correctly
  resolves a file uploaded this way - both chosen to the best of my knowledge, not
  confirmed against a real appliance. The `systemfile` upload itself, however, is based on
  a concrete example documented in the Citrix docs, so it's considerably safer than the
  earlier appfwsignatures calls.
- **Route `/objects/signature-categories/<id>/build`** (POST): collects all rule IDs found
  via `rule_ids` from `get_category()` (deduplicated, sorted numerically) and calls
  `import_appfw_signature(source='DEFAULT', name=<category name>, rule_ids=..., enabled='ON',
  actions=('LOG','BLOCK'))`. Without a loaded rule database or without a single CVE hit, it
  clearly refuses before NetScaler is even contacted. The success message honestly states
  the hit rate ("X of Y CVEs in this category had a matching rule") - not every CVE found
  via the NVD necessarily has a corresponding rule in the (sometimes very old,
  Snort-based) signature file.
- **Seamless reuse:** the newly created object deliberately carries the same name as the
  category and, on success, automatically appears in the existing "Signatures" section
  (live refresh) - from there it can be assigned to a profile via drag & drop just like any
  other signature object. Deliberately NO second, parallel assignment logic was built for
  this.
- **UI:** every category card now shows "X of Y with a matching NetScaler rule" as well as
  a new link "Create in NetScaler" (green, matching the existing links). The confirmation
  dialog explicitly points out the experimental, unverified status. The CVE detail list of
  a category now additionally shows, per CVE, either "NetScaler rule &lt;id&gt;" (green) or
  "no matching rule found" (yellow).

Full flow tested with a simulated, stateful NetScaler (load rule database → create category
with hits → details show correct rule IDs → confirmation dialog → correct NITRO payload →
new object appears in the Signatures section → immediately usable via drag & drop),
including the error cases (no rule database loaded, no CVE with a hit, only `https://`
allowed). **Not tested against a real appliance** - the one remaining unverified point is
the exact NITRO field naming of the import call itself.

## Navigation renamed, "Activate" button removed, multi-language support (start)

**Renaming:** the nav entry "Objekte" is now "Configuration" (translated), "Analysis" is
now "Logging" (translated) - technically only the displayed text, routes/URLs (`/objects`,
`/analysis`) remain unchanged.

**"Activate" button removed:** the entire Enable/Disable toggle per policy
(`templates/partials/_policy_row.html`, the `<form>` with `toggle_policy`) was removed -
this includes both the "Activate" and the "Deactivate" label (the same button depending on
state), since a half-removed control (only one label gone) would have looked inconsistent.
The route `toggle_policy`/`toggle_waf_policy` (`app.py`, `nitro.py`) was afterward
unreachable from anywhere in the frontend and was completely removed during later cleanup
(see "GitHub/setup files" above), not just left unused.

### Multi-language support: German/Italian/French/English based on browser language

**Deliberately without a new package dependency** (e.g. Flask-Babel): the project has no
requirements.txt/package management through which a new dependency would reliably reach the
Docker image - instead a small, custom module, **`translations.py`** (new), Python standard
library only:

- `detect_locale(accept_language_header)`: evaluates the browser's `Accept-Language` header
  (sorted by `q` priority), picks the first supported language (de/it/fr/en). **If none of
  those languages is present, English is used** (as requested) - also when the header is
  missing.
- `translate(locale, key)`: returns the translation, falling back to English and then to
  the key itself (a missing key thus stands out visibly instead of throwing an exception or
  staying empty).
- `TRANSLATIONS`: nested dict per language. A test checks that all 4 languages have exactly
  the same keys (no forgotten translation).

**Wiring** (`app.py`): `@app.before_request` determines `g.locale` fresh on EVERY request
from the header - **not** stored in a session/cookie, as requested ("based on browser
language"): if the user changes their browser language, it takes effect immediately on the
next load, no re-login needed. `@app.context_processor` makes `t('key')` and `locale`
available in every template without having to pass them individually to
`render_template()`. `base.html` sets `<html lang="{{ locale }}">` accordingly.

**Translation status after this second step:** fully translated now are login,
sidebar/navigation, the Dashboard page AND the Logging page (formerly "Analysis") - page
title, complete toolbar (search field, action/interval label including the interval values
themselves "1 Minute"/"3 Minuten"/"5 Minuten", Fetch-now/Clear-list buttons including
tooltips), the "no matches"/"no entries found" text, as well as the three fixed detail-row
labels Message/Request-URL/Severity. Three status texts generated at runtime by JavaScript
(refreshing.../last updated/session expired/list cleared) are now also translated - for
this, `analysis.html` embeds the matching translations as a small JSON block in the HTML
(`#logging-i18n-data`), which `analysis.js` reads out; without this JSON, each spot falls
back individually to its previous German text (`||` in JS), so a missing/empty block breaks
nothing. **Found and fixed along the way:** the time formatting (`formatTime()`) was fixed
to `de-DE`, regardless of the selected language - now tied to `<html lang>` (consistent
24-hour format even for English, more fitting for a technical monitoring tool than an
AM/PM switch).

### Fixed bugs: Configuration page title/heading + wrong browser title

**Reported by the user:** after the renaming, the navigation correctly showed "Logging" and
"Configuration", but the page itself (browser-tab title AND `<h1>` heading) still showed
the old, hard-coded "Objekte" when opening "Configuration" -
`templates/objects.html` had simply been overlooked in the previous translation step (only
the sidebar link, not the page itself, had been switched over). Fixed: `<title>` now uses
`t('configuration.title_tag')`, `<h1>` uses `t('sidebar.configuration')` (the same text as
the nav link, consistent).

**Additionally found and fixed along the way:** `logging.title_tag` for German was
mistakenly set to the English text "Logging – WAF Monitor" instead of "Protokollierung –
WAF Monitor" (a copy-paste error when the translation table was originally created) - the
browser tab showed "Logging" while the `<h1>` correctly showed "Protokollierung". Now
consistent.

Re-checked with all 4 languages: `<title>` and `<h1>` now match on both pages and correspond
to their respective nav label. The rest of `objects.html`/"Configuration" page content
(section headings, dialogs, card text) is still NOT translated - that remains the next,
considerably larger step.

**Deliberately NOT YET translated, same reasoning as the Dashboard step:** the
Objects/Configuration page, the labels and hint text of the seven relaxation-rule buttons
(Buffer Overflow, Start URL, SQL/Command Injection, Cookie Consistency, CSRF, Deny URL -
among others `entry.sql_button_label`/`entry.sql_scope_note` etc., which are built
dynamically with interpolated values in `log_parser.py`, not simple static template
strings), the names of the check/event types themselves (e.g. "SQL Injection",
"Cross-Site Scripting (XSS)" - come from `CHECK_LABELS` in `log_parser.py`), as well as all
the dynamic success/error messages from the POST routes in `app.py`. These parts are deeply
tied to already-existing, value-interpolating Python logic - translating them now too would
have meant building dozens of message building blocks per language instead of just
swapping template text, and would have been too risky/large for this step. Technical WAF
terms (Learning, Block, Stat, Log, "Security Checks", "General Profile Settings", "WAF
Policies", "vServer", "Hits", "Request-URL", "All"/"Blocked"/"Not Blocked") remain
deliberately untranslated - these are NetScaler's own GUI terms; an administrator should
recognize them regardless of the tool's language.

Tested with all 4 languages as well as the fallback case (unsupported browser language, no
Accept-Language header) - both the login page (directly via the Flask test client, since
the Playwright mock servers force a login state and `/` would otherwise redirect
immediately) and the Dashboard page in the browser (incl. `<html lang>`, nav renaming,
removed Activate button).

## Final cleanup: short messages, details in the log, dead code removed

**Why.** The long messages (per-file counts, funnel, reasons, CVE lists, file lists of the Snort set) were built to find out why too
few rules were added. With everything working they are noise for the user, so the messages are short now and the details moved.

**Messages (user-facing).** Creating a category: `Kategorie "x" angelegt: N CVEs aus der NVD, M aus den Regelwerken.` Updating the rule
database: `Regel-Datenbank aktualisiert: N Citrix-Regeln (Version V), M Snort-Regeln (ET Open, T übersetzbar). [Nicht geladen: <Dateien>.]
[Kategorien ergänzt: A +n, B +m.]` Creating the object: `Signatur-Objekt "x" erstellt: N Citrix-Regeln aktiviert, M Snort-Regeln ergänzt
(Aktion: block,log). K von T CVEs ohne passende Regel. Jetzt in "Signaturen" einem Profil zuweisen.` Rejections are one sentence. What
stays in the message because it is actionable: a one-line hint when the rule database is missing or the Snort set is empty or incomplete
(`_rule_db_hint()`, driven by `_snort_db_status()`, which compares the loaded ET files with the expected four), the "nicht geladen" file
names, and - when NetScaler rejects the file - the ACHTUNG note with the ns.log reason (now at most two lines of 200 characters).
Singular/plural is handled (`_count()`: "1 Regel" / "2 Regeln").

**Details for troubleshooting** are printed to the server log (`_log_details()`, visible with `docker logs`): per category the NVD hits per
term and the rule-derived counts; per "Update rule database" the per-file active/disabled counts, the funnel (HTTP, with CVE,
translatable), the skipped commented-out rules, the reasons and blocking options, and per-file download errors; per build the CVE split
(Citrix / translated Snort / only too-complex Snort rules with CVE ids / no Snort rule) and the description of the Snort set. On demand:
`python3 find_gap_examples.py --reasons` recomputes the funnel and reasons from the database (new), next to `--category` and `--term`.

**Dead code removed** (found with an AST scan for unused imports, unused module-level functions and never-read locals, then confirmed by
a stricter check for names with no reference in code): `snort_rule_parser.fetch_and_parse_snort_rules` and `index_rules_by_cve`,
`signature_db.find_rule_ids_for_cve`, `nitro.get_services` and `get_servicegroups` (and their unused imports in `app.py`), two never-read
variables, and the helpers `_snort_db_description` and `_complex_sentence` (replaced by the log line). Stale descriptions were updated (the
module header of `snort_rule_parser.py` still described NetScaler's own Snort import as an open question).

**Speed.** Measured with 8,600 realistic ET-style rules (5.7 MB): parsing all rules 0.8 s (0.09 ms per rule), the category sync 0.15 s per
category (0.7 s for five) - no problem, so the parser was left alone. The one repeated cost was re-parsing the same rules for every
category; `_is_translatable()` in `signature_db.py` now caches the result per rule text (`functools.lru_cache`).

**A slip caught by a check:** the first version of the message rewrite cut a marker range in `app.py` that also swallowed five unrelated
functions (`_set_locale`, `_inject_translation_helper`, `extract_policy_hits`, `build_enriched_policies`, `load_appfw_log_entries`). It was
caught by comparing the list of functions and decorators before and after, and restored; the final comparison shows only the intended
functions removed or added.

**Tests.** The eleven earlier runs were kept and adapted to the new wording; they now also check that the messages are short (length
limits, none of the old detail wording) and that the details reach the log. Run on a fresh copy of the project: all pass (classification,
position translation with the random comparison against the reference model and the five injected errors, schema limits and fallback,
category flow, refresh, build scenarios).

## NetScaler validates the imported file against a schema - one bad value rejects the whole object

**User's error** on "Create in NetScaler": `Problem validating Imported object against specification (NITRO 3257)`; `ns.log`:
`... Execution Attempt (CVE-2026-45434)' has length '149' which exceeds maxLength facet value '128'`, then `Import Failed: The Signature you
are trying to import is invalid`. Builds without translated Snort rules had worked.

**Cause.** The `LogString` of a translated rule was the ET message unchanged, and ET messages can be longer than 128 characters.
NetScaler validates the whole file against a schema, so that one value made it reject everything - including the Citrix rules.
Until now no translated rule had ever been imported on the appliance (the structure was modelled on the exported file, but not
imported), and the test suite had no model of the format's limits, which is why this was not caught.

**What Citrix's own file shows** (the user's `testsig.xml`, 3057 rules; observed maxima are lower bounds of the real limits):
`LogString` at most 128 characters and none above (304 rules at 120 or more), only printable ASCII, a trailing CVE kept when long;
`Comment` at most 29 characters (only 2 rules have one, e.g. "Related rules: 999998, 999997"); `Reference` at most 155 characters and 12
per rule; `LITERAL` pattern at most 132; `PCRE` pattern at most 253; at most 6 patterns per rule.

**Changes.**
- `fit_logstring()`: printable ASCII only, whitespace collapsed, at most 128 characters; when too long, a trailing "(CVE-...)" is kept
  and the descriptive part before it is cut with "...". `Comment` is now "WAF Monitor SID <n>" (at most 29), at most 12 `Reference`s.
- Limits in the classifier (`MAX_LITERAL_LENGTH`, `MAX_PCRE_LENGTH`, ...): a rule whose pattern or generated regex would exceed what
  Citrix's own file contains is not translated (reason `too_long`) instead of risking the whole import.
- Shorter regexes: characters Citrix itself escapes with a single backslash (`. \ / [ ] ? - $ ( ) & " % > ' | + : < = # ~ ,`) are written
  that way (`\/`, `\.`), everything else non-alphanumeric stays `\xHH`; gaps use the forms Citrix uses (`{n}`, `{0,N}`, `{n,}`, `.*?`),
  never `{0,0}`. Checked character by character: for each of the 95 printable ASCII characters (and hex bytes, and `nocase`) the literal
  matches exactly that character; the 207,636-comparison random test against the reference model still shows 0 differences, and the five
  injected errors are still detected.
- **If the import is still rejected** (a limit we do not know): the tool reads the latest matching lines from `ns.log` (the file the
  Logging page already reads; NITRO only says "see ns.log") and shows them. If the category also has Citrix rules, it repeats the import
  with the Citrix rules only and says clearly that the translated rules were NOT included and why. A Snort-only category is not retried
  (it would become an object with no active rule); other errors (e.g. "already exists") are unchanged.
- Tests now apply every known limit to every generated rule.

**NOT VERIFIED:** further schema facets we have not seen (the observed maxima are only lower bounds); whether `Comment` has a tighter limit
than we stay under; and, as before, whether NetScaler accepts the regex patterns and how it matches them. The fallback means a surprise no
longer takes the Citrix rules down with it.

## Positions (distance, within, startswith, endswith, depth, offset) are now translated, as regex

**User's second refresh** (after `target` / `flowbits:set` were allowed): translatable rose from 139 to 256 (+117). Blocking options,
"total / blocked only by this option": `distance` 2328 / **1983**, `pcre` 2194 / 1399, `startswith` 464 / 96, `bsize` 433 / 23,
`within` 191 / 18; the category assignment now also reported `apache +153`. So `distance` alone held back 1983 of the 5160 rules with a
CVE reference - by far the biggest lever, and the cheap way out (just ignoring it) would have made translated rules broader than the
originals: `distance:0` is an ordering constraint (e.g. `content:"id="; content:"'"; distance:0;` means the quote *after* `id=`), and
these rules block.

**Evidence that this can be done faithfully** (user's `testsig.xml`): Citrix expresses order and distance as PCRE patterns in its own
rules (293 of 887 PCRE patterns use `.*`/`.+`, e.g. `(?ism).cmd\x22.*\x26.*`), always keeping literal patterns next to them as
prefilter (rule 16426: literal `<?xml` plus PCRE at the same location). What Citrix uses, and what is therefore mirrored: inline flags
at the start (`(?s)`, `(?is)`, ...), `^` (50 patterns) and `$` (26), lookaheads `(?!...)`, lazy `.*?` (48), `{n,m}` (13), `\xHH` escapes
for special characters. What Citrix never uses: `\A`, `\z` (0 patterns) and scoped flags `(?i:...)` (0). A scare about doubled
backslashes turned out to be an artifact of how the output was displayed: in the XML the backslashes are single (684 `\xHH` single vs 1
doubled; odd-length backslash runs 1436 vs even 40).

**Design.** Per location the patterns of a rule form chains: a chain starts at a pattern without distance/within and takes the following
relative patterns of the same location. A chain with at least one positional modifier gets ONE extra `PCRE` pattern at that location; the
literal patterns stay (prefilter, fast match, and the AND over all patterns as before). `group_to_pcre()` builds it:
`startswith` -> `^`, `depth N` -> `^.{0,N-len}`, `offset N` -> `^.{N,}?`, `distance N` -> `.{N,}?` (`.*?` for 0), `within N` ->
`.{0,N-len}`, `endswith` -> `(?!.)` (with `(?s)`: no character follows - exactly the end, unlike `$`), `nocase` -> `[aA]` classes
per letter, other bytes as `\xHH`. Semantics as in Suricata/Snort: depth = the match ends within the first N bytes; offset = it starts
no earlier than byte N; distance/within are relative to the end of the previous match.

**Deliberately not translated** (ambiguous between Snort and Suricata, or not clearly expressible) - reason code `position_combo`:
`depth` together with `offset`, `startswith` together with `depth`/`offset`, `within` together with `distance > 0`, absolute together with
relative modifiers on one pattern, non-numeric or negative values, `depth`/`within` smaller than the pattern, `endswith` before further
patterns of the same location, `distance`/`within` without a previous pattern in the same buffer, and chains longer than 3 with positions
(`MAX_CHAIN_LENGTH`; keeps regex size and run time in check). `bsize`, `urilen`, `isdataat`, `dsize`, `rawbytes` stay blocking
(reason "Längenangaben"). A positional pattern counts as one more pattern against `MAX_NATIVE_PATTERNS` (6).

**Verification beyond examples.** A reference model of the Snort semantics (does an assignment of match positions exist that satisfies
every constraint?) was compared with the generated regex on random rules and buffers through the whole path from rule text through the
parser: 17,303 chains x 12 random buffers = 207,636 comparisons, 0 differences. To be sure the comparison can fail, five deliberate
errors were injected into the generator (endswith anchor dropped, startswith anchor dropped, ordering dropped, within bound one too large,
nocase ignored) - all five were detected. Also: 13 supported and 16 rejected combinations, the pattern layout, the whole file, and a run
through the build route.

**The user's real Linksys rule** (CVE-2013-3568, the one NetScaler's own conversion could not import) is now translatable, with six
patterns: URL literal `/ping.cgi` as fast match, method `POST`, body `pingstr=` and `|3b|`, a URL regex that anchors exactly `/ping.cgi`
(`^.{0,0}...(?!.)`) and a body regex (`pingstr=` at the start, `;` within 25 bytes after it).

**NOT VERIFIED (only an import on the appliance can show):** that NetScaler accepts these regexes (the constructs are the ones Citrix
itself uses, but the exact combination is new); against what a `HTTP_URL` / body / header pattern is matched (normalised or raw,
whole body or lines) - the literals have the same uncertainty; the regex run time on very large bodies (lazy `.*?` between at most three
patterns; the literal prefilter should keep it rare); and `nocase` on the *literal* patterns (the regex handles it, the separate literal
does not - unchanged caveat). Tests that previously used `depth`/`endswith`/`distance` as a stand-in for "too complex" were switched to
options that still block (`pcre`, `urilen`, `bsize`).

## First real ET Open numbers, and what they changed

> **Note:** the long messages described in this section (and in the ones below) were shortened later; the details moved to the server log - see "Final cleanup" above.

**User's "Update rule database" result** (Citrix file version 188, 3229 rules): Snort rule set 8595 rules from four files -
`web_specific_apps` 6099 active / 880 disabled, `web_server` 721 / 185, `exploit` 1713 / 387, `current_events` 62 / 186; 1638 rules
commented out by ET were skipped. Of the 8595 rules 8050 are HTTP, 5160 of those carry a CVE reference, and only **139 are simple
enough to translate** (2.7%). Reasons for the rest: position options 2458, `pcre` 2247, other options 297, no location 9. Most frequent
blocking options: `distance` 2353, `pcre` 2247, `target` 1390, `startswith` 476, `bsize` 436.

**Confirmed:** the earlier set of 1713 rules was the `exploit` file alone (it has exactly 1713 active rules), i.e. the database was
stale from the single-file days - the file list added to the messages was the right diagnostic. The Snort source is now complete;
the bottleneck is the translator, not the data.

**What the numbers exposed:**
- `target` (1390 rules) was blocking rules without reason: in Suricata it only states which side the alert names as the attack target
  and does not change what the rule detects. Now allowed.
- `flowbits` was treated as one thing. `flowbits:set/unset/toggle` only set a marker for *other* rules and do not change what this rule
  detects; `isset`/`isnotset` are conditions (the rule only fires after another rule fired) and `noalert` makes a rule a silent helper.
  `_flowbits_harmless()` now looks at the value: only set/unset/toggle (all instances) are harmless; everything else still blocks.
- Rules that inspect the server response (`http.response_body`, `http.stat_code`, `file_data`, ...) were filed under "other
  options". They get their own reason, `response` ("prüft die Server-Antwort"): a request rule cannot replace them.
- The refresh message now lists, per blocking option, the rule count and how many rules that option blocks *alone*:
  "distance 2353 / 120" means 2353 rules use `distance`, but only 120 would become translatable if it were relaxed. That second
  number is the real gain per option - the first overstates it, because many rules carry several blockers at once.

**The user's ownCloud rules** (`--term owncloud`): five ET rules, none translatable: 2049614 only because of `flowbits` (a `set`, now
translatable), 2049615/2049616/2049618 are "Successful ..." rules that read the response, 2049617 uses `flowbits`, `pcre`, `threshold`.
This changes nothing for ownCloud itself: Citrix already covers CVE-2023-49103 and CVE-2023-49105 (rules 998561, 998560), and Citrix
has priority.

**Deliberately NOT relaxed - the decision points the next numbers should inform:**
- `distance` / `within` (ordering and proximity of patterns). `distance:0` alone only means "after the previous match"; dropping it would
  let patterns match in any order, i.e. slightly broader than the original, and these rules block.
- `startswith` / `endswith` / `bsize` (anchoring; `bsize` is an exact buffer length). Dropped, an "exactly this URI" rule would become a
  "URI contains this" rule - potentially far broader.
- `pcre`. The native format has `PCRE` patterns, but Citrix's converter rewrites the syntax (e.g. `\<`, `\x3D`); doing it right needs
  verified examples, not guesses.
- `threshold` (rate-based): dropping it would block on the first hit instead of after N hits.

**NOT VERIFIED:** how many rules `target` and `flowbits:set` alone free up on real data (only the next refresh message shows it:
the "allein" numbers); and that dropping `flowbits:set` is safe for every ET rule - it is by definition, but only a real import and
traffic will show surprises.

Tested: 15 classification cases for `target`, the `flowbits` variants (set, unset, set+target, isset, isnotset, noalert, mixed, noalert as
keyword), response rules, and the unchanged blockers (`threshold`, `bsize`, `distance`, `pcre`); the three ownCloud rules rebuilt from
the options named in the user's output (2049614 now translatable, 2049615 `response`, 2049617 `pcre`); the "alone" counts; the real Linksys rule
still rejected; and all earlier test runs (classification, refresh message, category flow, build scenarios, nc23 reproduction).

## Making the Snort side explain itself (test with nextcloud / owncloud / caldav / carddav)

> **Note:** the long messages described in this section (and in the ones below) were shortened later; the details moved to the server log - see "Final cleanup" above.

**User's test and messages.** Category `nc23`, terms nextcloud, owncloud, caldav, carddav: 52 CVEs from the NVD (15 / 15 / 8 / 15,
deduplicated), plus 2 CVEs from rule text ("2 aus Citrix-Regeln, 0 aus übersetzbaren Snort-Regeln"). Build: 2 Citrix rules
activated; "für 52 CVE(s) gibt es im geladenen Snort-Regelwerk (1713 Regeln, 1257 HTTP-relevant) keine HTTP-Regel".

**What the data says.**
- The 2 Citrix rules are very probably CVE-2023-49103 (the well-known ownCloud graphapi flaw) and CVE-2023-49105
  (WebDAV authentication bypass): in the user's `testsig.xml` they are Citrix rules 998561 and 998560, both titled
  "WEB-MISC ownCloud ...". Both came from the rule-text match, not from the NVD - the NVD's first 15 hits per term are
  old CVEs and none of those has a rule. Citrix having a rule for a CVE also means no Snort rule is added for it
  (Citrix has priority), which is correct.
- **1713 Snort rules is suspiciously few** for four ET files (`web_specific_apps` alone is over 5 MB). The figure is
  closer to a single file, so the database is probably either left over from the time only `emerging-exploit.rules` was
  loaded, or some files failed to load. This is an inference; the "Update rule database" message lists per-file results.
- Whether ET Open has any active rule for these products could not be established from here (a web search found only
  reports about the vulnerabilities, no rule).

**Gaps found in what the tool told the user.**
1. The message gave the size of the Snort set but not *where it came from*, so an incomplete set could not be spotted.
2. CVEs whose Snort rules mention a search term but are too complex to translate were counted internally
   (`stats['snort_complex']`) and then thrown away, so "0 from Snort" could not be told apart from "Snort rules exist
   but are all too complex".
3. ET comments out rules it considers too noisy, outdated or slow; the parser skips them and never said how many.

**Changes.**
- `_snort_db_description()` (app.py): the Snort set is now described as "N Regeln, M HTTP-relevant, aus: <files>, Stand
  <date>" and, if any of the four expected files is absent, "es fehlen: ... bitte 'Regel-Datenbank aktualisieren'
  ausführen". Used in the build message and in the dead-end rejection.
- `sync_rule_derived_cves()` returns `snort_complex_cves`; creating a category and building it now name those CVEs
  ("Außerdem gibt es für N weitere CVE(s) Snort-Regeln, die einen Suchbegriff nennen, aber zu komplex ... sind (CVE-...)").
  Creating a category also says when the Citrix rules are loaded but the Snort set is empty.
- Parser: `count_disabled_rules()` counts commented-out rules; "Update rule database" shows, per file, "N aktiv, M
  deaktiviert" and the total skipped. Download and parsing were split (`_fetch_rules_text`) without changing
  `fetch_and_parse_snort_rules`.
- `find_gap_examples.py --term <keyword>`: lists every Snort rule and every Citrix rule whose text names the keyword;
  for Snort rules it states translatable / too complex (with the reason) / no CVE reference / not recognised as HTTP,
  and when nothing is found it says why that can be and to check the file list. Answers "does ET have anything for
  this product, and why is it not used" without needing a category. The file list in its output was also shortened.

**Still open / not done.** The NVD part is unchanged (15 hits per term, apparently the oldest); commented-out ET rules stay
skipped on purpose, because they were disabled for false positives, and these rules now block. NOT VERIFIED: that ET Open
contains no usable rules for nextcloud / owncloud / caldav / carddav - only the next "Update rule database" and
`--term` on the user's data can show it.

Tested by reproducing the user's case (53 NVD CVEs from mocked old hits, the real Citrix file, a Snort set from `exploit`
only with one too-complex ownCloud rule): the create and build messages name the file list, the missing files and the
complex CVE; `--term ownCloud` shows the Snort rule as too complex (`depth`, `endswith`) and Citrix rules 998560/998561;
`--term caldav` explains the empty result; the refresh message counts active and disabled rules per file. All earlier
checks (classification, generator, category flow, refresh message, build scenarios) still pass.

## Snort translator widened: several patterns, more locations, safer whitelist, and a location-detection bug

> **PARTLY SUPERSEDED**: the statement below that position options (`depth, offset, within, distance, startswith, endswith`) stay blocking no longer holds - see "Positions (distance, within, startswith, endswith, depth, offset) are now translated, as regex" above. `urilen`, `bsize`, `isdataat`, `pcre` and `threshold` still block.

**User report:** a category with 54 CVEs activated only 2 rules; "our Snort query seems to be ignored". It was not
ignored: the translator accepted too little, and part of what it should have accepted was misread.

**Finding 1 - a bug in location detection (the likely main cause).** Classic Snort rules write the location after
the pattern, often with another modifier in between: `content:"/a"; nocase; http_uri;`. The parser only recognised
the location when it came *directly* after the content, so such rules fell out as "no location". Also, the two
notations were mixed up although they work differently: `http_uri` (underscore) is a modifier for the *preceding*
pattern only, `http.uri` (dot) is a sticky buffer for all *following* patterns. A pattern after `http_uri` without
its own modifier lies in the default buffer, not in the URL. `_extract_content_matches()` now implements exactly
that. Found by a test case, not by looking at real ET data.

**Finding 2 - the one-pattern limit was stricter than needed.** The user's `testsig.xml` shows how Citrix itself
represents Snort rules: several `<Pattern>` elements in one rule - 992 rules with 2 patterns, 813 with 3, 191 with
4, 21 with 5, 5 with 6. Rule 803 ("HyperSeek hsx.cgi directory traversal") has three URL literals where the Snort
original requires all three, so several patterns mean AND. Rule 16426 combines `HTTP_METHOD` "PROPFIND",
`HTTP_POST_BODY` and `HTTP_URL`. Citrix keeps Snort's hex notation inside `LITERAL` patterns unchanged (228
patterns, e.g. `|00|`, `|20|/HTTP/1.`). Every rule has exactly one `fastmatch` pattern (3008 of 3057), usually first
(1868 of 1995 multi-pattern rules), placed in `HTTP_URL` (2696), `HTTP_METHOD` (190), `HTTP_RAW_URL`, `HTTP_HEADER`
(47), `HTTP_FORM_FIELD` or `HTTP_COOKIE` (5) - never in `HTTP_POST_BODY`.

**Changes.**
- Translatable now: 1 to 6 patterns (`MAX_NATIVE_PATTERNS`), each in `NATIVE_LOCATION_AREAS` = URL, METHOD,
  POST_BODY, HEADER, COOKIE (user-agent buffer excluded), not negated, not empty, no backslash escapes, valid
  `|hex|` notation, and at least one pattern in a fast-match location (`FASTMATCH_AREAS`).
- `build_native_signature_rule()` writes one `<Pattern>` per match. The fast-match pattern is a `fast_pattern`-marked
  one if its location allows it, otherwise the longest pattern outside `HTTP_METHOD`; it goes first. Verified
  against Citrix rule 16426: every generated `<Pattern>` has the identical tag/attribute structure.
- **Whitelist instead of blacklist** (`_ALLOWED_RULE_KEYS`): any option not known to be harmless makes the rule
  untranslatable. Before, unknown options such as `flowbits:isset`, `threshold` or `urilen` slipped through
  silently, so a translated rule could be broader than the original - and these rules now block. `fast_pattern`
  is harmless (it only picks the prefilter pattern; all patterns must still match) and no longer blocks;
  `nocase` is tolerated. Position options (`depth, offset, within, distance, startswith, endswith, urilen,
  isdataat`) stay blocking: without them the rule would match more broadly than the original. `pcre` stays
  blocking. Rules that check the server response (`flow:to_client` / `from_server`) are rejected.
- `classify_for_native_translation()` returns `(ok, reason, code)`; `parse_rule_line()` adds
  `native_translatable_code` and `native_blocking_keys`. `summarize_untranslatable()` turns them into text.
- "Update rule database" now appends why rules are not translated, e.g. "Nicht übersetzbar wegen:
  Positionsangaben ...: N, pcre-Muster: N ... Häufigste blockierende Optionen: endswith (N), depth (N) ...". That
  shows which restriction costs the most, so the next widening can be chosen from numbers instead of guesses.
- `find_gap_examples.py` lists all patterns of a translatable rule.

**What stays out, and why it matters:** most modern ET rules use `depth`, `startswith`, `endswith`, `within` or
`pcre`. The real Linksys rule (CVE-2013-3568) still does not qualify (`depth, endswith, within`). The native format
has `offset`/`depth` attributes on `Match`, but only one rule in the whole file uses each - too thin to rely on.

**NOT VERIFIED:**
1. That several patterns combine with AND in NetScaler is inferred from Citrix's own conversions of Snort rules
   (e.g. rule 803), not from NetScaler documentation.
2. What exactly `HTTP_HEADER` / `HTTP_COOKIE` / `HTTP_POST_BODY` compare against (whole header text vs. value) is
   inferred from how Citrix uses them; the first real import and a test request will show.
3. Whether the generated rules import, and `nocase` handling (see above) - unchanged from before.
4. How much this raises the yield on real ET Open data. Only simulated rules were tested; the numbers in the next
   "Update rule database" message answer that.

Tested: 25 classification cases (including the two notations, `uricontent`, hex validity, escapes, negation,
pcre, position, flowbits, threshold, response rules, user-agent, post-body-only, more than six patterns); the
generator on a four-pattern rule built from the real Linksys rule minus its position options (structure checked
against rule 16426, one fast-match pattern, hex preserved, fast_pattern preference, method-as-fast-match); the
whole file with three added rules (no duplicate ids, our own parser reads every CVE back); the category flow with
a multi-location rule (279 Citrix rules plus 2 translated ones, checked against an independent computation); the
"Update rule database" message with a mix of translatable and blocking rules; and the earlier build scenarios.

## Categories now also take their CVEs from the rule sets (not only from the NVD)

**Why.** Evidence from the user's exported `testsig.xml` (version 161): the Citrix file has WordPress rules for
205 distinct valid CVEs, nearly all from 2018 to 2025, yet a WordPress category matched only 2 of them. The NVD
client (`nvd_client.search_cves_by_keyword`) fetches just the first page of 15 hits per term, with no paging and
no ordering, and the user's example CVE-2006-0733 (WordPress 2.0.0, disputed) suggests those 15 are the oldest.
(That the NVD returns oldest first is an inference, not verified from here.) Newer CVEs never entered the
category, so neither Citrix nor ET could contribute anything for them. Plain "newest first" would not have
helped either: newer plugin CVEs mostly have no rule at all. The user chose the rule-driven way: take the CVEs
from the rules.

**Mechanism** (`signature_db.py`): `find_rule_derived_cves(terms)` looks in the loaded rule databases for rules
whose text mentions a search term - for Citrix the category plus `LogString`, for Snort the `msg`. Matching is
word-based: the generic words `microsoft, server, http, the, and, for, web, application, app, of` are dropped,
and every remaining word must appear as a whole word (so `iis` does not match inside another word, `d-link`
stays one word, and "Microsoft IIS" finds the Citrix rules titled "WEB-IIS ..."). Citrix rules take priority;
a Snort rule only counts if it is HTTP and simple enough to translate (otherwise it would not be actionable -
those CVEs are counted but not added). `sync_rule_derived_cves(category_id)` replaces the rows it created
earlier and inserts the current ones; rows from the NVD are never touched, and a CVE that is already there from
the NVD is not duplicated (it keeps its NVD description and date). `sync_all_categories_rule_derived_cves()`
does this for every category. No schema change: rule-derived rows are marked by `matched_term` starting with
`Regeltext: ` (`RULE_SOURCE_PREFIX`), which the details dialog already shows as a badge; their description is
the rule's text, their date stays empty.

**When it runs:** when a category is created (if rule sets are already loaded; otherwise the message says to
update the rule database), after every "Update rule database" for all categories (new rules appear, removed ones
disappear), and at the start of "Create in NetScaler" so categories created before this change benefit at once.

**Result on the user's data** (strict word matching against the real `testsig.xml`, verified against an
independent count straight from the XML): WordPress 205 CVEs, IIS 71, OWA 88, SharePoint 26, Apache 142. A
simulated WordPress category (3 NVD CVEs, one of them CVE-2006-0733) grew to 208 CVEs, and the build enabled
exactly the 279 Citrix rules that belong to those CVEs plus one translated Snort rule, instead of 3 rules.
Six references in the Citrix file are malformed (e.g. `CVE-20120391`, two IDs glued together); our parser
drops them and so did the cross-check.

**Caveats.**
- The match is on rule text, not on CPE or product version, so a category can include rules for old versions,
  and a CVE the NVD would assign to the product but whose rule text never names it is not found (a custom term
  must actually appear in rule texts).
- "Apache" is broad: Citrix titles like "WEB-MISC Apache Tomcat ..." match, so the Apache preset also pulls in
  other Apache projects (Tomcat, Struts, ...). Use a more specific custom category if that is unwanted.
- The NVD part itself is unchanged (still 15 hits per term). Paging through all NVD hits remains possible as an
  addition; it was not chosen.
- On the Snort side this was tested with simulated rules only; real ET Open numbers appear after the first
  "Update rule database" on the user's side.
- CVE-2006-0733 stays a plain NVD row: there is no Citrix rule for it, and no Snort rule for it was found.

Tested: the matching against an independent count from the XML for six cases; creating a category before any
rules are loaded (message with hint, three NVD rows); the sync after loading rules (204 Citrix + 1 Snort added,
the too-complex and the Joomla Snort rule left out, NVD rows and the NVD date untouched, no duplicates); a repeat
sync (stable) and a shrinking Snort set (its CVE disappears, NVD rows stay); the build with the large category
checked against an independent computation of the expected rule ids; the objects page rendering the large
category. The earlier build scenarios (Citrix-only, Snort-only, only-too-complex, dead end, import failure) still
pass. Browser-level tests were not re-run (the sandbox was reset earlier and those servers were lost); no
template or JavaScript changed.

## Why a WordPress category got no Snort rules: too narrow a source, and no visibility into why

> **Note:** the long messages described in this section (and in the ones below) were shortened later; the details moved to the server log - see "Final cleanup" above.

**User report:** a WordPress category (15 CVEs) built a signature object with only 2 CVEs matched - both
already covered by Citrix - and nothing added from Snort, although the user was sure newer Snort rules exist.

**Cause 1 - the source was too narrow (my unverified assumption).** The tool loaded exactly one ET Open file,
`emerging-exploit.rules`, chosen earlier on the assumption that it holds the most CVE-referenced web-attack
rules; that was never checked, since the ET host blocks this assistant's fetch tool. The ET Open directory
listing shows the file that actually targets application-specific web attacks is
`emerging-web_specific_apps.rules` (about 5.4 MB, roughly four times the exploit file), next to
`emerging-web_server.rules` (about 0.5 MB) and `emerging-current_events.rules` (about 0.14 MB, recent
vulnerabilities). A WordPress plugin CVE will normally sit there, not in "exploit".

**Cause 2 - visibility.** The result said only "2 of 15", never why the other 13 got nothing. It could not
distinguish "Snort database empty", "no Snort rule for this CVE", and "rule exists but too complex".

**Changes.**
- `snort_rule_parser.DEFAULT_SNORT_RULES_URLS`: four files (web_specific_apps, web_server, exploit,
  current_events) instead of one. `web_client` is deliberately excluded - those rules describe attacks on
  browsers, not on a server behind a WAF. `fetch_and_parse_snort_rule_files()` loads each file on its own: one
  failing file (network error, renamed, empty) no longer blocks the rest, duplicate SIDs are kept once, and
  every file's outcome is returned.
- "Update rule database" (`/objects/signature-rules/refresh`): reports the per-file counts and gives
  honest funnel numbers - loaded, HTTP-relevant, with a CVE reference, simple enough to translate - plus any
  file that could not be loaded. If nothing at all loads, the existing Snort database is left untouched.
- "Create in NetScaler" message: for the CVEs without a Citrix rule it now says how many got a translated
  Snort rule, how many only have too-complex Snort rules (CVEs listed), and how many have no HTTP rule in the
  loaded rule set (with its size). If the Snort database is empty it says so and tells the user what to do; a
  dead-end rejection names the reason instead of a generic text.
- `uricontent` (the deprecated one-option form of `content` + `http_uri`) is now recognised as HTTP and as a
  URL match; before, an old-style rule using it under `proto tcp` would have been classed as non-HTTP.
- `find_gap_examples.py --category <name>`: lists every CVE of a category with its status (Citrix rule,
  translatable Snort rule, too-complex rule with the reason, Snort rule not recognised as HTTP, none at all).

**A detail that looked like a bug but is correct:** a category with 2 matched CVEs can report 3 activated
Citrix rules, because one CVE (CVE-2001-0253) maps to two Citrix rules (803 and 1607).

**Honest expectation.** More files will raise the number of CVEs that have a Snort rule at all, but the number
that gets *translated* is bounded by the translator's scope: sample ET rules in the search results chain
several `content` matches across different buffers, use `pcre`, `fast_pattern` or a `threshold`, which all
count as too complex. Widening coverage needs further native-format knowledge confirmed against hand-made
rules (more locations, and whether several patterns in one rule combine with AND), not more guessing. Also
note that ET ships many old or noisy rules commented out (`#alert ...`); the parser ignores commented lines,
so those are not considered.

**NOT VERIFIED:** the four file URLs were taken from the ET Open directory listing and earlier lookups but
were not fetched from this sandbox (no network, and robots.txt blocks crawlers); the first real "Update rule
database" on the user's side will show per-file results, including any file that is no longer there. "ET Open"
(Proofpoint's Suricata ruleset) is not the same as the Talos Snort rule sets; the latter was not used.

## Snort gap-filling now translates rules natively (NetScaler's own Snort import abandoned)

> **PARTLY SUPERSEDED**: the limits "exactly one content match" and "only HTTP_URL" described below were widened - see "Snort translator widened" above.

**Why the earlier approach was dropped.** Every attempt to let NetScaler convert Snort rules failed on
the user's appliance (14.1.60.57, all features licensed, so not a licensing issue), always at the
conversion step, never at the merge: "Problem converting snort rules to WAF signature file" with the V3
switch on, "cannot be transformed with the given XSLT file" with it off, and "Failed to convert third
party vendor rules" in `ns.log`. This held for the real Linksys rule, for the same rule with its
network variables replaced by `any`, and for a deliberately minimal one-line rule - and the GUI's own
"Add" import (which creates a new object, no merge involved) failed identically. So the fault is in
NetScaler's conversion on this appliance, not in our file content or our NITRO call; a separate-object
variant would have hit the same wall.

**New approach.** We translate simple Snort rules into NetScaler's *native* `<SignatureRule>` format
ourselves and add them to the very same XML file we already build from the Citrix source, so everything
goes through the one proven import (`import appfw signatures local:<file>`), with no second import and
no merge. The user supplied the missing ground truth: a complete exported signature file
(`testsig.xml`, 3057 rules, version 161) containing a rule they had created by hand in the GUI
(id 1000000, pattern `/test` at `HTTP_URL`), plus the Citrix-native rules around it.

**What the file taught us** (verified by parsing it): rules live in `<Signatures>`; each has a
`PatternList` with `RequestPatterns` > `Pattern` > `Location area=...` + `Match type=...`; locations seen
are `HTTP_URL`, `HTTP_FORM_FIELD`, `HTTP_METHOD`, `HTTP_RAW_URL`, `HTTP_HEADER`, `HTTP_COOKIE`,
`HTTP_POST_BODY`, `HTTP_RESP_BODY`, `HTTP_RESP_HEADER`, `HTTP_STATUS_CODE`; match types `LITERAL`/
`Literal` (both occur), `PCRE`, `Expression`, `Injection`, `CrossSiteScripting`; hand-made rules get ids
from 1000000 up; 3008 of 3057 rules mark a pattern `type="fastmatch"`. There is no attribute for
case-insensitivity on `Match`.

**Implementation.**
- `snort_rule_parser.py`: `_extract_content_matches()` now handles both Snort notations (location
  keyword before `content`, new Suricata style, and after it, classic style - the minimal test rule
  would otherwise have been misread as "no location"), records negation (`content:!"x"`), and
  `classify_for_native_translation()` decides translatability. A rule is translated only if it has
  exactly one `content` match, at the URL (`NATIVE_LOCATION_AREAS = {'URL': 'HTTP_URL'}` - the only
  location confirmed by a real hand-made rule), not negated, non-empty, no hex bytes (`|3b|`) or
  escapes in the text, and none of `endswith/startswith/fast_pattern/within/distance/depth/offset/pcre/
  byte_test/byte_jump`. Everything else is skipped with a stated reason. The real Linksys rule (four
  `content` matches over three locations plus several modifiers) is correctly *not* translatable.
- `signature_file_parser.py`: `build_native_signature_rule()` builds the element (attributes identical to
  the hand-made rule; `Pattern type="fastmatch"` and `Match type="LITERAL"` as in Citrix's own rules;
  child order PatternList, LogString, Reference..., Comment as in the most common native order; CVE as
  `cve,2013-3568` like the Citrix rules). `build_filtered_signature_xml(..., extra_rules=...)` appends them
  *after* the on/off loop (so they are not switched off again), with ids starting at
  `max(1000000, highest existing id + 1)`, sorted by SID so a rebuild gives the same ids. Verified
  against the user's file: it already contains id 1000000, the new rule correctly gets 1000001, no
  duplicate ids, and our own parser reads the generated rule and its CVE back.
- `app.py` (`build_signature_category`): for CVEs without a Citrix rule it looks up the Snort rules,
  re-parses them, and passes the translatable ones to the build; one upload, one import. The message
  names how many Snort rules were added for how many CVEs and lists up to five CVEs that were skipped
  as too complex. If neither source yields anything usable the build is rejected without any NITRO call
  (with a message that says when Snort rules existed but were all too complex). The count in the message
  now says "Citrix-Regeln", because "0 Regeln aktiviert" read like a failure in the Snort-only case.
- Removed as dead code: `nitro.merge_snort_signatures_from_file()`, `snort_rule_parser.build_gap_rules_file()`
  and `_resolve_rule_variables()`. The helper `find_gap_examples.py` now only lists CVEs whose Snort rule
  is actually translatable.

**Defaults:** `NATIVE_RULE_ACTIONS = 'block,log'` - added rules block and log, like Citrix's own rules
(`log` keeps blocked hits visible in `ns.log` and on the Logging page). This was first `'log'` only, as a
cautious default for third-party rules; changed to `block,log` at the user's explicit request. The caveat
stands: the rules come from ET Open and have not been checked against the user's own traffic, so they can
produce false positives that block legitimate requests - set the constant back to `'log'` for a
watch-first rollout. `NATIVE_RULE_CATEGORY = 'web-misc'`, the most common category in the file.

**NOT VERIFIED (only an import on the real appliance can settle these):**
1. Whether NetScaler accepts the generated rules on import. The structure follows the user's exported
   template, but it has never been imported.
2. Whether `Match type="LITERAL"` compares case-sensitively. Snort's `nocase` cannot be expressed, so a
   rule that relies on it may miss case variants (weaker detection, not a false-positive risk).
3. Whether Snort's `http_uri` (normalised URI, includes the query string) corresponds to `HTTP_URL` in
   NetScaler's matching exactly; `HTTP_RAW_URL` also exists.
4. Whether an all-`OFF` Citrix part plus only the added rules is accepted for a Snort-only category.

**Scope this deliberately gives up:** only single-pattern URL rules are translated. Most ET Open exploit
rules chain several matches or use modifiers, so a large share of gap CVEs will be reported as skipped.
Extending coverage means confirming further locations (header, cookie, post body) against hand-made
rules the same way the URL one was confirmed, rather than guessing them.

Tested: the classifier on 12 cases (both notations, negation, hex, escape, header/body locations, `within`,
pcre-only, no location, the real Linksys rule, Log4Shell with `nocase`); the generator against the user's
file (attributes and location identical to their rule, 3057 to 3058 rules, id collision avoided, round trip
through our parser, special characters `& < >` escaped, deterministic ids, unchanged behaviour without
extra rules); and the whole build route with the real file as the Citrix source in six scenarios -
Snort-only translatable, Citrix plus translated plus skipped, only-untranslatable (rejected, zero NITRO
calls), Citrix-only (message unchanged), true dead end, and an import failure reported as an error. The
Snort-only case sends exactly one upload and one import and contains no `vendortype`/`merge` field.
The browser regression suite from earlier sessions was not re-run: the sandbox was reset and those test
servers were lost, and this change touches only backend files (no templates, JavaScript or CSS).

## Merge step confirmed blocked by a known-fragile NetScaler API area, not our code

> **SUPERSEDED** by "Snort gap-filling now translates rules natively" above: the merge approach
> described below was abandoned and its code removed. Kept as history of how we got there.

**User's real error on the merge call:** "object already exists" - with `merge: true` already
set, meaning NetScaler is not honoring the merge intent at all and instead treating the
call as a fresh import against an already-used name.

**Found a highly relevant data point:** an open, unresolved GitHub issue on Citrix's own
official Terraform provider (`citrix/terraform-provider-citrixadc#1214`) reports the exact
same operation (`appfwsignatures` import with `merge`) failing, with a *different* NITRO
error (3197, "Importing the resource failed") but the same underlying action. This is
reasonably strong evidence that the `-merge` import path is a genuinely fragile area of
NetScaler's own API - not merely a wrong field name on our side, though the exact field
name/value still can't be fully ruled out either.

**User supplied the actual uploaded file** (`/var/tmp/<category>_snort.rules`, a real ET
Open rule for CVE-2013-3568 / Linksys) - confirmed, by re-parsing it with our own
`snort_rule_parser.py`, that the file we built and uploaded was correct (right SID, right
CVE, correctly flagged as HTTP-relevant). This rules out our own file-building/upload code
as the cause - the failure is specifically in the merge-import call itself, consistent with
the Terraform provider finding above.

**Independent, smaller finding from the same real rule:** it used Suricata's newer
dot-notation sticky buffers (`http.method`, `http.uri`, `http.request_body`) rather than the
older underscore style (`http_uri`) our `_HTTP_OPTION_KEYWORDS` list only covered. Didn't
cause a bug here (the rule's protocol was explicitly `http`, which alone already triggers
`is_http=True`), but was a real latent gap for a `tcp`-protocol rule using only the newer
dot-notation buffers - now fixed by adding the dot-notation equivalents alongside the
existing underscore ones. Re-verified the full existing parser test suite still passes
unchanged.

**Not yet resolved:** whether/how the merge step can be made to work reliably. Proposed to
the user two ways forward rather than continuing to guess blindly: (1) test the merge
manually via the NetScaler GUI's own "Merge with Existing Signature Object" checkbox
(Configuration > Security > NetScaler Web App Firewall > Signatures > Add) to establish
whether it even works reliably on their specific appliance/version, ideally while capturing
the real request via browser dev tools for a verified-correct payload; or (2) fall back to
creating Snort-sourced gap coverage as its own, separately-named signature object instead of
merging - simpler and avoids this fragile operation entirely, at the cost of a profile only
being able to use one or the other (Citrix-only or Snort-only) rather than combined
coverage in one object. Awaiting the user's choice before implementing either.

## Fixed bug: a category covered ONLY by Snort could never be built

**Found by the user**, testing the new feature with a real D-Link CVE confirmed (via
`find_gap_examples.py`) to be in the Snort database but not the Citrix one: building a
category containing only that one CVE failed immediately with "Keine der 1 CVEs dieser
Kategorie hat eine passende Regel... Kein NetScaler-Objekt erstellt" - the Snort merge step
never even ran.

**Root cause:** the existing early-exit guard (`if not rule_ids: return error`), which
pre-dates the Snort feature and made sense when Citrix was the only source, still ran
*before* the newly-added Snort gap-lookup. A category with zero Citrix-matched CVEs now
triggers that guard and returns immediately, regardless of whether Snort could cover it -
exactly the scenario this whole feature exists for.

**Fixed:** the Snort gap lookup (`gap_cve_ids` / `snort_matches` / `gap_rules_by_sid`) now
happens *before* the guard, and the guard only rejects when *neither* source has anything
(`not rule_ids and not gap_rules_by_sid`). The later part of the route reuses these same
values instead of recomputing them. When a category is Snort-only, `rule_ids` stays empty,
`build_filtered_signature_xml()` sets every rule in the uploaded Citrix-based file to
`enabled="OFF"`, that (otherwise-empty) object is still created and imported as before, and
the Snort merge step immediately afterward gives it its actual content. **Not previously
exercised, now newly relevant:** NetScaler accepting an import where every rule is
`enabled="OFF"` was never actually tested before this fix - the old guard always prevented
that file from ever being sent. Flagged as not independently verified, alongside the
existing Snort-merge-field-name caveat.

Tested directly against the reported scenario (a category with one CVE, zero Citrix
matches, one Snort match) - now returns success with the merge sentence instead of the
early-rejection message. Also re-verified the two surrounding cases still behave correctly:
an ordinary Citrix-covered category (unchanged, no superfluous Snort mention when nothing
needed merging) and a genuine dead end where *neither* source has anything (still correctly
rejected, with an updated message naming both sources). `app.py` still loads cleanly with
all 27 routes.

## Snort/ET-Open gap-filling for signature categories (no UI change)

> **PARTLY SUPERSEDED**: the "merge into the same object via `-VendorType Snort -merge`" part of this
> section no longer exists (see "Snort gap-filling now translates rules natively" above). The rule
> source (ET Open), the database tables, the parser and the one-object-per-category design still apply.

User-requested extension, building on a separate design conversation about using Snort
signatures: the NVD only provides CVE *metadata* (description, CVSS, affected CPEs), never
actual detection patterns - it was always meant as a filter/match layer, not a signature
source. The real gap is that Citrix's own signature file doesn't have a rule for every CVE
it could theoretically cover. This feature fills some of those gaps using a second,
independent rule source (Snort/Suricata rules), merged into the *same* signature object the
category build already creates - **no new button, no new step for the user**, exactly as
requested.

**Sandbox incident during this work:** partway through, the working container was reset
and all in-progress files were lost except the two most recently delivered
(`profile_parser.py`, `TECHNICAL_NOTES.md`). Resumed by having the user re-upload their own
current project (`WT.zip`) rather than reconstructing from memory/notes - their copy is the
authoritative one, since it's the one actually deployed and tested against their real
NetScaler. Verified it matched the expected latest state (NetScaler version field, removed
credit-card checkboxes, NITRO error surfacing, SQL Injection dropdown) before continuing.

**Confirmed via Citrix's own documentation** (docs.netscaler.com, "Snort rule integration"):
NetScaler can natively import Snort rules and convert them to WAF signatures itself -
`import appfw signatures <src> <name> -VendorType Snort` - no need to build Signature-XML by
hand for this path. A Citrix community-forum post flagged a real format/version risk though:
a user hit "cannot be transformed with the given XSLT file" importing plain-text Snort rules
on an older NetScaler build; newer builds (13+) reportedly handle the Suricata/Snort3 format
more natively. Flagged as **NOT VERIFIED** in the code - this can only really be confirmed
against the user's own appliance.

**Rule source:** ET Open (Emerging Threats/Proofpoint) - confirmed free, BSD-licensed, no
registration needed, direct download
(`https://rules.emergingthreats.net/open/suricata/rules/emerging-exploit.rules`, the
"exploit" category has the highest concentration of CVE-referenced web-attack rules; other
ET categories like "dns"/"malware" aren't relevant here). Deliberately NOT the free Snort.org
Community Rules - a community-forum post confirmed those lack coverage for CVEs as prominent
as Log4Shell (CVE-2021-44228), leaving ET Open as the better free option. `robots.txt` on
that domain blocks crawler tools (including this assistant's own `web_fetch`, which is why
the actual rule-file content couldn't be inspected directly here) but does not block a plain
HTTP client like Python's `requests` - which is exactly how ET's own download instructions
expect the file to be fetched (Suricata-Update, PulledPork, OinkMaster all work the same
way).

**One signature object, not two:** a profile can only reference one signature object at a
time (`appfwprofile.signatures` is a single value, not a list) - so gap-filling Snort rules
are **merged into the same object** the category build already creates (`-merge` on the
import command), never a second, separate object. This was the key design decision that
keeps the existing one-object-per-category-per-profile model intact.

**New files/additions:**
- **`snort_rule_parser.py`** (new): parses Suricata/Snort `.rules` text - `parse_rule_line()`
  extracts `sid`, `msg`, `cve_ids` (normalizes `reference:cve,2021-44228` to `CVE-2021-44228`,
  matching the format already used by `signature_db`/`nvd_client`), `classtype`, `rev`, and
  `is_http` (protocol is `http`, OR any HTTP sticky-buffer keyword like `http_uri`/
  `http_header`/... is present - older rules often use `tcp` + explicit HTTP options rather
  than `proto http`). Tokenizes options respecting quoted strings (a semicolon inside
  `msg:"..."` must not be treated as an option separator) rather than a naive
  `split(';')`. Malformed/unparseable lines are skipped, not fatal - large rule files
  (tens of thousands of lines) shouldn't fail entirely over one bad line.
  `fetch_and_parse_snort_rules()` mirrors the existing Citrix-file fetcher's error-handling
  shape. `build_gap_rules_file()` assembles just the selected gap rules' raw text into a
  `.rules` file ready for upload - no further transformation, NetScaler does the actual
  Snort→WAF conversion itself on import.
- **`signature_db.py`**: three new tables (`snort_rules`, `snort_rule_cves`,
  `snort_rules_meta`), mirroring the existing Citrix rule tables but kept fully separate
  (different source, different format). `replace_snort_rules()` (full replace, like the
  Citrix equivalent - the source file is itself the authoritative current state).
  `find_snort_rules_for_cves()` only returns rules already flagged `is_http` - the "only
  HTTP-relevant rules" filter from the requested pipeline is applied here, at the database
  level, not as an afterthought later. `schema.sql` updated and re-verified byte-for-byte
  identical to `init_db()`'s own output (13 objects now, was 9).
- **`nitro.py`**: new `merge_snort_signatures_from_file()`, deliberately a separate function
  from the existing `import_appfw_signature_from_file()` rather than extending it with
  parameters - keeps the already-working Citrix import path completely untouched. **NOT
  VERIFIED**: the exact NITRO JSON field names (`vendortype`: `"Snort"`, `merge`: `true`) are
  inferred from the CLI syntax (`-VendorType Snort -merge`), not confirmed against a real
  appliance - same caveat as the format risk above.
- **`app.py`**:
  - `/objects/signature-rules/refresh` ("Regel-Datenbank aktualisieren") now also fetches
    and stores the ET Open rules after the existing Citrix step succeeds - same click, same
    button, the response message reports both outcomes. If only the Snort part fails
    (network error, empty file), the Citrix part's success is NOT reverted - appended as a
    plain-text note in the same message instead.
  - `/objects/signature-categories/<id>/build` ("In NetScaler erstellen"): after the
    existing Citrix-based object creation succeeds (unchanged), computes which of the
    category's CVEs have *no* Citrix rule (`cve['rule_ids']` empty), looks those up against
    the Snort rule database, deduplicates by `sid` (one rule can cover several gap CVEs),
    and - only if any gap rules are found - uploads a small `<category>_snort.rules` file
    and merges it into the just-created object. Every sub-step failure (upload, merge) is
    appended to the success message rather than flipping the overall result to failure,
    since the primary (Citrix) object already exists at that point.

Tested entirely at the backend/route level (no template or JavaScript changes were needed
or made, matching the "no change to buttons or steps" requirement exactly): the parser
against 13 hand-built scenarios (a realistic Log4Shell-shaped rule, multi-CVE rules, the
tricky semicolon-inside-quotes case, non-HTTP rules, malformed lines, comments); the new
database functions (replace vs. accumulate, HTTP-only filtering, lookup by multiple CVEs);
the full `/objects/signature-rules/refresh` flow fetching both sources in one call,
including ET Open being unreachable while Citrix still succeeds; and the full
`/objects/signature-categories/<id>/build` flow end to end with a real CVE gap - confirming
the exact merge payload sent to NITRO, confirming the uploaded file contains the gap rule's
raw text, and confirming a merge failure is reported without downgrading the overall
(already-successful) result. `app.py` still loads cleanly with all 27 routes afterward.

## Fixed: Credit Card "types" checkboxes removed - the field never existed on NetScaler

**User's real NITRO error, now visible thanks to the previous fix:** "Invalid argument
[creditcardnumber] (NITRO 278)" - confirming the field name itself was wrong, not just a
value within it.

**Root cause, confirmed against Citrix's own documentation** (docs.netscaler.com, "Credit
card check" page): NetScaler's Credit Card check has **no concept of "which card brands to
detect"** at all - it recognizes common credit-card number patterns automatically; nothing
to select. `creditCardNumber` does exist as a NetScaler term, but only as a **binding**
parameter for exempting one specific, concrete card number (or regex) from detection on one
specific URL - `bind appfw profile <name> -creditCardNumber <number/regex> "<url>"` - not a
`set`/`add appfw profile` field, and not a list of card-brand tokens at all. The entire
premise of the earlier checkbox-list feature (six checkboxes for Visa/Amex/.../Mastercard)
was mistaken; no amount of guessing a different field name would have fixed it, since no
such field exists to guess.

**Fixed:** removed the checkbox-list entirely rather than trying another guess.
`DETAIL_FIELD_CHECKBOX_OPTIONS` and `CHECKBOX_FIELD_DEFAULTS` are now empty (kept as
infrastructure for a possible future genuine multi-select field, not deleted outright).
`'creditcard'` in `CHECK_EXTRA_FIELDS` now only lists `creditcardxout` (confirmed real,
since the user's own profile already had this exact field with this exact name). New
`DETAIL_FIELD_BLOCKLIST = {'creditcardnumber'}`: even though the field is no longer
registered as a checkbox-list, the existing prefix-matching logic would otherwise still
pick up a literal `creditcardnumber` key if some NetScaler version ever happened to report
one under the `appfwprofile` resource (unlikely given the docs, but not worth leaving to
chance) - the blocklist guarantees it's never shown as a (now meaningless, read-only) field
either. The Credit Card check now only shows its one genuinely configurable detail field,
X-Out.

If the user actually wants the *real* NetScaler feature this was confused with - exempting
one specific credit card number from detection on one specific URL - that would be a
different, binding-based relaxation feature (structurally similar to the existing SQL/XML
injection relaxation rules), not implemented here; would need to be requested and built
separately if wanted.

Both browser tests that exercised the removed checkbox-list feature were rewritten rather
than deleted outright: the now-invalid assertions (checkbox presence, selecting/saving card
types) were replaced with assertions that the Credit Card section shows only X-Out and no
checkbox-list, while the still-valid parts of those same tests (the Command Injection and
SQL Injection dropdowns, tested in the same files) were kept unchanged. Full regression
suite re-run afterward, 391 checks, all passing.

## Real NITRO error text now surfaced for every profile update (was previously swallowed)

**User report:** saving the new Credit Card checkboxes failed with only this app's own
generic fallback text ("Fehler beim Aktualisieren der Einstellungen... Details ggf. im
NetScaler-Log") - not NetScaler's actual error. Also asked, reasonably, why nothing showed
up in `ns.log` (answered separately: `ns.log` records WAF traffic hits, not configuration
API calls - the right place to look is the message the app itself shows, which is why
fixing this gap mattered).

**Root cause:** `nitro.update_appfw_profile()` - the single function behind every profile
write in this app (the four action checkboxes, all check-detail fields including the new
dropdowns/checkboxes, buffer-overflow relaxation, signature assignment, profile creation) -
only ever returned a bare `True`/`False`, via the generic `nitro_request()` helper which
logs the real NITRO error server-side but never returns it to the caller. Every one of its
7 call sites in `app.py` could therefore only ever show its own generic, pre-written
message, never NetScaler's actual reason - a real gap given how many new, partially
unverified dropdowns/checkboxes were just added upstream of it.

**Fixed:** `update_appfw_profile()` now builds its own request (like most other write
functions in `nitro.py` already do) and returns `(True, None)` or `(False, error_text)`,
using the existing `_extract_nitro_error()` helper - the same pattern already used
throughout the rest of this file. All 7 call sites in `app.py` updated to unpack the tuple
and include the real error text in their message to the user.

**Second, independent bug found while testing this fix:** `_extract_nitro_error()` itself
crashed (`AttributeError`, uncaught) when a response's JSON body was `None` or anything
other than a dict (e.g. a bare HTTP 500 with no response body at all) - `body.get(...)` on
a non-dict raises `AttributeError`, not the `ValueError` the function was only catching.
This surfaced immediately once `update_appfw_profile` started routing through this helper:
the test mock simulating a NetScaler 500-with-no-body response caused an unhandled
exception deep in Flask instead of a clean JSON error response, hanging a test that waited
for the (never-arriving) "teilweise konfiguriert" message. Fixed by checking
`isinstance(body, dict)` before calling `.get()`, falling back to the HTTP status as before
for any non-dict or missing body - this could plausibly have affected a REAL NetScaler
error response too (not just the test mock), so this is a genuine robustness fix, not just
a test artifact.

Tested directly against the exact reported scenario (a simulated NITRO error on saving
credit-card types) - the real NITRO message and error code now appear in full in the
response. All 7 call sites individually re-tested with a simulated failure, confirming each
surfaces the real error text instead of its old generic wording. Full regression suite
re-run afterward; one pre-existing browser test (profile creation's "partial success" path)
started timing out once routed through the fixed `_extract_nitro_error`, which traced
directly to the second bug above rather than a regression from the main fix - fixed
together, confirmed with 405 checks passing; route/decorator sanity check re-run again (26
routes, no orphaned definitions).

## Fixed bugs found by the user: SQL Injection dropdown missing, Credit Card checkboxes invisible

**SQL Injection Type was still a plain text field.** The user had only explicitly asked for
the XML/JSON SQL and CMD injection "type" fields to become dropdowns; the base SQL Injection
check's `sqlinjectiontype` was left as-is at the time. Added the same dropdown (same five
SQL values) to `DETAIL_FIELD_OPTIONS` for consistency, once the user pointed out the gap.

**Real bug: the Credit Card checkbox-list never appeared on the user's actual NetScaler.**
Root cause found in `structure_profile_checks()`'s existing filtering logic (pre-dating
this feature): any detail field whose value is "empty" (`None`, `''`, `[]`, or `{}`) gets
silently excluded from `detail_fields` entirely - a reasonable rule for ordinary read-only
display fields (no point showing an empty field), but wrong for the new editable
checkbox-list field: "no card types currently selected" (an empty list) is a completely
normal, valid state for an unconfigured or just-created Credit Card check, and the user
needs to see empty checkboxes to be ABLE to select types in the first place - instead the
entire field, and therefore the whole multi-select UI, silently vanished. Likely the exact
state of the user's own profile (Credit Card check present, but no types chosen yet yet).

Fixed in two layers, since a real NetScaler response's exact shape when a list field is
unconfigured wasn't known with certainty (could be an empty list, or the key could be
missing from the response entirely):
1. Both the prefix-match loop and the `CHECK_EXTRA_FIELDS` loop now special-case any field
   registered in `DETAIL_FIELD_CHECKBOX_OPTIONS`: such a field is kept even when its value
   is empty, as long as the key is present in the raw profile at all.
2. New `CHECKBOX_FIELD_DEFAULTS` dict (currently just `{'creditcardnumber': []}`): if the
   key is missing from the raw profile entirely (not just empty), the field is still added
   with this default value, so the checkbox list renders with nothing pre-checked rather
   than not rendering at all. `'creditcard'` was also added to `CHECK_EXTRA_FIELDS`
   (`['creditcardnumber', 'creditcardxout']`) so this check is covered by both fallback
   paths, not just prefix-matching.

Ordinary non-checkbox-list fields are deliberately unaffected by this change - an empty
`sqlinjectiontype` (for example) still correctly stays hidden, to avoid suddenly surfacing
a large number of previously-hidden empty fields across every other check as an unintended
side effect of this fix.

Tested by adding a second mock profile with `creditcardaction` set but `creditcardnumber`
entirely absent (reproducing the exact reported scenario) - confirms the checkbox list now
renders with nothing checked, and that selecting a type and saving from this empty starting
state works correctly end to end. Also re-tested the three existing scenarios (empty list
present, field entirely absent, field with real values) directly against
`structure_profile_checks()`, plus a regression check that an ordinary empty text field
(`sqlinjectiontype=''`) is still correctly hidden as before.

While adding the second mock profile, several *other* existing browser tests broke because
they located "the first profile on the page" positionally and now found two - fixed by
appending the new mock profile at the end of the list (preserving index 0 for the existing
one) and scoping a couple of ambiguous `.profile-subheading` locators with `.first()`. Full
regression suite re-run afterward, 405 checks, all passing.

## More check-detail labels, three new dropdowns, and the first multi-select (checkbox-list) field

User-supplied list of the remaining unreadable field names (from directly inspecting the
detail rows), plus three concrete UI upgrade requests: turn a free-text field into a
dropdown, and turn a list-valued field (credit card types) into checkboxes.

**Straightforward label additions** (no new value guessing needed):
`bufferoverflowmaxquerylength` → "Maximum Query Length", `bufferoverflowmaxtotalheaderlength`
→ "Maximum Total Header Length", `cmdinjectiongrammar`/`jsoncmdinjectiongrammar` → "Check
using CMD Grammar", `jsonsqlinjectiongrammar` → "Check using SQL Grammar",
`jsoncmdinjectiontype`/`jsonsqlinjectiontype`/`xmlsqlinjectiontype` → "Check Request
Containing", `xmlsqlinjectionchecksqlwildchars` → "Check for SQL Wildcard Characters",
`creditcardxout` → "X-Out", `fieldformatmaxlength`/`fieldformatminlength` → "Maximum/Minimum
Length", `postbodylimit` → "Post Body Limit (Bytes)". Also renamed `sqlinjectionparsecomments`
from the earlier, less accurate "Parse Comments" to "SQL Comments Handling" (reused for the
new `xmlsqlinjectionparsecomments` too), and fixed a small pre-existing inconsistency:
`CHECK_LABELS['creditcard']` was still the one German entry ("Kreditkarten-Schutz") among
otherwise all-English check names - now "Credit Card".

**New dropdowns, values NOT independently verified against a real appliance:**
`cmdinjectiontype`/`jsoncmdinjectiontype` (None / CMD Special Character / CMD Keyword / CMD
Special Character Or Keyword / CMD Special Character And Keyword) and
`jsonsqlinjectiontype`/`xmlsqlinjectiontype` (the SQL equivalents) use the `CMDSplChar`/
`SQLSplChar`/…`ANDKeyword`/…`ORKeyword` token family already referenced elsewhere in this
project's SQL/CMD-injection relaxation dialogs (for the base SQL/CMD injection type itself,
left as a plain text field - not part of this request), with "None"/"CMDKeyword"/"SQLKeyword"
added by inference since they weren't previously used anywhere in this codebase.
`sqlinjectionparsecomments`/`xmlsqlinjectionparsecomments` (Check All Comments / ANSI/Nested
/ ANSI / Nested) use values derived from the Citrix CLI reference for
`-SQLInjectionParseComments` (`checkall`/`ansinested`/`ansi`/`nested`) - also not
independently confirmed here. Both flagged prominently in code comments; the user offered to
check their own NetScaler if unsure, this is the concrete ask for that.

**New checkbox-list field type** (`profile_parser.DETAIL_FIELD_CHECKBOX_OPTIONS`,
`_build_detail_entry()`): the first check-detail field that holds a LIST of selected values
rather than a single scalar. `creditcardnumber` gets six checkboxes (American Express /
Diners Club / Discover / JCB / Master Card / Visa) - token values (`amex`, `dinersclub`,
`discover`, `jcb`, `mastercard`, `visa`) are guessed from NetScaler's usual lowercase-
concatenated naming convention, **not verified**, same caveat as above. `_build_detail_entry`
normalizes the raw NITRO value defensively (accepts a real list, a space-separated string,
or nothing) so a differently-shaped response from a real appliance won't crash the page,
just show nothing pre-checked.

This required a new dirty-tracking/save/discard path throughout the stack, since a checkbox
group doesn't fit the existing single-value pattern:
- `templates/partials/_profile_checks.html`: new `checkbox-list` branch rendering one
  `<label><input type="checkbox">…</label>` per option, with the group's original selection
  stored as a JSON array on the wrapping `<span data-original='[...]'>` (an individual
  checkbox's own `.value` is always its fixed option token, never the "original" state).
- `static/js/profile_checks.js`: `checkDetailsIsDirty()`/`cancelCheckDetails()`/
  `saveCheckDetails()` now branch on `input.type === 'checkbox'`, comparing/collecting the
  whole checked-set per `data-field` (via new `getCheckboxListOriginal()`/
  `getCheckboxListCurrent()`/`sameStringSet()` helpers) instead of a single `.value`. After a
  successful save, the new selection becomes the new "original" (stored back onto the
  container's `data-original`), so a subsequent Discard reverts to the just-saved state, not
  the page-load state.
- `app.py` (`profile_check_details`) and `nitro.update_appfw_profile` needed no change to
  the NITRO call itself - a Python list already serializes correctly as a JSON array in the
  PUT body (confirmed by how the existing four-checkbox action fields, e.g.
  `sqlinjectionaction`, already send lists) - only the route's "stringify everything" step
  was adjusted to pass lists through unchanged instead of turning them into a string
  representation of the list.

Tested end to end in the browser: unchecking/checking credit-card types, Discard correctly
reverting to the pre-edit selection, Save sending the exact expected JSON array, and -
important edge case - Discard *after* a successful Save correctly reverting to the
newly-saved state rather than the original page-load state. The Command Injection Type
dropdown was verified to show all five options with the right labels. Full regression suite
re-run afterward, 395 checks, all passing; route/decorator sanity check re-run again (26
routes, no orphaned definitions).

## NetScaler version in the sidebar, further Configuration-page translations, readable check-detail labels

Three combined requests in one step.

**NetScaler version display:** confirmed via a real NITRO example (Ansible collection
debug log) that `GET nsversion` returns a `version` string like `"NetScaler NS13.1: Build
49.13.nc, Date: ..."`. `nitro.get_ns_version()` (new) extracts release and build via regex
and joins them as `"<release>.<build>"`, e.g. `"14.1.60.73"` - exactly the format the user
asked for. Fetched once at login (not on every page load, to avoid an extra NITRO round
trip on every navigation) and stored in `session['ns_version']`, exposed to every template
via the existing `t`/`locale` context processor. Shown in the sidebar between "Logged in
as" and the logout button, hidden entirely if the appliance doesn't return a parseable
version (no broken layout). Tested with the real example string, the user's own example
format, a variant without the ".nc" build suffix, and all failure paths (missing field,
unparseable text, NITRO error) - all return `None` instead of crashing.

**Configuration page: remaining static text translated.** All four section headings, the
page-level intro paragraph, every section's intro paragraph, the rule-database status line
and "Update rule database" button, all category/signature/profile card labels ("Show
details", "Create in NetScaler", "Delete", "Signature: X", "Pending: X"), the empty-state
messages, and a few small leftover strings in `_vserver_row.html` ("Backend", "no backend
bound", "no policy", "No AppFW policy bound to this vServer.") are now translated in all 4
languages. The three JavaScript-generated freshness texts
(`checkSignatureFreshness()`) are translated too, via the same embedded-JSON pattern used
on the Logging page (`#configuration-i18n-data`) plus a small `formatI18n()` helper for
`{placeholder}` substitution matching the Python-side `translate()` convention. **Still NOT
translated:** the dynamic dialog content in `objects.js` (create/assign/delete/build
confirmation dialogs) - same reasoning as before, these are a much larger, separate
undertaking tied to dynamic, value-interpolating JS, not simple template text.

**Readable labels for check-detail fields on the Dashboard:** `profile_parser.py` gained
`DETAIL_FIELD_LABELS`, a dictionary mapping raw NITRO field names (e.g.
`cookieencryption`, `defaultfieldformatmaxoccurrences`) to their NetScaler-GUI-style
display names (e.g. "Encrypt Server Cookies", "Max Field Occurrences"). Deliberately kept
in English regardless of the tool's language - same reasoning as "Learning"/"Block"/
"Security Checks": these are NetScaler's own configuration terms, an administrator should
recognize them independent of UI language. Covers the fields already used elsewhere in
this project (`CHECK_EXTRA_FIELDS`) plus other fields of the same checks known from the
Citrix CLI reference (SQL Injection Type, Buffer Overflow thresholds, XSS transform flags,
Credit Card settings, ...). A field not in the dictionary still displays (falls back to
its raw NITRO name, shown additionally as a hover tooltip on the label) rather than
crashing - built by Claude alone, without needing the user to enumerate every field, as
asked; coverage is necessarily incomplete for rarely-used fields, extendable by adding
entries to the dictionary.

Old tests that asserted literal German text (`"kein Backend gebunden"`, `"Signatur:
lab_waf_sig"`, `"noch nicht geladen"`, etc.) needed updating to their English equivalents -
expected fallout of translation work, not a regression, same pattern as earlier
Dashboard/Logging translation steps. Full regression suite re-run afterward, 376 checks,
all passing; route/decorator sanity check re-run again too (26 routes, no orphaned
definitions).

## Signature rule database now always uses the current Citrix version (mapping file)

**User question that prompted this:** the "Update rule database" button only ever loaded
one hard-coded file (`sig-r14.1b0v183s8.xml`), with no way to pick up newer Citrix
signature releases without a code change. The user offered to supply multiple links
manually so the tool could keep checking for new signatures.

**Better solution found instead of manual links:** Citrix itself publishes a mapping file,
`https://s3.amazonaws.com/NSAppFwSignatures/SignaturesMapping.xml` - the exact same file
NetScaler's own built-in auto-update feature uses (`set appfw settings SignatureUrl ...`).
Fetched and verified for real: it lists every currently available release/build/schema
combination with its own signature-file path, e.g.:

```xml
<AppfwSignatures date="2026/09/15 15:27:13">
  <Signature release="15.1" build="0" version="183" schema_version="8">
    <sig_file><file>sigs/sig-r15.1b0v183s8.xml</file>...</sig_file>
  </Signature>
  <Signature release="14.1" build="0" version="183" schema_version="8">...</Signature>
  ...
</AppfwSignatures>
```

This removes the need for the user to ever supply a link manually again - the tool now
resolves the current file itself, automatically, on every click.

- **`signature_file_parser.fetch_signature_mapping()`** (new): downloads and parses this
  mapping file into a list of `{release, build, version, schema_version, file_url}`
  entries, sorted with the newest first (highest `version`, ties broken by highest
  `schema_version`). Tested against the file's real, current content.
- **Route `/objects/signature-rules/available`** (new, GET): returns this list plus the
  mapping file's own `date` attribute, for populating a selection dropdown.
- **Route `/objects/signature-rules/refresh`** (changed): now resolves the file to load in
  this order - (1) an explicit `url` in the request body (kept for advanced/manual
  override), (2) an explicit `release`+`build`+`schema_version` (a specific entry chosen
  from the dropdown), (3) with nothing supplied, automatically the mapping file's newest
  entry - "always use the latest file", exactly as requested, with zero manual maintenance
  going forward: new Citrix releases simply appear the next time the mapping file is
  fetched.
- **UI:** a new dropdown next to "Update rule database", defaulting to "Latest version
  (automatic)", populated from `/objects/signature-rules/available` on page load. Choosing
  a specific release lets the user match their own appliance's schema version exactly if
  the automatic pick isn't right for them (relevant for the later NetScaler upload step,
  where the uploaded file's schema needs to be one the target appliance understands).

Tested with the real mapping file content as a fixture: correct sort order, automatic
"newest" selection, an explicit older-release selection actually loading a different file,
a request for a release no longer listed (clear error, no crash), and the previous plain
`url` override still working unchanged. Full regression suite re-run afterward, 351 checks,
all passing.

## Signature rule database: dropdown removed again, automatic freshness check instead

Follow-up to the mapping-file change above, on user feedback: the manual release dropdown
was removed again - "always take the newest version" is now the only behavior, no
selection needed. Instead, the Configuration page now automatically checks on every load
whether a newer signature version is available than the one currently loaded, and makes
that clearly visible.

- **`templates/objects.html`:** the `<select>` is gone; the rules-db bar now carries
  `data-loaded-version="{{ signature_rules_meta.file_version }}"` (empty if nothing has
  been loaded yet) plus a new `<span id="rules-db-freshness">`, filled in by JavaScript.
- **`static/js/objects.js`, `checkSignatureFreshness()`** (new): on page load, fetches
  `/objects/signature-rules/available` (unchanged, already returns entries sorted newest
  first) and compares its newest `version` against the page's `data-loaded-version`. Three
  states: nothing loaded yet (neutral note naming the available version), up to date
  (green "✓ Signatur aktuell"), outdated (visually prominent orange badge naming both
  version numbers and prompting "bitte Regel-Datenbank aktualisieren"). A failed check
  (e.g. no network) fails silently - the status line simply keeps whatever the server
  rendered, no broken UI.
- **`refreshSignatureRuleDatabase()`** always POSTs `{}` now (no more release selection) -
  the backend route already defaulted to "automatically load the newest mapping entry"
  when nothing was specified, so no backend change was needed for this part.
- **Route `/objects/signature-rules/refresh`** now also returns `file_version` in its JSON
  response, so the frontend can update `data-loaded-version` immediately after a successful
  refresh without a full page reload - otherwise the freshness check would keep comparing
  against the pre-refresh version until the next visit.
- The explicit `release`/`build`/`schema_version` selection mechanism in the backend route
  itself was intentionally left in place (unused by the UI now, but harmless) in case a
  future need for manual version pinning comes up again.

Tested in the browser for all three states (never loaded, up to date, outdated - the
outdated case via a realistic page load with an intercepted, lowered
`data-loaded-version`, not just a client-side variable poke) plus screenshots of the
up-to-date and outdated states. Full regression suite re-run afterward, 356 checks, all
passing; the route/decorator sanity check from the previous incident was run again too
(26 routes, no orphaned function definitions).

## Fixed bug: drop highlight flickered / only appeared to work near the edge

**Cause:** in HTML5 drag-and-drop, `dragenter`/`dragleave` also fire when moving onto a
child element INSIDE the drop target (text, badge, chip), not only when actually leaving
the element - a well-known pitfall with native drag-and-drop. Without a countermeasure, the
`.drop-target` class was briefly removed and immediately reapplied on every mouse movement
over a child element; the highlight thus only stayed visibly stable where no child element
was under the cursor - usually a thin strip near the edge of the card/row.

**Fixed** in `static/js/objects.js` (vServer rows and profile cards as drop targets):
`dragleave` now only removes the highlight when `event.relatedTarget` is NO LONGER inside
the element (`!element.contains(event.relatedTarget)`) - the standard fix for this
behavior. Tested with a simulated mouse movement across several child elements (name,
badge, address, policy count): the highlight now stays consistent across the entire area
and only disappears when actually leaving.

## Signatures as their own drag-and-drop object

**Underlying problem, fixed after feedback with a real Postman response:** `GET
appfwsignatures` without a name does NOT return a list of individual objects on NetScaler
(unlike appfwpolicy/appfwprofile/lbvserver/...), but a SINGLE object with a `response`
field in the free-text format of the CLI output `show appfw signatures`, e.g.:

```
1)\tUrl: default_signatures.xml\tName: "*Default Signatures"
\tCreation Date: ...
2)\tUrl: _clone_...\tName: "lab_waf_sig"
\t...
```

`nitro._parse_signature_objects_report()` splits this via regex into individual objects
(`name`, `url`, `is_default`). Built-in signature sets shipped by Citrix are recognizable by
a leading `"*"` in the name (e.g. `"*Default Signatures"`, `"*Xpath Injection Patterns"`)
and, like the default profiles, are NOT shown as their own card - only custom/imported
signature objects (e.g. `"lab_waf_sig"`).

**New section "Signatures"** on the Objects page (above "WAF Profiles"), with the same
cards as profiles, but visually set apart (`.signature-card`, purple border instead of the
blue add card). Every card is draggable; the **target is a profile card**, not a vServer -
a signature belongs to a profile, not directly to a vServer (the NetScaler object hierarchy
is signature → profile → policy → vServer). Dropping a signature onto a profile opens a
confirmation dialog, and on confirmation a single NITRO call: `set appfw profile <profile>
-signatures <signature>` (route `/objects/assign-signature`). This replaces a previously
assigned signature rather than adding to it (a profile has only one signature assignment).
The profile card then shows "Signature: \<name\>" as a subtitle.

**Distinguishing profile vs. signature drag:** since profile cards are both a drag source
(→ vServer) and now a drop target (← signature), an `application/x-object-kind` marker
(`"profile"` or `"signature"`) is set on the DataTransfer in addition to the name when
dragging. vServer rows only accept `"profile"`, profile cards only `"signature"` - wrong
combinations (e.g. a signature onto a vServer) are silently ignored on drop.

**Bug found and fixed along the way (not the original Postman error, but newly found while
testing this function):** `attachProfileCardDragHandlers()` / `attachProfileCardDropHandlers()`
searched the ENTIRE document on every call instead of only newly inserted cards. After
every live refresh of the profile cards (`refreshProfileCards()`, e.g. after creating a new
profile), this caused additional, duplicate listeners to accumulate even on already
existing, unchanged elements such as the signature cards - the most recently registered
(incorrect) listener overwrote the DataTransfer kind marker of the signature card, so that
it was incorrectly recognized as "profile" after the first profile refresh. Fixed by having
the attach functions now accept an optional `root` parameter, and `refreshProfileCards()`
now only re-wires the freshly inserted area instead of re-searching the whole document.

Tested with the exact report the user supplied via Postman (three entries, two built-in +
`lab_waf_sig`), including the complete drag flow signature → profile → vServer across
several consecutive actions (exactly where the listener bug occurred). **Not** tested
against a real appliance.

## Known, fixed bug: "internal server error" with exactly one binding

**Affected:** the Objects page (500 error) and potentially the vServer display of a policy
in the Dashboard (incorrect/missing display, possibly also a 500 depending on NITRO
version).

**Cause:** NITRO returns, for binding endpoints queried by name (e.g.
`lbvserver_service_binding/<name>`), a single object instead of an array with one element
when there is EXACTLY ONE match - a documented, often-overlooked NITRO quirk. In this case
the code iterated over the dict keys (strings) instead of the binding object itself and
crashed with `AttributeError: 'str' object has no attribute 'get'`.

**Update, after feedback with a real server log:** the error did in fact occur - but at a
spot that hadn't initially been protected: `get_appfw_signature_objects`
(`appfwsignatures`), with exactly ONE signature object on the appliance. This disproves the
original assumption that only BINDINGS queried by name were affected - NetScaler clearly
collapses ANY list response into a single object as soon as there's exactly one match, even
for a normal listing without a name in the path. Because of this, `_as_list()` was applied
consistently to ALL list returns in `nitro.py`, not just the originally suspected ones:
`get_waf_policies`, `get_waf_profiles`, `get_lb_vservers`, `get_cs_vservers`,
`get_services`, `get_servicegroups`, `get_appfw_signature_objects`, `get_policy_stats`
as well as the previously-fixed `get_lbvserver_service_bindings`,
`get_lbvserver_servicegroup_bindings`, `get_csvserver_lbvserver_binding`,
`get_vserver_appfwpolicy_bindings` and `get_policy_vserver_bindings`. (`get_appfw_profile`
and `get_system_file` already handled the singleton case correctly and didn't need
changes.)

Tested with a simulated setup matching exactly the reported error (exactly one signature
object on the appliance) as well as individually reproduced and tested for all the other
named functions - still **not** against the actual appliance, since I don't have access to
one.

## Objects page: vServer, services, policy bindings (basis for rule creation)

New, dedicated page (`/objects`, nav entry "Objekte"), **currently read-only**: first step
toward object-based rule creation (select vServer → create bound policy → choose profile) -
this write part has NOT been implemented yet.

- **`objects_parser.py`** (new, analogous to `profile_parser.py`, but for the relationships
  BETWEEN objects instead of the structure of a single profile): `structure_vserver()`
  builds an enriched vServer object from the raw NITRO objects, with backends
  (service/service group) and bound AppFW policies (incl. resolved rule and profile link),
  sorted by priority.
- **NITRO calls** (`nitro.py`): `get_lb_vservers`, `get_cs_vservers`, `get_services`,
  `get_servicegroups`, `get_lbvserver_service_bindings`,
  `get_lbvserver_servicegroup_bindings`, `get_csvserver_lbvserver_binding`,
  `get_vserver_appfwpolicy_bindings`. One NITRO call per vServer for its bindings -
  analogous to the already existing pattern in `build_enriched_policies()` (there: one call
  per policy). With many vServers, correspondingly many requests; uncritical for the
  current read-only page, may need to be batched for future extensions.
- **Display** (`templates/objects.html`, `_vserver_row.html`, `static/css/objects.css`):
  deliberately kept in the existing style - the same classes as for policies/profiles on
  the Dashboard (`status-dot`, `chip`, `detail-row`, `profile-link`, `toggleDetails()`/
  `toggleSection()`). A profile link from the policy list jumps to the Dashboard as usual
  via `?jump_profile=<name>`.
- **If a referenced profile is missing** (a policy points to an `appfwprofile` that no
  longer exists), that's marked in red as "(not found)" instead of a dead link.
- **ASSUMPTION, not tested against a real appliance:** GSLB, VPN and other vServer types
  are not read (only `lbvserver`/`csvserver`, since uncommon for AppFW bindings); for a CS
  vServer, only the *default* LB target binding is read, not content-switching policies
  with multiple targets.

### Custom profiles only + "+ Add" card: creating and configuring a new profile

The WAF-profile cards now only show **custom profiles** - default profiles (from
`DEFAULT_PROFILE_NAMES`, the same constant as on the Dashboard) are not shown as a card.
Important for correctness: internally, resolving "does the profile referenced by a policy
exist?" (in `_build_vserver_objects`) still uses the COMPLETE, unfiltered profile list -
otherwise a policy on a default profile would be incorrectly marked as "not found".

At the end of the card row is a color-highlighted **"+ Add" card**, same size as the
profile cards (same CSS grid), but not draggable. Clicking it opens the "Create new
profile" dialog (`openCreateProfileDialog()` in `objects.js`):

- **Name** (required), **Defaults** (Basic/Advanced/Core/CVE), **Type** (optional:
  HTML/XML/HTML+XML/don't set), **Comment** (optional), **Signature** (optional, dropdown
  of existing `appfwsignatures` objects, loaded via `GET appfwsignatures`).
- **Security-check actions (Learning/Block/Log/Stat) are deliberately NOT configured
  here** - the editable checkboxes on the Dashboard page already exist for that; the new
  profile lands there with the default values dictated by "Defaults" and can be further
  adjusted there.

Route `/objects/create-profile`, up to three sequential NITRO write calls:
1. `add appfw profile <name> -defaults <defaults>` (required) - `nitro.add_appfw_profile`
2. `set appfw profile <name> -type <type>` (only if given)
3. `set appfw profile <name> -signatures <name>` (only if given; the chosen signature
   object must still exist at the time of submission, checked server-side)

**Per Citrix docs, "Defaults" and "Type" cannot be set in the same call**
("add appfw profile" with `-defaults`, then separately "set appfw profile" for `-type`) -
hence the two separate steps instead of one combined call. If step 2 or 3 fails, the
profile created in step 1 remains; the message transparently lists what was done and what
wasn't ("partially configured - done: ...; failed: ..."), analogous to the existing pattern
for policy+binding.

On success, only the profile-card area (`#content-waf-profiles`) is reloaded and replaced
via a background fetch of `/objects` (`refreshProfileCards()`), including newly registered
drag handlers for the new card - the vServer area is untouched.

**ASSUMPTION, not verified against a real appliance:** the NITRO field for the signature
assignment is `signatures` (plural) - taken from the NITRO Python docs, not from an
official field reference. If step 3 fails with an error on exactly this field, change the
field name to `signature` (singular) in `app.py`/`objects_create_profile`.

### Drag & drop: dragging a WAF profile onto a vServer → create and bind a new policy

The write part is now implemented. Above the vServer list, a "WAF Profiles" area appears
with all appfwprofile objects as draggable cards (`draggable="true"`,
`static/js/objects.js`). When a card is dropped onto a vServer row (the drop target gets a
dashed highlight), a dialog opens in the familiar style (`sql-dialog-*` classes from
`analysis.css`, additionally included in `objects.html` for this):

- **Policy name:** pre-filled with `pol-<profile>-<vserver>`, editable.
- **Rule type:** "Hostname contains" / "URL path contains" (build the classic expression
  `HTTP.REQ.HOSTNAME.CONTAINS("...")` or `HTTP.REQ.URL.CONTAINS("...")`) or "Free
  expression". The expression field is auto-filled from type+value, **unless** the user has
  edited it by hand - after that, their input is left untouched even if type/value still
  change.
- **Priority:** suggestion = highest priority already assigned on this vServer + 10 (read
  from the already-rendered detail markup, no extra request), otherwise 100.

On submit (route `/objects/bind-profile`, two NITRO write calls):
1. `add appfw policy <name> <rule> <profilename>` (`nitro.add_appfw_policy`)
2. Bind to the vServer (`nitro.add_vserver_appfwpolicy_binding`, depending on type either
   `lbvserver_appfwpolicy_binding` or `csvserver_appfwpolicy_binding`)

**If step 2 fails, the policy created in step 1 remains on the NetScaler** (independently
existing, not bound) - the error message in the dialog makes this explicit ("was created,
but the binding ... failed"), so nothing is hidden. On success, only the affected vServer
row is reloaded and replaced via a background fetch of `/objects` (`refreshVserverRow()`,
DOMParser) - no full page reload, other expanded rows remain unchanged.

**Validation:** the profile must still exist on the NetScaler at the time of submission
(checked server-side, against TOCTOU gaps between page load and drop), policy/vServer names
against a character whitelist pattern, priority must be a positive number.

**ASSUMPTION, not verified against a real appliance:** the binding is sent without
`"type": "REQUEST"`. Real CLI examples for AppFW policy bindings to LB vServers didn't
include `-type` (unlike Responder/Rewrite bindings, where request/response must be
explicitly distinguished); AppFW covers both via the profile. If the binding fails with an
error on exactly this field, add `"type": "REQUEST"` to the binding body in
`nitro.add_vserver_appfwpolicy_binding`.

**Real error encountered and fixed:** `add_vserver_appfwpolicy_binding` initially sent a
test `"comment"` field in the binding body (analogous to the appfwprofile_*_binding
objects like SQL/CMD/DenyURL/CSRF, which accept comment). Unlike those,
`lbvserver_appfwpolicy_binding` / `csvserver_appfwpolicy_binding` rejects the field -
NITRO error 278 "Invalid argument [comment]". The policy itself (appfwpolicy) was created
correctly WITH a comment; only the second step (the binding) failed, which the app already
correctly reported as a partial success ("was created, but the binding ... failed").
Fixed by having `add_vserver_appfwpolicy_binding` no longer accept or send any `comment`
field at all - the policy already carries the explanatory comment.

Next possible step (not yet implemented): CVE/signature matching (see chat history).

## Toolbar: "Fetch now" and "Clear list"

Two buttons in the Analysis toolbar, purely client-side in `static/js/analysis.js`:

- **Fetch now** (`#fetch-now-btn`): immediately triggers an `/analysis/data` request (the
  same function `refreshLog()` used for automatic polling) and restarts the poll timer so
  that no second, automatic fetch follows right after. Disabled while loading.
- **Clear list** (`#clear-list-btn`): clears only the DISPLAY (`#log-container` is replaced
  by a hint text) - triggers no request and changes nothing about `ns.log` or the
  NetScaler. If polling continues, the next automatic fetch replaces the hint text with the
  current entries again; this is intentional ("clear" means "hide for now", not "pause
  polling"). Anyone who wants the list to stay empty until their next deliberate click also
  needs to pause the poll interval itself (there is currently no dedicated switch for that).

## Analysis feature: how it works & its limits

The Analysis page reads `ns.log` via the NITRO endpoint `systemfile`
(`nitro.get_system_file`), filters out all CEF lines with signature ID `APPFW` via regex
(`log_parser.parse_appfw_log`), and shows them as individual cards color-coded by severity.
A dropdown (1/3/5 minutes) controls how often `static/js/analysis.js` reloads the fragment
`/analysis/data` and swaps out the content of `#log-container`.

There are also purely client-side filters (no additional server request needed), which are
automatically reapplied after every poll:
- **Action filter** (`All` / `Blocked` / `Not Blocked`): compares the `act` field exactly
  against `"blocked"`. Everything else (`dropped`, `none`, `logged`, ...) counts as "Not
  Blocked". If, say, `dropped` should also count as "Blocked", adjust `applyFilters()` in
  `static/js/analysis.js`. The selection is remembered in localStorage, same as the poll
  interval.
- **Free-text search:** searches the complete, unchanged log line (`data-search` attribute
  per card) - so it also finds values that only appear in the collapsed details, e.g. the
  transaction ID (`cs3`). As soon as the field contains text, an **"X" button** appears on
  the right of the field, clearing the search text (the action filter is unaffected). The
  button's visibility is set in `applyFilters()`, so it's correctly shown/hidden after
  polling too and after `filterByValue()` (clicking a transaction ID).
- **Profile link:** the profile name in every log card links to
  `/dashboard?jump_profile=<name>#profile-<name>`. `static/js/dashboard.js` recognizes the
  `jump_profile` parameter when the Dashboard loads, automatically opens the matching
  profile section including its detail area, and scrolls there (uses the same
  `jumpToProfile()` function as the existing profile link in the policy details).
- **Transaction-ID link:** in the expandable details of every log card, the transaction ID
  (`cs3`) is also a link. Clicking it enters the value into the search field above and
  filters on it immediately (calls `filterByValue()` in `static/js/analysis.js`). The value
  is deliberately passed only via a `data-*` attribute rather than interpolated directly
  into the JS call, so that log data containing special characters (e.g. `'`) can't inject
  anything into the `onclick` handler.

## Buffer-overflow actions: relaxation rule & activate

For buffer-overflow hits (`APPFW_BUFFEROVERFLOW*`), there are two buttons in the expandable
log details, depending on whether the hit was `Blocked` or `Not Blocked`
(`log_parser.is_blocked_action`):

- **Blocked → "Create relaxation rule"**: block is already active; the button only raises
  the affected threshold (Max URL/Header/Cookie Length, see `BUFFER_OVERFLOW_FIELD_MAP` in
  `log_parser.py`) in the associated profile to the value NetScaler itself reported - the
  equivalent of NetScaler's own **"Click-to-Deploy"** feature in the Syslog Viewer. The
  value is primarily parsed from the `msg` line
  (`"...length(960) is greater than maximum allowed(200)."`); only if this pattern isn't
  found does the tool fall back to the character count of the logged request URL and show a
  warning, since that isn't necessarily exactly the value NetScaler measured internally.
- **Not Blocked → "Activate"**: only sets `block` in the profile's `bufferoverflowaction`
  list (existing actions like `log`/`stats` are preserved, read-modify-write via
  `get_appfw_profile` + `update_appfw_profile`). The threshold is deliberately NOT changed
  here, since the current value has already been exceeded (otherwise there wouldn't be a
  log entry) - raising it to the observed length at the same time would let exactly this
  request, and similarly long ones, straight through again.

Both actions ask for confirmation via `window.confirm()` before the actual NITRO write
(`static/js/buffer_overflow_actions.js`) and show success/error directly on the button.

**Important assumption that should be checked:** NITRO has no per-URL exception list for
Buffer Overflow like other checks do - "relaxation" here necessarily means a
**profile-wide** increase of the threshold, not an exception limited to this one URL. The
mapping `APPFW_BUFFEROVERFLOW_QUERY` → `bufferoverflowmaxurllength` as well as
`APPFW_BUFFEROVERFLOW_TOTAL_HDR` → `bufferoverflowmaxheaderlength` is a plausible but not
1:1 Citrix-documented assumption (see the comment in `log_parser.py`,
`BUFFER_OVERFLOW_FIELD_MAP`).

## Start-URL relaxation

Unlike Buffer Overflow, the relaxation rule here is a real exception limited to exactly one
URL: NITRO object `appfwprofile_starturl_binding`, created via POST with `{name: <profile>,
starturl: <regex>}` (`nitro.add_appfw_starturl_binding`). The button only appears for
`Blocked` hits of `APPFW_STARTURL` (`log_parser._parse_start_url`, field `is_start_url`).

The suggested rule is generated from the logged request URL: the query string is stripped
(Start URL only checks the path, not the parameters - **assumption**, see the comment near
`_suggest_starturl_pattern`), the rest is turned via `re.escape()` into an exact, anchored
regex (`^...$`). The value is shown in full in both the button text AND the confirmation
dialog before the actual NITRO write is executed.

Shared building blocks for the confirmation dialog + success/error display now live in
`static/js/relaxation_actions.js` (previously part of `buffer_overflow_actions.js`), so
that Buffer Overflow and Start URL share the same logic instead of duplicating it.

## SQL-injection relaxation (HTML / XML / JSON)

For **blocked** SQL-injection hits (`APPFW_SQL`, `APPFW_XML_SQL`, JSON variant), the button
"Create relaxation rule" (false positive) appears in the log details. Field name and
location are parsed from the `msg` line (`SQL Keyword check failed for field q="..."`,
`log_parser._parse_sql_injection`); route: `/analysis/sql-injection/relax`. Without a
recognizable field name (HTML/XML), NO button is deliberately shown.

| Type | NITRO object | Granularity / scope |
|---|---|---|
| HTML | `appfwprofile_sqlinjection_binding` | **individual pattern** (keyword / special string / wildchar) for **one field on one URL** |
| XML | `appfwprofile_xmlsqlinjection_binding` | **profile-wide, whole element/attribute** - NetScaler knows neither URL nor value type here |
| JSON | `appfwprofile_jsonsqlurl_binding` | **all keys of this URL** (only the URL field verified) |

### HTML: releasing individual patterns (default)

Instead of exempting the entire field from the SQL check, the button only releases the
named patterns; every other SQL attack pattern in the same field on the same URL is still
checked. Clicking it opens a dialog (`static/js/sql_injection_actions.js`) with the
patterns recognized from the log message (`log_parser._parse_sql_tokens`). There, patterns
can be deselected, changed, and added. **Each pattern gets its own rule**:
`as_value_type_sql` (Keyword | SpecialString | Wildchar) + `as_value_expr_sql` as a literal
(`isvalueregex_sql = NOTREGEX`), bound to the field name (`sqlinjection`, also literal) and
form-action URL (`formactionurl_sql`, anchored regex).

- **Message format (confirmed on a real NetScaler 14.1):** `..or(;)` = keyword `or` +
  special character `;`. The dots are an ellipsis marker (more text before/after the
  keyword) and are NOT part of the keyword - the parser strips them (`_strip_ellipsis`). A
  rule with `..or` never matches.
- **Pre-selection = keyword only:** in the default mode `SQLSplCharANDKeyword`, NetScaler
  only blocks on keyword AND special character; releasing the keyword is sufficient.
  Released special characters widen the rule unnecessarily (if `;` is released,
  `x; drop table t` gets through as long as no other special character appears). Special
  characters are therefore listed but not pre-selected; check them additionally if needed
  for a different check mode (`SQLSplChar`, `SQLSplCharORKeyword`). **Price of releasing the
  keyword:** patterns that only use this one keyword (e.g. `' or 1=1`) then get through on
  this field/URL.
- **An iterative approach is normal:** NetScaler only reports what it flagged (one keyword +
  one special character), not necessarily ALL suspicious patterns in the input value.
  Missing patterns can be added in the dialog, or released after testing again via the next
  log entry. Existing rules count as done.
- **Grammar:** per Citrix docs, rules with value type `Keyword` are evaluated when SQL
  grammar is enabled - so keyword rules stay effective. Special-character rules only affect
  the pattern-match check.
- **Wildcards:** if "Check for SQL Wildcards" is enabled later and reports a wildchar, add
  it in the dialog as "Wildcard" (or add it manually beforehand).
- On a partial success (an individual rule fails), the message states exactly what was
  created and what wasn't; clicking again is safe.
- If the page's auto-refresh fires while the dialog is open, the result appears as a
  bottom-right toast instead of on the (then replaced) button.

### XML and JSON: coarser rules (a NetScaler limitation, or unverified)

Both use a simple confirmation dialog stating the actual scope. XML rules can't be bound to
a URL or pattern in NetScaler (profile-wide for the element). For JSON, newer versions
reportedly also know key name/value type; the exact NITRO field names for this could not be
verified, so the JSON rule is URL-only. Once the field names are known (e.g. via
`GET /nitro/v1/config/appfwprofile_jsonsqlurl_binding/<profile>` after manually creating a
fine-grained rule in the GUI), JSON can be switched over analogously to HTML.

**Assumptions that should be checked (not tested against a real appliance):**
- The value expression is matched against the **flagged pattern** (keyword/special
  character), not the complete field value. Confirmed in practice for special characters
  (after releasing `;`, NetScaler reported the next character `'`). Test: create the rule,
  resend the example; then send a value with a NOT-released keyword AND special character -
  it must still be blocked.
- The message format `<keyword>(<special character>)` (NetScaler >= 11.0, HTML payloads
  only; confirmed on 14.1 with the `..` marker). Older formats with the complete input
  value provide no suggestions; patterns are then entered manually. Multiple special
  characters may be suggested as a single pattern - split them in the dialog if they should
  be handled individually.
- For XML/JSON, the message format matches the pattern `... check failed for
  <element|attribute|key> <name>`; the JSON event name contains `JSON` and `SQL`; for XML,
  `ELEMENT` is assumed unless the message says "attribute".
- `formactionurl_sql` / `jsonsqlurl` expect the anchored regex `^scheme://host/path$` (as
  with NetScaler Learning and the start-URL rule). If the request is still blocked despite
  the rule, check the rule in the profile.
- If a rule already exists, NetScaler reports "Resource already exists"; the UI shows an
  explanatory note for this.

## Command-injection relaxation (HTML)

For **blocked** command-injection hits, the button "Create relaxation rule (Command
Injection → ...)" appears in the log details. Structure and usage match the SQL-injection
dialog (`injection_token_dialog.js`): the dialog shows the patterns recognized from the
message, which can be deselected, changed, and added; **each pattern gets its own rule**
(`log_parser._parse_cmd_injection`, route `/analysis/cmd-injection/relax`).

- **NITRO object:** `appfwprofile_cmdinjection_binding` with `cmdinjection` (field name,
  literal, `isregex_cmd=NOTREGEX`), `formactionurl_cmd` (anchored URL regex),
  `as_scan_location_cmd` (FORMFIELD | HEADER | COOKIE), `as_value_type_cmd` (**Keyword |
  SpecialString**, no wildchar), and `as_value_expr_cmd` (literal,
  `isvalueregex_cmd=NOTREGEX`).
- **Pre-selection = keyword only:** default mode is `CMDSplCharANDKeyword` (block only on
  special character AND keyword), releasing the keyword is enough. Released special
  characters widen the rule unnecessarily (if `;` is released, e.g. `x; cat y` gets
  through). For a different check mode (`CMDSplChar`, `CMDSplCharORKeyword`), additionally
  check special characters if needed. **Price of releasing the keyword:** the released
  command (e.g. `ping`) may afterward appear in this field on this URL with arbitrary
  special characters.
- **Grammar:** per Citrix docs, keyword rules are evaluated when CMD grammar is enabled.
- **Not implemented:** JSON command injection (the CLI knows `-jsoncmdURL` with key and
  value type, but the NITRO field names couldn't be verified) as well as XML. No button
  appears there.
- **Assumptions (not tested against a real appliance):**
  - **Event name and message text** are not confirmed. Any event name containing `CMD` or
    `COMMAND` is recognized; for an unknown name, also any "check failed" message that
    mentions `CMD` or `Command Injection`. Field name/location are read from
    `... check failed for field|header|cookie <name>="..."` (as with SQL). If no button
    appears, usually the field name is missing: check the real log line and adjust
    `_cmd_event_kind` or the two `SQL_MSG_*_RE`.
  - The bracket format `<keyword>(<special character>)` including the `..` ellipsis marker
    applies as with SQL (confirmed there on a real NetScaler 14.1). Older formats with the
    complete input value provide no suggestions; patterns are then entered manually.
  - The value expression matches the **flagged pattern**, not the whole field value
    (confirmed for SQL).
  - Test: create the rule, resend the example; then send a value with a NOT-released
    command AND special character - it must still be blocked.

## Cookie Consistency: switching from Block to Transform

The button appears on **every** cookie-consistency hit (`APPFW_COOKIE`), regardless of
`blocked`/`not blocked` - label and hint text adapt accordingly:
- **blocked:** "Switch to Transform" - the text makes clear that block is being removed.
- **not blocked:** "Adjust cookie-transform settings" - the hint explains that this case
  isn't blocking already and only sets the three profile-wide settings (Encrypt/Proxy/Flags),
  e.g. to configure them ahead of enabling block, or to change them afterward. The dialog
  and the three selection lists are identical in both cases. Unlike the other buttons, in
  both cases this is not a fine-grained exception for a single hit, but a **profile-wide**
  change of the check action or the transform settings
(`log_parser._parse_cookie_consistency`, route `/analysis/cookie-consistency/transform`,
`nitro.set_cookie_consistency_transform`) - it affects every request going through this
profile.

Clicking it opens a dialog with the three NetScaler transform settings (values and labels
exactly as in the NetScaler profile):

| Setting | NITRO field | Values |
|---|---|---|
| Encrypt Server Cookies | `cookieencryption` | None, Decrypt Only, Encrypt Session Only, Encrypt All |
| Proxy Server Cookies | `cookieproxying` | None, Session Only |
| Flags to add in Cookies | `addcookieflags` | None, Secure, HTTP Only, All |

**Deviation from the request:** for "Flags to add in Cookies", only Secure, HTTP Only and
All were named; NetScaler additionally knows `none` there (set no flag), as with the other
two settings - this was added so the selection matches the real profile setting. Remove it
from `COOKIE_FLAGS_VALUES` (`app.py`) again if needed.

On submit, a PUT to `appfwprofile` (read-modify-write, since a NITRO PUT replaces the field
instead of merging):
- `block` is removed from `cookieconsistencyaction` IF it was set (Log/Stats/Learn are
  preserved); if `block` wasn't set (the not-blocked case), the action is left unchanged,
- `cookietransforms` is set to `ON` - per Citrix docs, the three settings otherwise have no
  effect ("no cookie transformations are performed regardless of any other settings"),
- the three chosen values are set.

The route reads the profile's actual state (not the triggering log line's action) and
phrases the success message accordingly ("Block removed" vs. "Block was not active"). If
only `block` was set in the profile, no actions remain active after the change (not even
`log`); the message points this out. No button for other event types.
**Not tested against a real appliance:** only with simulated NITRO.

## Deny URL from logged requests

If `logEveryPolicyHit ON` is set in the profile, NetScaler logs every request that hits a
WAF policy as `APPFW_POLICY_HIT` (msg "Application Firewall profile invoked", with no
transaction ID). The "Not blocked" list thus shows all requests; on every policy hit with
`act=not blocked`, the button **"Create deny-URL rule"** appears
(`log_parser._parse_policy_hit`, route `/analysis/deny-url/add`).

**Terminology:** NetScaler itself calls deny-URL entries "Deny URL relaxation rules", but
technically they're additions (rules), not exceptions - the URL will be **rejected** going
forward. NITRO object: `appfwprofile_denyurl_binding` (`name`, `denyurl`). Deny URL takes
precedence over Start URL.

- **Dialog / variants:** it is NOT confirmed which representation of the URL NetScaler
  matches the deny-URL pattern against (with scheme+host, path only, with/without query
  string). The initially suggested, strictly anchored pattern `^http://host/path$` didn't
  work in a real test (access was let through despite an active Deny-URL check). The
  default is therefore a **tolerant pattern** that matches every representation of the same
  path and only allows the host from the log: `^(?:https?://host)?/path(?:\?.*)?$`. Also
  selectable are "Strict" (scheme+host+path), "Path only" (host-independent), and "Custom".
  A live check line (JavaScript regex, not PCRE) shows which of the four representations
  the pattern matches. The pattern remains freely editable (e.g. `^/admin/` for a directory
  or `[.]bak$` for an extension).
- **Protection against locking yourself out:** patterns that match at least 3 of 4 example
  URLs (each in the host and the path representation) (`.*`, `http`, `^/.+`, ...) are
  rejected server-side before reaching NITRO. PCRE syntax that Python can't compile is not
  checked (NetScaler then validates it).
- **Only effective with `block`:** after creating it, the app reads the profile's
  `denyurlaction` and appends a NOTE if `block` is missing (check inactive, or Log/Stats
  only). Without `block`, the rule is created but doesn't reject anything.
- No button on policy hits with `act=blocked` (already rejected there) and for all other
  event types.
- **If access still gets through despite the rule - diagnosis:**
  1. The profile's deny-URL action must include `block` (the NOTE after creation checks
     this).
  2. Test with Start URL disabled, since Start URL can block the same page independently of
     the deny rule (`APPFW_STARTURL` in the log). Deny URL takes precedence over Start URL
     as long as `block` is active.
  3. Search the log for `APPFW_DENYURL`: if the entry is missing, the pattern doesn't match
     the representation NetScaler checks - try a different variant or pattern. Check the
     rule in the profile (GUI: Profile > Deny URL > Checks) and delete it if necessary
     before creating a differing variant with the same pattern text.
  4. Whether the policy captures the request at all (is there a policy-hit entry).
- With `logEveryPolicyHit` active, policy hits fill the list (max. `MAX_LOG_ENTRIES`
  entries) and can push out real violations; the "Blocked" action filter hides them.

**Important limitations arising from the NITRO API:**
- `systemfile` always returns the file **completely**, there is no offset/tail reading. On
  an active appliance, `ns.log` can be several MB - this is fully transferred and parsed on
  every poll. For sustained production use, consider deliberately choosing a large poll
  interval, or adding a server-side size limit/rotation.
- The logged-in NetScaler user needs read rights on system files. If not, the page reports
  this as an error text (no silent failure).
- The meaning of `cn1`, `cn2` and `cs5` in the CEF extension part is not unambiguously
  documented and is therefore shown under the raw field name (see the comment in
  `log_parser.py`). `cs1` (profile), `cs2` (PPE), `cs3` (transaction ID), and `cs4`
  (severity), on the other hand, are clearly identifiable from the example log and labeled
  accordingly.
- Assumes active CEF logging on the NetScaler. If native NetScaler format or LEEF is used
  instead, `log_parser.py` needs to be adapted.

## Getting started

```bash
pip install -r requirements.txt
python app.py       # http://localhost:5000 (development server)
# production/Docker: gunicorn -b 0.0.0.0:8000 app:app
```

Note: `PROTOCOL` in `nitro.py` is set to `http`. For production use, switch to `https` and
adjust the certificate check (`verify=False`).
