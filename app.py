"""
NetScaler WAF Monitor – Flask-Anwendung.

Enthält nur App-Setup und Routen. Die NITRO-Kommunikation liegt in
nitro.py, die Aufbereitung der Profildaten in profile_parser.py.
"""
import os
import re
import warnings
from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify, g

from nitro import (
    nitro_login,
    get_waf_policies,
    get_waf_profiles,
    get_policy_stats,
    get_policy_vserver_bindings,
    get_appfw_log_text,
    get_appfw_profile,
    update_appfw_profile,
    add_appfw_starturl_binding,
    add_appfw_sqlinjection_binding,
    add_appfw_xmlsqlinjection_binding,
    add_appfw_jsonsqlurl_binding,
    add_appfw_denyurl_binding,
    add_appfw_cmdinjection_binding,
    set_cookie_consistency_transform,
    add_appfw_csrftag_binding,
    get_lb_vservers,
    get_cs_vservers,
    get_services,
    get_servicegroups,
    get_lbvserver_service_bindings,
    get_lbvserver_servicegroup_bindings,
    get_csvserver_lbvserver_binding,
    get_vserver_appfwpolicy_bindings,
    add_appfw_policy,
    add_vserver_appfwpolicy_binding,
    add_appfw_profile,
    get_appfw_signature_objects,
    delete_appfw_signature_object,
    upload_system_file,
    import_appfw_signature_from_file,
)
from profile_parser import enrich_profiles_with_checks, parse_action_tokens, CHECK_LABELS, CHECKS_WITHOUT_LEARN
from objects_parser import structure_vserver, _backend_summary
import signature_db
from translations import detect_locale, translate
from nvd_client import search_cves_by_keyword
from signature_file_parser import fetch_and_parse_signature_file, build_filtered_signature_xml
from log_parser import parse_appfw_log, BUFFER_OVERFLOW_FIELD_LABELS, SQL_TOKEN_TYPES, CMD_TOKEN_TYPES

app = Flask(__name__)
signature_db.init_db()
app.secret_key = os.environ.get('SECRET_KEY', 'fallback-dev-key-123456')


@app.before_request
def _set_locale():
    """
    Sprache je Browser (Accept-Language-Header) statt je Nutzer-Einstellung -
    passt zum Wunsch "je nach Browsersprache anzeigen". Kein Speichern in
    Session/Cookie: ändert der Nutzer die Browsersprache, wirkt das sofort
    beim nächsten Request, ohne dass er sich neu anmelden müsste.
    """
    g.locale = detect_locale(request.headers.get('Accept-Language'))


@app.context_processor
def _inject_translation_helper():
    """Stellt t('schlüssel') und die aktuelle Sprache alle Templates zur
    Verfügung, ohne sie in jeder render_template()-Aufruf einzeln
    mitgeben zu müssen."""
    return {'t': lambda key, **kwargs: translate(g.locale, key, **kwargs), 'locale': g.locale}

# Profile, die NetScaler standardmäßig mitbringt (alles andere gilt als "custom")
DEFAULT_PROFILE_NAMES = [
    "ns-aaa-default-appfw-profile",
    "ns-aaatm-default-appfw-profile",
    "ns-vpn-default-appfw-profile",
    "ns-web-default-appfw-profile",
    "ns-mgmt-gui-default-appfw-profile",
    "APPFW_BYPASS",
    "APPFW_RESET",
    "APPFW_DROP",
    "APPFW_BLOCK",
]

# Speicherort/Name der auszulesenden Logdatei sowie Obergrenze der
# angezeigten Einträge (Performance: ns.log kann mehrere MB groß sein und
# wird bei jedem Poll komplett übertragen, siehe nitro.get_system_file).
NS_LOG_LOCATION = '/var/log'
NS_LOG_FILENAME = 'ns.log'
MAX_LOG_ENTRIES = 300

# Auswahlmöglichkeiten für das Polling-Intervall auf der Analysis-Seite
# (Wert in Sekunden, Label für das Dropdown).
POLL_INTERVALS = [
    {'seconds': 60, 'label_key': 'time.minute_1'},
    {'seconds': 180, 'label_key': 'time.minutes_3'},
    {'seconds': 300, 'label_key': 'time.minutes_5'},
]


# Feldnamen, unter denen NITRO den Hit-Zähler einer Policy liefern kann.
# Für stat/appfwpolicy heißt das Feld "pipolicyhits" (NITRO-Doku:
# appfwpolicy | statistics). Die übrigen Namen sind nur Fallbacks.
POLICY_HIT_FIELDS = ('pipolicyhits', 'hits', 'totalhits', 'totalrequests')


def extract_policy_hits(stat):
    """
    Liest den Hit-Zähler aus einem stat/appfwpolicy-Eintrag. NITRO liefert
    Statistikwerte häufig als String ("42"), daher wird in int gewandelt.
    Fehlt das Feld (z.B. Policy nirgends gebunden), ergibt das 0.
    """
    for field in POLICY_HIT_FIELDS:
        value = stat.get(field)
        if value in (None, ''):
            continue
        try:
            return int(float(value))
        except (TypeError, ValueError):
            continue
    return 0


def build_enriched_policies(nsip, token):
    """Policies mit Hits, Profil und gebundenen vServern zusammenstellen."""
    policies = get_waf_policies(nsip, token)
    stats_dict = get_policy_stats(nsip, token)

    enriched_policies = []
    for policy in policies:
        name = policy.get('name')
        stat = stats_dict.get(name, {})
        hits = extract_policy_hits(stat)
        profile = policy.get('profile') or policy.get('profilename') or '–'
        vservers = get_policy_vserver_bindings(nsip, token, name) if name else []
        enriched_policies.append({
            'name': name,
            'state': policy.get('state', 'UNKNOWN'),
            'comment': policy.get('comment', ''),
            'rule': policy.get('rule', ''),
            'profile': profile,
            'hits': hits,
            'vservers': vservers,
        })
    return enriched_policies


def load_appfw_log_entries(nsip, token):
    """
    Liest ns.log über NITRO und filtert die WAF(AppFW)-Einträge heraus.
    Gibt (entries, error_message) zurück - error_message ist None bei Erfolg.
    """
    raw_text = get_appfw_log_text(nsip, token, NS_LOG_LOCATION, NS_LOG_FILENAME)
    if raw_text is None:
        return [], (
            f"{NS_LOG_FILENAME} konnte nicht gelesen werden. Prüfen Sie, ob der "
            "angemeldete Benutzer Leserechte auf Systemdateien hat (NITRO "
            "systemfile) und ob der Pfad korrekt ist."
        )
    entries = parse_appfw_log(raw_text, max_entries=MAX_LOG_ENTRIES)
    return entries, None


@app.route('/', methods=['GET', 'POST'])
def login():
    if 'auth_token' in session:
        return redirect(url_for('dashboard'))
    error = None
    if request.method == 'POST':
        nsip = request.form.get('nsip', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not nsip or not username or not password:
            error = "Bitte alle Felder ausfüllen."
        else:
            token = nitro_login(nsip, username, password)
            if token:
                session['auth_token'] = token
                session['nsip'] = nsip
                session['username'] = username
                session.pop('_flashes', None)
                flash('Erfolgreich angemeldet!', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = "Anmeldung fehlgeschlagen. Bitte IP, Benutzername und Passwort prüfen."
    return render_template('login.html', error=error)


@app.route('/dashboard')
def dashboard():
    if 'auth_token' not in session:
        flash('Bitte zuerst anmelden.', 'warning')
        return redirect(url_for('login'))

    nsip = session.get('nsip')
    token = session.get('auth_token')

    enriched_policies = build_enriched_policies(nsip, token)

    profiles = get_waf_profiles(nsip, token)
    default_profiles = enrich_profiles_with_checks(
        [p for p in profiles if p.get('name') in DEFAULT_PROFILE_NAMES]
    )
    custom_profiles = enrich_profiles_with_checks(
        [p for p in profiles if p.get('name') not in DEFAULT_PROFILE_NAMES]
    )

    return render_template(
        'dashboard.html',
        active_page='dashboard',
        nsip=nsip,
        username=session.get('username'),
        policies=enriched_policies,
        default_profiles=default_profiles,
        custom_profiles=custom_profiles,
        policy_count=len(enriched_policies),
        default_profile_count=len(default_profiles),
        custom_profile_count=len(custom_profiles),
    )


def _build_vserver_objects(nsip, token, profiles):
    """
    Baut die vollstaendige Liste angereicherter VServer-Objekte (LB + CS)
    fuer die Objekte-Seite. Ein NITRO-Aufruf pro VServer fuer dessen
    Bindungen (Backends, AppFW-Policies) - analog zum bereits bestehenden
    Muster in build_enriched_policies() (dort: ein Aufruf pro Policy).
    profiles: bereits geladene appfwprofile-Liste (vermeidet einen
    zusätzlichen NITRO-Aufruf, da der Aufrufer sie ohnehin braucht).
    """
    policies_by_name = {p['name']: p for p in get_waf_policies(nsip, token) if p.get('name')}
    profiles_by_name = {p['name']: p for p in profiles if p.get('name')}

    vservers = []
    for vs in get_lb_vservers(nsip, token):
        name = vs.get('name')
        if not name:
            continue
        backends = []
        for b in get_lbvserver_service_bindings(nsip, token, name):
            backends.append({'name': b.get('servicename'), 'kind': 'service',
                             'summary': _backend_summary(b)})
        for b in get_lbvserver_servicegroup_bindings(nsip, token, name):
            backends.append({'name': b.get('servicegroupname'), 'kind': 'servicegroup', 'summary': ''})
        policy_bindings = get_vserver_appfwpolicy_bindings(nsip, token, 'lb', name)
        vservers.append(structure_vserver(vs, 'lb', backends, policy_bindings, policies_by_name, profiles_by_name))

    for vs in get_cs_vservers(nsip, token):
        name = vs.get('name')
        if not name:
            continue
        backends = []
        for b in get_csvserver_lbvserver_binding(nsip, token, name):
            target = b.get('lbvserver')
            if target:
                backends.append({'name': target, 'kind': 'lbvserver', 'summary': 'Ziel-LB-VServer'})
        policy_bindings = get_vserver_appfwpolicy_bindings(nsip, token, 'cs', name)
        vservers.append(structure_vserver(vs, 'cs', backends, policy_bindings, policies_by_name, profiles_by_name))

    return vservers


OBJECT_NAME_RE = re.compile(r'^[A-Za-z0-9_.:@=#\- ]{1,255}$')


@app.route('/objects/bind-profile', methods=['POST'])
def objects_bind_profile():
    """
    Drag-and-drop-Zielaktion: legt eine NEUE AppFW-Policy an, die auf das
    per Drag&Drop gewählte Profil zeigt, und bindet sie an den VServer, auf
    den das Profil gezogen wurde. Zwei NITRO-Schreibaufrufe (Policy anlegen,
    dann binden); schlägt der zweite fehl, bleibt die bereits angelegte
    Policy stehen - das wird in der Fehlermeldung transparent gemacht,
    statt es zu verschleiern.
    """
    if 'auth_token' not in session:
        return jsonify({'success': False, 'message': 'Sitzung abgelaufen. Bitte erneut anmelden.'}), 401

    payload = request.get_json(silent=True) or {}
    vserver_name = (payload.get('vserver_name') or '').strip()
    vserver_type = (payload.get('vserver_type') or '').strip().lower()
    profile_name = (payload.get('profile_name') or '').strip()
    policy_name = (payload.get('policy_name') or '').strip()
    rule = (payload.get('rule') or '').strip()
    priority_raw = payload.get('priority')

    def bad_request(message):
        return jsonify({'success': False, 'message': message}), 400

    if vserver_type not in ('lb', 'cs'):
        return bad_request(f'Ungültiger VServer-Typ: {vserver_type or "(leer)"}')
    if not vserver_name or not OBJECT_NAME_RE.match(vserver_name):
        return bad_request('Kein (gültiger) VServer-Name angegeben.')
    if not policy_name or not OBJECT_NAME_RE.match(policy_name):
        return bad_request('Kein (gültiger) Policy-Name angegeben.')
    if not profile_name or not OBJECT_NAME_RE.match(profile_name):
        return bad_request('Kein (gültiges) Profil angegeben.')
    if not rule:
        return bad_request('Kein Regel-Ausdruck angegeben.')
    if len(rule) > 8192:
        return bad_request('Regel-Ausdruck zu lang.')
    try:
        priority = int(priority_raw)
        if priority <= 0:
            raise ValueError
    except (TypeError, ValueError):
        return bad_request(f'Ungültige Priorität: {priority_raw!r} (muss eine positive Zahl sein).')

    nsip = session.get('nsip')
    token = session.get('auth_token')

    # Das Profil muss auf dem NetScaler existieren - sonst legt NITRO die
    # Policy zwar an, aber sie zeigt auf ein nicht vorhandenes Profil.
    existing_profiles = {p.get('name') for p in get_waf_profiles(nsip, token)}
    if profile_name not in existing_profiles:
        return bad_request(f'Profil "{profile_name}" existiert nicht (mehr) auf dem NetScaler.')

    comment = 'Über WAF Monitor Objekte-Seite (Drag & Drop) angelegt'
    policy_ok, policy_error = add_appfw_policy(nsip, token, policy_name, rule, profile_name, comment=comment)
    if not policy_ok:
        if policy_error and 'exist' in policy_error.lower():
            message = f'Policy "{policy_name}" existiert bereits ({policy_error}) - bitte einen anderen Namen wählen.'
        else:
            message = f'Fehler beim Anlegen der Policy "{policy_name}": {policy_error}'
        return jsonify({'success': False, 'message': message})

    bind_ok, bind_error = add_vserver_appfwpolicy_binding(
        nsip, token, vserver_type, vserver_name, policy_name, priority)
    if not bind_ok:
        message = (f'Policy "{policy_name}" wurde angelegt, aber die Bindung an "{vserver_name}" ist '
                  f'fehlgeschlagen: {bind_error}. Die Policy existiert jetzt unabhängig davon auf dem '
                  'NetScaler und kann dort manuell gebunden oder wieder entfernt werden.')
        return jsonify({'success': False, 'message': message})

    message = f'Policy "{policy_name}" (Profil "{profile_name}") an "{vserver_name}" gebunden (Priorität {priority}).'
    return jsonify({'success': True, 'message': message})


# Vordefinierte Signatur-Kategorien. Für die beiden Microsoft-Anwendungen
# wird bewusst zusätzlich nach "Microsoft IIS" gesucht (auf Wunsch des
# Nutzers) - OWA/SharePoint laufen auf IIS, die zugehörigen IIS-CVEs sind
# also ebenfalls relevant für ein Profil, das diese Anwendung schützt.
SIGNATURE_CATEGORY_PRESETS = {
    'IIS': ['Microsoft IIS'],
    'Apache': ['Apache HTTP Server'],
    'OWA': ['Microsoft Exchange Server', 'Microsoft IIS'],
    'SharePoint': ['Microsoft SharePoint', 'Microsoft IIS'],
    'WordPress': ['WordPress'],
}


@app.route('/objects/signature-categories/create', methods=['POST'])
def create_signature_category():
    """
    Legt eine Signatur-Kategorie an: entweder eine der 5 vordefinierten
    (IIS/Apache/OWA/SharePoint/WordPress, mit festen Suchbegriffen) oder
    eine eigene mit frei angegebenen Suchbegriffen. Für jeden Suchbegriff
    wird die NVD nach passenden CVEs durchsucht (search_cves_by_keyword);
    Treffer werden über alle Begriffe hinweg zusammengeführt und dedupliziert
    (dieselbe CVE kann z.B. sowohl bei "SharePoint" als auch bei "Microsoft
    IIS" auftauchen). NUR lokal gespeichert (SQLite) - schreibt NICHT zum
    NetScaler; der Import als echtes appfwsignatures-Objekt ist ein
    separater, noch nicht umgesetzter Schritt.
    """
    if 'auth_token' not in session:
        return jsonify({'success': False, 'message': 'Sitzung abgelaufen. Bitte erneut anmelden.'}), 401

    payload = request.get_json(silent=True) or {}
    preset = (payload.get('preset') or '').strip()
    custom_name = (payload.get('name') or '').strip()
    custom_terms_raw = (payload.get('terms') or '').strip()

    def bad_request(message):
        return jsonify({'success': False, 'message': message}), 400

    if preset:
        if preset not in SIGNATURE_CATEGORY_PRESETS:
            return bad_request(f'Unbekannte vordefinierte Kategorie: {preset}')
        name = preset
        terms = SIGNATURE_CATEGORY_PRESETS[preset]
    else:
        if not custom_name or not OBJECT_NAME_RE.match(custom_name):
            return bad_request('Kein (gültiger) Name für die eigene Kategorie angegeben.')
        terms = [t.strip() for t in custom_terms_raw.split(',') if t.strip()]
        if not terms:
            return bad_request('Bitte mindestens einen Suchbegriff angeben (kommagetrennt).')
        if len(terms) > 5:
            return bad_request('Maximal 5 Suchbegriffe je Kategorie.')
        name = custom_name

    if signature_db.category_name_exists(name):
        return bad_request(f'Eine Kategorie mit dem Namen "{name}" existiert bereits.')

    category_id = signature_db.create_category(name, terms)

    all_cves = {}
    per_term_counts = {}
    for term in terms:
        found = search_cves_by_keyword(term)
        per_term_counts[term] = len(found)
        for cve in found:
            if cve['cve_id'] not in all_cves:
                all_cves[cve['cve_id']] = {**cve, 'matched_term': term}
    signature_db.add_category_cves(category_id, list(all_cves.values()))

    term_summary = '; '.join(f'{t}: {c}' for t, c in per_term_counts.items())
    if all_cves:
        message = f'Kategorie "{name}" angelegt mit {len(all_cves)} CVEs ({term_summary}).'
    else:
        message = (f'Kategorie "{name}" angelegt, aber es wurden keine CVEs gefunden ({term_summary}). '
                  'Möglich, dass die NVD-Anfrage fehlgeschlagen ist (siehe Server-Log) oder die '
                  'Suchbegriffe zu keinem Treffer führten.')
    return jsonify({'success': True, 'message': message, 'category_id': category_id, 'cve_count': len(all_cves)})


@app.route('/objects/signature-categories/<int:category_id>/assign', methods=['POST'])
def assign_signature_category(category_id):
    """
    Merkt lokal vor, dass ein Profil diese Signatur-Kategorie erhalten soll
    (Drag & Drop einer Kategorie-Karte auf eine Profil-Karte). Schreibt
    NICHTS zum NetScaler - das ist der noch nicht umgesetzte Import-Schritt.
    """
    if 'auth_token' not in session:
        return jsonify({'success': False, 'message': 'Sitzung abgelaufen. Bitte erneut anmelden.'}), 401

    payload = request.get_json(silent=True) or {}
    profile_name = (payload.get('profile_name') or '').strip()
    if not profile_name or not OBJECT_NAME_RE.match(profile_name):
        return jsonify({'success': False, 'message': 'Kein (gültiges) Profil angegeben.'}), 400

    category = signature_db.get_category(category_id)
    if not category:
        return jsonify({'success': False, 'message': 'Kategorie nicht gefunden.'}), 400

    nsip = session.get('nsip')
    token = session.get('auth_token')
    known_profiles = {p.get('name') for p in get_waf_profiles(nsip, token)}
    if profile_name not in known_profiles:
        return jsonify({'success': False, 'message': f'Profil "{profile_name}" existiert nicht (mehr) auf dem NetScaler.'}), 400

    signature_db.add_assignment(category_id, profile_name)
    message = (f'Kategorie "{category["name"]}" für Profil "{profile_name}" vorgemerkt ({len(category["cves"])} CVEs). '
              'Noch nicht zum NetScaler übertragen - der Import ist ein separater, noch nicht umgesetzter Schritt.')
    return jsonify({'success': True, 'message': message})


@app.route('/objects/signature-categories/<int:category_id>/delete', methods=['POST'])
def delete_signature_category(category_id):
    """
    Löscht eine lokale Signatur-Kategorie - nur, solange sie keinem Profil
    vorgemerkt zugewiesen ist (sonst müsste die Vormerkung erst entfernt
    werden; dafür gibt es aktuell keine eigene Funktion). Rein lokal, kein
    NetScaler-Zugriff nötig.
    """
    if 'auth_token' not in session:
        return jsonify({'success': False, 'message': 'Sitzung abgelaufen. Bitte erneut anmelden.'}), 401

    category = signature_db.get_category(category_id)
    if not category:
        return jsonify({'success': False, 'message': 'Kategorie nicht gefunden.'}), 400

    assignment_count = signature_db.count_assignments(category_id)
    if assignment_count > 0:
        return jsonify({'success': False, 'message': (
            f'Kategorie "{category["name"]}" ist {assignment_count} Profil(en) vorgemerkt zugewiesen '
            'und kann deshalb nicht gelöscht werden. Ein Entfernen einzelner Vormerkungen ist aktuell '
            'noch nicht möglich.')}), 400

    signature_db.delete_category(category_id)
    return jsonify({'success': True, 'message': f'Kategorie "{category["name"]}" gelöscht.'})


DEFAULT_SIGNATURE_FILE_URL = 'https://s3.amazonaws.com/NSAppFwSignatures/sigs/sig-r14.1b0v183s8.xml'


@app.route('/objects/signature-rules/refresh', methods=['POST'])
def refresh_signature_rules():
    """
    Lädt die öffentliche Citrix-Signaturdatei (Standard-URL editierbar, da
    versionsspezifisch benannt - z.B. "sig-r14.1b0v183s8.xml" für Release
    14.1 Build 0 Version 183) und baut daraus die lokale Regel-Datenbank
    (rule_id -> category/CVE) neu auf. Kein NetScaler-Zugriff nötig, die
    Datei ist öffentlich erreichbar (Citrix' eigener Update-Mechanismus
    lädt von derselben Adresse). Ersetzt die bisherige Regel-Datenbank
    komplett.
    """
    if 'auth_token' not in session:
        return jsonify({'success': False, 'message': 'Sitzung abgelaufen. Bitte erneut anmelden.'}), 401

    payload = request.get_json(silent=True) or {}
    url = (payload.get('url') or DEFAULT_SIGNATURE_FILE_URL).strip()
    if not url.startswith('https://'):
        return jsonify({'success': False, 'message': 'Nur https-URLs sind erlaubt.'}), 400

    rules, meta, raw_bytes, error = fetch_and_parse_signature_file(url)
    if error:
        return jsonify({'success': False, 'message': f'Fehler beim Laden der Signaturdatei: {error}'})

    signature_db.replace_signature_rules(rules, url, meta['schema_version'], meta['version'])
    signature_db.save_source_file(raw_bytes)
    message = (f'Regel-Datenbank aktualisiert: {len(rules)} Regeln geladen (Schema {meta["schema_version"]}, '
              f'Version {meta["version"]}).')
    return jsonify({'success': True, 'message': message, 'rule_count': len(rules)})


SIGNATURE_UPLOAD_LOCATION = '/var/tmp'


@app.route('/objects/signature-categories/<int:category_id>/build', methods=['POST'])
def build_signature_category(category_id):
    """
    Erstellt aus einer lokalen Kategorie ein ECHTES appfwsignatures-Objekt
    auf dem NetScaler (gleicher Name wie die Kategorie). Vorgehen:
      1. Aus der lokal gespeicherten Original-Signaturdatei
         (signature_db.get_source_file(), von "Regel-Datenbank
         aktualisieren" befüllt) eine eigene Kopie bauen, in der GENAU die
         zur Kategorie passenden Regeln enabled="ON" sind, alle anderen
         enabled="OFF" (signature_file_parser.build_filtered_signature_xml).
      2. Diese Datei auf den NetScaler hochladen (upload_system_file).
      3. Das Signatur-Objekt aus dieser hochgeladenen Datei importieren
         (import_appfw_signature_from_file).

    HINTERGRUND: Ursprünglich wurde versucht, ein Signatur-Objekt per
    "import appfw signatures DEFAULT <name>" aus dem eingebauten
    Standard-Set zu KLONEN (mit oder ohne Regel-Filter). Beides schlug an
    einer echten Appliance mit NITRO-Fehler 3197 fehl
    ("Failed to parse Signatures file: /var/download/custom/<name>"). Der
    Nutzer hat das mit dem Citrix-Produktmanager abgeklärt: Es gibt KEINEN
    API-Befehl zum Klonen eines bestehenden Signatur-Objekts. Der einzige
    unterstützte Weg ist der Import einer selbst hochgeladenen Datei -
    deshalb jetzt dieser Ablauf, bei dem der gewünschte Regelzustand direkt
    in die Datei geschrieben wird, statt ihn nachträglich per NITRO zu
    setzen (das hätte ohnehin denselben, oben genannten Klon-Schritt
    gebraucht).

    Nicht jede über die NVD gefundene CVE hat zwangsläufig eine passende
    Regel in der (teils sehr alten, Snort-basierten) Signaturdatei - das
    wird in der Erfolgsmeldung transparent mitgeteilt (X von Y CVEs).

    Das neue Objekt kann danach wie jedes andere Signatur-Objekt in der
    "Signaturen"-Sektion per Drag & Drop einem Profil zugewiesen werden -
    dafür wird hier bewusst keine eigene, zweite Zuweisungslogik gebaut.

    **NICHT VERIFIZIERT** (siehe README): Weder das Zielverzeichnis für den
    Upload (`SIGNATURE_UPLOAD_LOCATION`) noch die Auflösung von
    "src": "local:<filename>" für eine so hochgeladene Datei wurden bisher
    an einer echten Appliance bestätigt.
    """
    if 'auth_token' not in session:
        return jsonify({'success': False, 'message': 'Sitzung abgelaufen. Bitte erneut anmelden.'}), 401

    category = signature_db.get_category(category_id)
    if not category:
        return jsonify({'success': False, 'message': 'Kategorie nicht gefunden.'}), 400

    rules_meta = signature_db.get_signature_rules_meta()
    if not rules_meta or not rules_meta.get('rule_count'):
        return jsonify({'success': False, 'message': (
            'Es ist noch keine Regel-Datenbank geladen. Bitte zuerst "Regel-Datenbank aktualisieren" '
            'ausführen.')}), 400

    source_bytes = signature_db.get_source_file()
    if not source_bytes:
        return jsonify({'success': False, 'message': (
            'Die Original-Signaturdatei liegt nicht mehr lokal vor (z.B. nach einem Update auf eine '
            'ältere Version dieses Tools). Bitte "Regel-Datenbank aktualisieren" erneut ausführen.')}), 400

    rule_ids = sorted({rid for cve in category['cves'] for rid in cve['rule_ids']}, key=int)
    if not rule_ids:
        return jsonify({'success': False, 'message': (
            f'Keine der {len(category["cves"])} CVEs dieser Kategorie hat eine passende Regel in der '
            'geladenen Signaturdatei gefunden. Kein NetScaler-Objekt erstellt.')}), 400

    nsip = session.get('nsip')
    token = session.get('auth_token')
    name = category['name']
    filename = f'{name}.xml'

    filtered_xml, enabled_count = build_filtered_signature_xml(source_bytes, rule_ids)

    upload_ok, upload_error = upload_system_file(nsip, token, SIGNATURE_UPLOAD_LOCATION, filename, filtered_xml)
    if not upload_ok:
        message = f'Fehler beim Hochladen der Signaturdatei für "{name}": {upload_error}'
        return jsonify({'success': False, 'message': message})

    import_ok, import_error = import_appfw_signature_from_file(nsip, token, SIGNATURE_UPLOAD_LOCATION, filename, name)
    matched = sum(1 for cve in category['cves'] if cve['rule_ids'])
    total = len(category['cves'])
    if not import_ok:
        if import_error and 'exist' in import_error.lower():
            message = (f'Signatur-Objekt "{name}" existiert bereits ({import_error}) - bitte einen anderen '
                      'Kategorie-Namen wählen oder das bestehende Objekt zuerst löschen. Die Datei wurde '
                      f'unter {SIGNATURE_UPLOAD_LOCATION}/{filename} auf dem NetScaler hochgeladen und kann '
                      'bei Bedarf dort manuell entfernt werden.')
        else:
            message = f'Fehler beim Erstellen des Signatur-Objekts "{name}": {import_error}'
        return jsonify({'success': False, 'message': message})

    message = (f'Signatur-Objekt "{name}" auf dem NetScaler erstellt, mit {enabled_count} Regeln aktiviert '
              f'({matched} von {total} CVEs dieser Kategorie hatten eine passende Regel). Kann jetzt wie jedes '
              'andere Signatur-Objekt in der "Signaturen"-Sektion einem Profil zugewiesen werden.')
    return jsonify({'success': True, 'message': message})


@app.route('/objects/signatures/<signature_name>/delete', methods=['POST'])
def delete_signature_object(signature_name):
    """
    Löscht ein echtes Signatur-Objekt auf dem NetScaler (DELETE
    appfwsignatures/<name>) - nur, solange kein Profil dieses Objekt
    aktuell referenziert (appfwprofile.signatures). Das wird hier VORAB
    geprüft (klare eigene Fehlermeldung) und ist kein Ersatz für die
    Prüfung, die NetScaler selbst ohnehin vornimmt.
    """
    if 'auth_token' not in session:
        return jsonify({'success': False, 'message': 'Sitzung abgelaufen. Bitte erneut anmelden.'}), 401
    if not signature_name or not OBJECT_NAME_RE.match(signature_name):
        return jsonify({'success': False, 'message': 'Kein (gültiger) Signatur-Name angegeben.'}), 400

    nsip = session.get('nsip')
    token = session.get('auth_token')

    bound_profiles = [p.get('name') for p in get_waf_profiles(nsip, token) if p.get('signatures') == signature_name]
    if bound_profiles:
        return jsonify({'success': False, 'message': (
            f'Signatur "{signature_name}" ist noch {len(bound_profiles)} Profil(en) zugewiesen '
            f'({", ".join(bound_profiles)}) und kann deshalb nicht gelöscht werden. Zuerst die '
            'Zuweisung im Profil ändern oder entfernen.')}), 400

    ok, error = delete_appfw_signature_object(nsip, token, signature_name)
    if ok:
        return jsonify({'success': True, 'message': f'Signatur "{signature_name}" gelöscht.'})
    message = f'Fehler beim Löschen der Signatur "{signature_name}": {error}'
    return jsonify({'success': False, 'message': message})


@app.route('/objects')
def objects():
    """
    Objekte-Seite: liest VServer (LB+CS), deren Backends (Service/
    ServiceGroup) und gebundene AppFW-Policies - Grundlage fuer die
    spaetere, objektbezogene Regel-Erstellung. Aktuell rein lesend.
    """
    if 'auth_token' not in session:
        flash('Bitte zuerst anmelden.', 'warning')
        return redirect(url_for('login'))

    nsip = session.get('nsip')
    token = session.get('auth_token')
    all_profiles = [p for p in get_waf_profiles(nsip, token) if p.get('name')]
    # Nur Custom-Profile werden als ziehbare Karten angezeigt (siehe Dashboard-
    # Aufteilung); für die Auflösung "existiert das Profil einer Policy?" in
    # _build_vserver_objects wird trotzdem die VOLLSTÄNDIGE Liste gebraucht,
    # sonst würde eine Policy auf einem Default-Profil fälschlich als
    # "nicht gefunden" markiert.
    profiles = sorted(
        [p for p in all_profiles if p['name'] not in DEFAULT_PROFILE_NAMES],
        key=lambda p: p['name']
    )
    vservers = _build_vserver_objects(nsip, token, all_profiles)
    all_signatures = get_appfw_signature_objects(nsip, token)
    # Eingebaute Signatur-Sets (Name beginnt mit "*", z.B. "*Default
    # Signatures") werden wie die Default-Profile nicht als eigene Karte
    # angezeigt - nur eigene/importierte Signatur-Objekte.
    custom_signatures = sorted(
        [sig for sig in all_signatures if sig.get('name') and not sig.get('is_default')],
        key=lambda sig: sig['name']
    )
    signature_objects = [sig['name'] for sig in custom_signatures]

    signature_categories = signature_db.list_categories()
    assignments_by_profile = signature_db.list_assignments_by_profile()
    for profile in profiles:
        profile['_pending_categories'] = assignments_by_profile.get(profile['name'], [])
    signature_rules_meta = signature_db.get_signature_rules_meta()

    return render_template(
        'objects.html',
        active_page='objects',
        nsip=nsip,
        username=session.get('username'),
        vservers=vservers,
        vserver_count=len(vservers),
        profiles=profiles,
        profile_count=len(profiles),
        signature_objects=signature_objects,
        signatures=custom_signatures,
        signature_count=len(custom_signatures),
        signature_categories=signature_categories,
        signature_category_presets=sorted(SIGNATURE_CATEGORY_PRESETS.keys()),
        signature_rules_meta=signature_rules_meta,
        default_signature_file_url=DEFAULT_SIGNATURE_FILE_URL,
    )


PROFILE_DEFAULTS_VALUES = {'basic', 'advanced', 'core', 'cve'}
PROFILE_TYPE_VALUES = {'HTML', 'XML', 'HTML XML'}


@app.route('/objects/assign-signature', methods=['POST'])
def objects_assign_signature():
    """
    Drag-and-drop-Zielaktion: weist ein Signatur-Objekt einem Profil zu
    ("set appfw profile <name> -signatures <signatur>"). Anders als beim
    Binden eines Profils an einen VServer ist das EIN einzelner
    Schreibaufruf (keine Policy nötig) und wirkt auf jeden Request über
    dieses Profil.
    """
    if 'auth_token' not in session:
        return jsonify({'success': False, 'message': 'Sitzung abgelaufen. Bitte erneut anmelden.'}), 401

    payload = request.get_json(silent=True) or {}
    profile_name = (payload.get('profile_name') or '').strip()
    signature_name = (payload.get('signature_name') or '').strip()

    def bad_request(message):
        return jsonify({'success': False, 'message': message}), 400

    if not profile_name or not OBJECT_NAME_RE.match(profile_name):
        return bad_request('Kein (gültiges) Profil angegeben.')
    if not signature_name or not OBJECT_NAME_RE.match(signature_name):
        return bad_request('Kein (gültiges) Signatur-Objekt angegeben.')

    nsip = session.get('nsip')
    token = session.get('auth_token')

    known_profiles = {p.get('name') for p in get_waf_profiles(nsip, token)}
    if profile_name not in known_profiles:
        return bad_request(f'Profil "{profile_name}" existiert nicht (mehr) auf dem NetScaler.')
    known_signatures = {sig.get('name') for sig in get_appfw_signature_objects(nsip, token)}
    if signature_name not in known_signatures:
        return bad_request(f'Signatur-Objekt "{signature_name}" existiert nicht (mehr) auf dem NetScaler.')

    ok = update_appfw_profile(nsip, token, profile_name, {'signatures': signature_name})
    if ok:
        message = f'Signatur "{signature_name}" dem Profil "{profile_name}" zugewiesen.'
    else:
        message = f'Fehler beim Zuweisen der Signatur "{signature_name}" zu Profil "{profile_name}".'
    return jsonify({'success': ok, 'message': message})


@app.route('/objects/create-profile', methods=['POST'])
def objects_create_profile():
    """
    Legt ein neues, eigenes AppFW-Profil an (Objekte-Seite, "+ Add"-Karte).
    Bis zu drei nacheinander ausgeführte Schritte, jeder unabhängig
    fehlschlagbar - die Meldung listet transparent, was gesetzt wurde und
    was nicht, statt bei einem Teilfehler den Rest zu verschleigen:
      1. add appfw profile <name> -defaults <defaults>   (Pflicht)
      2. set appfw profile <name> -type <type>           (optional)
      3. set appfw profile <name> -signatures <signature> (optional, muss
         auf ein vorhandenes Signature-Objekt zeigen)
    Security-Check-Aktionen (Learning/Block/Log/Stat) werden hier bewusst
    NICHT konfiguriert - dafür gibt es bereits die editierbaren Kästchen
    auf der Dashboard-Seite; das neue Profil landet dort mit den durch
    "defaults" vorgegebenen Standardwerten.
    """
    if 'auth_token' not in session:
        return jsonify({'success': False, 'message': 'Sitzung abgelaufen. Bitte erneut anmelden.'}), 401

    payload = request.get_json(silent=True) or {}
    profile_name = (payload.get('name') or '').strip()
    defaults = (payload.get('defaults') or '').strip().lower()
    profile_type = (payload.get('type') or '').strip()
    signature = (payload.get('signature') or '').strip()
    comment = (payload.get('comment') or '').strip()

    def bad_request(message):
        return jsonify({'success': False, 'message': message}), 400

    if not profile_name or not OBJECT_NAME_RE.match(profile_name):
        return bad_request('Kein (gültiger) Profilname angegeben.')
    if profile_name in DEFAULT_PROFILE_NAMES:
        return bad_request(f'"{profile_name}" ist der Name eines Default-Profils und nicht erlaubt.')
    if defaults not in PROFILE_DEFAULTS_VALUES:
        return bad_request(f'Ungültiger Wert für "Defaults": {defaults or "(leer)"}')
    if profile_type and profile_type not in PROFILE_TYPE_VALUES:
        return bad_request(f'Ungültiger Profiltyp: {profile_type}')
    if comment and len(comment) > 255:
        return bad_request('Kommentar zu lang.')
    if signature and not OBJECT_NAME_RE.match(signature):
        return bad_request(f'Ungültiger Signatur-Objektname: {signature}')

    nsip = session.get('nsip')
    token = session.get('auth_token')

    if signature:
        known_signatures = {s.get('name') for s in get_appfw_signature_objects(nsip, token)}
        if signature not in known_signatures:
            return bad_request(f'Signatur-Objekt "{signature}" existiert nicht auf dem NetScaler.')

    steps = []  # (Label, ok, error)
    create_ok, create_error = add_appfw_profile(nsip, token, profile_name, defaults, comment=comment or None)
    steps.append(('Profil angelegt', create_ok, create_error))

    if not create_ok:
        if create_error and 'exist' in create_error.lower():
            message = f'Profil "{profile_name}" existiert bereits ({create_error}).'
        else:
            message = f'Fehler beim Anlegen des Profils "{profile_name}": {create_error}'
        return jsonify({'success': False, 'message': message})

    if profile_type:
        type_ok = update_appfw_profile(nsip, token, profile_name, {'type': profile_type})
        steps.append((f'Typ "{profile_type}" gesetzt', type_ok, None if type_ok else 'Schreibfehler'))

    if signature:
        sig_ok = update_appfw_profile(nsip, token, profile_name, {'signatures': signature})
        steps.append((f'Signatur "{signature}" zugewiesen', sig_ok, None if sig_ok else 'Schreibfehler'))

    failed = [f'{label} ({error})' if error else label for label, ok, error in steps if not ok]
    done = [label for label, ok, _ in steps if ok]
    if failed:
        message = (f'Profil "{profile_name}" teilweise konfiguriert - erledigt: {", ".join(done)}; '
                  f'fehlgeschlagen: {", ".join(failed)}. Die restlichen Einstellungen können am Profil '
                  'in der NetScaler-GUI nachgeholt werden.')
        return jsonify({'success': False, 'message': message})

    message = f'Profil "{profile_name}" angelegt ({", ".join(done)}).'
    return jsonify({'success': True, 'message': message})



@app.route('/analysis')
def analysis():
    if 'auth_token' not in session:
        flash('Bitte zuerst anmelden.', 'warning')
        return redirect(url_for('login'))

    nsip = session.get('nsip')
    token = session.get('auth_token')

    entries, log_error = load_appfw_log_entries(nsip, token)

    return render_template(
        'analysis.html',
        active_page='analysis',
        nsip=nsip,
        username=session.get('username'),
        entries=entries,
        log_error=log_error,
        poll_intervals=[{'seconds': p['seconds'], 'label': translate(g.locale, p['label_key'])}
                       for p in POLL_INTERVALS],
        log_filename=NS_LOG_FILENAME,
    )


@app.route('/analysis/data')
def analysis_data():
    """
    Liefert das HTML-Fragment mit den aktuellen Log-Einträgen zurück
    (für das periodische Nachladen per JS - siehe static/js/analysis.js).
    Es wird bewusst dasselbe Partial wie beim initialen Laden gerendert,
    damit Markup und Darstellung nicht doppelt gepflegt werden müssen.
    """
    if 'auth_token' not in session:
        return render_template(
            'partials/_log_list.html',
            log_error='Sitzung abgelaufen. Bitte erneut anmelden.',
            entries=[],
            log_filename=NS_LOG_FILENAME,
        ), 401

    nsip = session.get('nsip')
    token = session.get('auth_token')
    entries, log_error = load_appfw_log_entries(nsip, token)

    return render_template(
        'partials/_log_list.html',
        entries=entries,
        log_error=log_error,
        log_filename=NS_LOG_FILENAME,
    )


@app.route('/analysis/buffer-overflow/relax', methods=['POST'])
def buffer_overflow_relax():
    """
    Erhoeht einen Buffer-Overflow-Schwellenwert (Max URL/Header/Cookie
    Length) im betroffenen Profil auf den vom Log gemeldeten Wert - das
    Aequivalent zu NetScalers eigenem "Click-to-Deploy"-Feature.
    Wird von einem "Blocked"-Treffer ausgeloest; das Profil hat Block also
    bereits aktiv, es wird nur der Schwellenwert angepasst.
    """
    if 'auth_token' not in session:
        return jsonify({'success': False, 'message': 'Sitzung abgelaufen. Bitte erneut anmelden.'}), 401

    payload = request.get_json(silent=True) or {}
    profile_name = (payload.get('profile') or '').strip()
    field = (payload.get('field') or '').strip()
    value = payload.get('value')

    if not profile_name:
        return jsonify({'success': False, 'message': 'Kein Profil angegeben.'}), 400
    if field not in BUFFER_OVERFLOW_FIELD_LABELS:
        return jsonify({'success': False, 'message': f'Unbekanntes Feld: {field}'}), 400
    try:
        value = int(value)
    except (TypeError, ValueError):
        return jsonify({'success': False, 'message': 'Ungueltiger Wert.'}), 400
    if not (0 < value <= 65535):
        return jsonify({'success': False, 'message': 'Wert außerhalb des zulässigen Bereichs (1-65535).'}), 400

    nsip = session.get('nsip')
    token = session.get('auth_token')
    success = update_appfw_profile(nsip, token, profile_name, {field: value})

    field_label = BUFFER_OVERFLOW_FIELD_LABELS.get(field, field)
    if success:
        message = f'{field_label} in Profil "{profile_name}" auf {value} gesetzt.'
    else:
        message = f'Fehler beim Aktualisieren von {field_label} in Profil "{profile_name}".'

    return jsonify({'success': success, 'message': message})


@app.route('/analysis/buffer-overflow/activate', methods=['POST'])
def buffer_overflow_activate():
    """
    Aktiviert 'block' fuer den Buffer-Overflow-Check im betroffenen Profil,
    unter Beibehaltung bereits vorhandener Aktionen (z.B. log/stats). Wird
    von einem "Not Blocked"-Treffer ausgeloest; Schwellenwerte werden dabei
    bewusst NICHT veraendert, da das den gerade erkannten Verstoss wieder
    unter den Schwellenwert setzen und ihn dadurch wieder Not-Blocked
    machen wuerde.
    """
    if 'auth_token' not in session:
        return jsonify({'success': False, 'message': 'Sitzung abgelaufen. Bitte erneut anmelden.'}), 401

    payload = request.get_json(silent=True) or {}
    profile_name = (payload.get('profile') or '').strip()
    if not profile_name:
        return jsonify({'success': False, 'message': 'Kein Profil angegeben.'}), 400

    nsip = session.get('nsip')
    token = session.get('auth_token')

    profile = get_appfw_profile(nsip, token, profile_name)
    if profile is None:
        return jsonify({
            'success': False,
            'message': f'Profil "{profile_name}" konnte nicht gelesen werden.'
        }), 502

    current_tokens = parse_action_tokens(profile.get('bufferoverflowaction'))
    current_tokens = [t for t in current_tokens if t != 'none']
    if 'block' not in current_tokens:
        current_tokens.append('block')

    success = update_appfw_profile(nsip, token, profile_name, {'bufferoverflowaction': current_tokens})

    if success:
        message = f'Block für Buffer Overflow in Profil "{profile_name}" aktiviert (Aktionen: {", ".join(current_tokens)}).'
    else:
        message = f'Fehler beim Aktivieren von Block in Profil "{profile_name}".'

    return jsonify({'success': success, 'message': message})


@app.route('/analysis/starturl/relax', methods=['POST'])
def starturl_relax():
    """
    Fügt die vom Nutzer bestätigte URL (bzw. den daraus abgeleiteten Regex)
    als neue Start-URL-Relaxation-Regel zum betroffenen Profil hinzu.
    Anders als bei Buffer Overflow ist das hier eine echte, auf genau
    diese URL beschränkte Ausnahme (appfwprofile_starturl_binding), kein
    profilweiter Schwellenwert.
    """
    if 'auth_token' not in session:
        return jsonify({'success': False, 'message': 'Sitzung abgelaufen. Bitte erneut anmelden.'}), 401

    payload = request.get_json(silent=True) or {}
    profile_name = (payload.get('profile') or '').strip()
    pattern = (payload.get('pattern') or '').strip()

    if not profile_name:
        return jsonify({'success': False, 'message': 'Kein Profil angegeben.'}), 400
    if not pattern:
        return jsonify({'success': False, 'message': 'Kein Muster angegeben.'}), 400
    if len(pattern) > 2048:
        return jsonify({'success': False, 'message': 'Muster zu lang.'}), 400

    nsip = session.get('nsip')
    token = session.get('auth_token')
    success = add_appfw_starturl_binding(
        nsip, token, profile_name, pattern,
        comment='Über WAF Monitor Analysis hinzugefügt'
    )

    if success:
        message = f'Start-URL-Regel für Profil "{profile_name}" hinzugefügt: {pattern}'
    else:
        message = f'Fehler beim Hinzufügen der Start-URL-Regel in Profil "{profile_name}".'

    return jsonify({'success': success, 'message': message})


# Erlaubte Fundorte je SQL-Regeltyp (Whitelist für die Eingabevalidierung).
SQL_RELAX_LOCATIONS = {
    'html': {'FORMFIELD', 'HEADER', 'COOKIE'},
    'xml': {'ELEMENT', 'ATTRIBUTE'},
}
SQL_RELAX_COMMENT = 'Über WAF Monitor Analysis hinzugefügt'
SQL_RELAX_MAX_TOKENS = 20
SQL_RELAX_MAX_TOKEN_LENGTH = 256


def _validate_relax_tokens(raw_tokens, allowed_types):
    """Prüft die vom Browser gesendeten Muster. Gibt (tokens, None) mit einer
    duplikatfreien Liste von (Typ, Wert) zurück oder (None, Fehlermeldung)."""
    if not isinstance(raw_tokens, list) or not raw_tokens:
        return None, 'Kein Muster zur Freigabe angegeben.'
    if len(raw_tokens) > SQL_RELAX_MAX_TOKENS:
        return None, f'Zu viele Muster (maximal {SQL_RELAX_MAX_TOKENS}).'
    tokens = []
    for item in raw_tokens:
        item = item if isinstance(item, dict) else {}
        token_type = (item.get('type') or '').strip()
        token_value = item.get('value')
        if token_type not in allowed_types:
            return None, f'Ungültiger Mustertyp: {token_type or "(leer)"}'
        if not isinstance(token_value, str) or token_value == '':
            return None, 'Ein Muster ist leer.'
        if len(token_value) > SQL_RELAX_MAX_TOKEN_LENGTH:
            return None, 'Ein Muster ist zu lang.'
        if (token_type, token_value) not in tokens:
            tokens.append((token_type, token_value))
    return tokens, None


def _create_token_rules(nsip, auth_token, profile_name, field, location, url_pattern, tokens,
                        add_binding, check_label):
    """Legt je Token eine fein granulare Regel an (add_binding = NITRO-Funktion
    des jeweiligen Checks) und fasst das Ergebnis zusammen. Bereits vorhandene
    identische Regeln zählen als erledigt (nicht als Fehler); bei Teilerfolg wird
    genau benannt, was angelegt wurde und was nicht - ein erneuter Klick ist
    gefahrlos."""
    created, existing, failed = [], [], []
    for token_type, token_value in tokens:
        label = f'{token_type} „{token_value}“'
        ok, error = add_binding(
            nsip, auth_token, profile_name, field, url_pattern, location=location,
            value_type=token_type, value_expr=token_value, comment=SQL_RELAX_COMMENT)
        if ok:
            created.append(label)
        elif error and 'exist' in error.lower():
            existing.append(label)
        else:
            failed.append(f'{label} ({error})')

    target = f'{field} ({location}) auf {url_pattern}'
    parts = []
    if created:
        parts.append('angelegt: ' + ', '.join(created))
    if existing:
        parts.append('bereits vorhanden: ' + ', '.join(existing))
    if failed:
        parts.append('FEHLER: ' + '; '.join(failed))
    summary = '; '.join(parts)
    if failed:
        message = f'{check_label}-Regeln für Profil "{profile_name}" ({target}) nur teilweise angelegt - {summary}'
        return jsonify({'success': False, 'message': message})
    message = f'{check_label}-Regeln für Profil "{profile_name}" ({target}): {summary}'
    return jsonify({'success': True, 'message': message})


def _relax_html_sql_tokens(nsip, auth_token, profile_name, field, location, url_pattern, tokens):
    return _create_token_rules(nsip, auth_token, profile_name, field, location, url_pattern, tokens,
                               add_appfw_sqlinjection_binding, 'SQL-Injection')


@app.route('/analysis/sql-injection/relax', methods=['POST'])
def sql_injection_relax():
    """
    Legt für einen geblockten SQL-Injection-Treffer eine Relaxation Rule an
    (false positive). Je nach kind:
      html - Feldname + Form-Action-URL (nur diese Seite) + EINZELNE Muster
             (tokens: Keyword/SpecialString/Wildchar, je Token eine Regel);
             alle anderen SQL-Muster werden weiter geprüft
      xml  - Element/Attribut, PROFILWEIT (NetScaler kennt hier keine URL)
      json - URL-basiert, gilt für alle Keys dieser URL
    """
    if 'auth_token' not in session:
        return jsonify({'success': False, 'message': 'Sitzung abgelaufen. Bitte erneut anmelden.'}), 401

    payload = request.get_json(silent=True) or {}
    profile_name = (payload.get('profile') or '').strip()
    kind = (payload.get('kind') or '').strip().lower()
    field = (payload.get('field') or '').strip()
    location = (payload.get('location') or '').strip().upper()
    url_pattern = (payload.get('url_pattern') or '').strip()
    raw_tokens = payload.get('tokens')

    def bad_request(message):
        return jsonify({'success': False, 'message': message}), 400

    if not profile_name or len(profile_name) > 256:
        return bad_request('Kein (gültiges) Profil angegeben.')
    if kind not in ('html', 'xml', 'json'):
        return bad_request(f'Unbekannter Regeltyp: {kind or "(leer)"}')
    if len(field) > 512:
        return bad_request('Feldname zu lang.')
    if len(url_pattern) > 2048:
        return bad_request('Muster zu lang.')

    if kind in SQL_RELAX_LOCATIONS:
        if not field:
            return bad_request('Kein Feld-/Elementname angegeben.')
        if location not in SQL_RELAX_LOCATIONS[kind]:
            return bad_request(f'Ungültiger Fundort: {location or "(leer)"}')
    if kind in ('html', 'json') and not url_pattern:
        return bad_request('Keine URL angegeben.')

    tokens = []
    if kind == 'html':
        tokens, token_error = _validate_relax_tokens(raw_tokens, SQL_TOKEN_TYPES)
        if token_error:
            return bad_request(token_error)

    nsip = session.get('nsip')
    token = session.get('auth_token')

    if kind == 'html':
        return _relax_html_sql_tokens(nsip, token, profile_name, field, location, url_pattern, tokens)
    elif kind == 'xml':
        success, error = add_appfw_xmlsqlinjection_binding(
            nsip, token, profile_name, field,
            location=location, comment=SQL_RELAX_COMMENT)
        target = f'{field} ({location}), profilweit'
    else:
        success, error = add_appfw_jsonsqlurl_binding(
            nsip, token, profile_name, url_pattern, comment=SQL_RELAX_COMMENT)
        target = f'alle Keys auf {url_pattern}'

    if success:
        message = f'SQL-Injection-Regel für Profil "{profile_name}" hinzugefügt: {target}'
        return jsonify({'success': True, 'message': message})

    if error and 'exist' in error.lower():
        message = (f'Für Profil "{profile_name}" existiert bereits eine passende Regel ({error}). '
                   'Wird der Request trotzdem blockiert, passen URL bzw. Feldname der '
                   'bestehenden Regel nicht - bitte im Profil prüfen.')
    else:
        message = f'Fehler beim Hinzufügen der SQL-Injection-Regel in Profil "{profile_name}": {error}'
    return jsonify({'success': False, 'message': message})


# Erlaubte Fundorte für Command-Injection-Relaxations (HTML).
CMD_RELAX_LOCATIONS = {'FORMFIELD', 'HEADER', 'COOKIE'}


# Von NetScaler vorgegebene Werte der drei Cookie-Transform-Einstellungen
# (set appfw profile -cookieEncryption/-cookieProxying/-addCookieFlags).
COOKIE_ENCRYPTION_VALUES = {'none', 'decryptOnly', 'encryptSessionOnly', 'encryptAll'}
COOKIE_PROXYING_VALUES = {'none', 'sessionOnly'}
# ANNAHME: addCookieFlags kennt neben den drei vom Nutzer genannten Werten
# zusätzlich "none" (kein Flag setzen) - wie bei den anderen beiden
# Einstellungen ist das der NetScaler-Default und wird mit aufgenommen,
# damit die Auswahl vollständig der echten Profil-Einstellung entspricht.
COOKIE_FLAGS_VALUES = {'none', 'httpOnly', 'secure', 'all'}


# Token-Namen, wie NetScaler sie in *action-Feldern erwartet (siehe CLI-Doku,
# z.B. "set appfw profile -startURLaction block learn log stats"). Das
# UI-Kästchen "Stat" sendet/erwartet das NITRO-Token "stats" (Plural).
CHECK_ACTION_TOKENS = {'block', 'learn', 'log', 'stats'}


@app.route('/profile/<profile_name>/check/<check_key>/action', methods=['POST'])
def profile_check_action(profile_name, check_key):
    """
    Setzt Learning/Block/Log/Stat für EINEN Security Check eines Profils neu
    (z.B. "sqlinjectionaction"). check_key ist der Feld-Präfix wie ihn
    profile_parser.structure_profile_checks() liefert (z.B. "sqlinjection");
    das Feld wird gegen CHECK_LABELS geprüft, damit nicht auf beliebige
    Profilfelder geschrieben werden kann.

    Sendet der Nutzer keine der vier Aktionen, wird laut NetScaler-Doku
    explizit "none" gesetzt (nicht eine leere Liste) - so schaltet man einen
    Check laut CLI-Referenz korrekt komplett aus.

    ACHTUNG (wird auch im Dialog/README erläutert): Nicht jeder Check
    unterstützt "Learning" (z.B. Buffer Overflow, Deny URL, Command
    Injection kennen laut Doku nur Block/Log/Stats). Diese App hält dafür
    keine eigene, möglicherweise unvollständige Positivliste - NetScaler
    validiert das selbst; eine ungültige Kombination kommt als Fehler von
    NITRO zurück und wird 1:1 angezeigt, es wird nichts stillschweigend
    weggelassen.
    """
    if 'auth_token' not in session:
        return jsonify({'success': False, 'message': 'Sitzung abgelaufen. Bitte erneut anmelden.'}), 401

    if check_key not in CHECK_LABELS:
        return jsonify({'success': False, 'message': f'Unbekannter Security Check: {check_key}'}), 400
    if not profile_name or len(profile_name) > 256:
        return jsonify({'success': False, 'message': 'Kein (gültiges) Profil angegeben.'}), 400

    payload = request.get_json(silent=True) or {}
    raw_tokens = payload.get('tokens')
    if not isinstance(raw_tokens, list):
        return jsonify({'success': False, 'message': 'Ungültige Liste der Aktionen.'}), 400
    tokens = []
    for item in raw_tokens:
        token = str(item).strip().lower()
        if token not in CHECK_ACTION_TOKENS:
            return jsonify({'success': False, 'message': f'Ungültige Aktion: {item}'}), 400
        if token == 'learn' and check_key in CHECKS_WITHOUT_LEARN:
            return jsonify({'success': False, 'message': (
                f'"{CHECK_LABELS.get(check_key, check_key)}" unterstützt kein Learning '
                '(nur Block/Log/Stats laut NetScaler).')}), 400
        if token not in tokens:
            tokens.append(token)

    action_field = check_key + 'action'
    field_value = tokens if tokens else ['none']

    nsip = session.get('nsip')
    token = session.get('auth_token')
    success = update_appfw_profile(nsip, token, profile_name, {action_field: field_value})

    label = CHECK_LABELS.get(check_key, check_key)
    if success:
        shown = ', '.join(tokens) if tokens else 'none (Check deaktiviert)'
        message = f'"{label}" in Profil "{profile_name}" aktualisiert: {shown}'
    else:
        message = (f'Fehler beim Aktualisieren von "{label}" in Profil "{profile_name}". '
                  'Möglich, dass dieser Check nicht alle gewählten Aktionen unterstützt '
                  '(z.B. kein Learning) - Details ggf. im NetScaler-Log.')
    return jsonify({'success': success, 'message': message})


@app.route('/analysis/cookie-consistency/transform', methods=['POST'])
def cookie_consistency_transform():
    """
    Stellt den Cookie-Consistency-Check eines Profils von 'block' auf
    'transform' um: block wird aus der Action entfernt, cookieTransforms
    aktiviert und die drei vom Nutzer gewählten Einstellungen (Encrypt
    Server Cookies / Proxy Server Cookies / Flags to add in Cookies)
    gesetzt. PROFILWEITE Änderung - wirkt auf jeden Request über dieses
    Profil, nicht nur auf den Treffer, der den Button ausgelöst hat.
    """
    if 'auth_token' not in session:
        return jsonify({'success': False, 'message': 'Sitzung abgelaufen. Bitte erneut anmelden.'}), 401

    payload = request.get_json(silent=True) or {}
    profile_name = (payload.get('profile') or '').strip()
    cookie_encryption = (payload.get('cookie_encryption') or '').strip()
    cookie_proxying = (payload.get('cookie_proxying') or '').strip()
    add_cookie_flags = (payload.get('add_cookie_flags') or '').strip()

    if not profile_name or len(profile_name) > 256:
        return jsonify({'success': False, 'message': 'Kein (gültiges) Profil angegeben.'}), 400
    if cookie_encryption not in COOKIE_ENCRYPTION_VALUES:
        return jsonify({'success': False, 'message': f'Ungültiger Wert für Encrypt Server Cookies: {cookie_encryption or "(leer)"}'}), 400
    if cookie_proxying not in COOKIE_PROXYING_VALUES:
        return jsonify({'success': False, 'message': f'Ungültiger Wert für Proxy Server Cookies: {cookie_proxying or "(leer)"}'}), 400
    if add_cookie_flags not in COOKIE_FLAGS_VALUES:
        return jsonify({'success': False, 'message': f'Ungültiger Wert für Flags to add in Cookies: {add_cookie_flags or "(leer)"}'}), 400

    nsip = session.get('nsip')
    token = session.get('auth_token')
    success, tokens, had_block = set_cookie_consistency_transform(
        nsip, token, profile_name, cookie_encryption, cookie_proxying, add_cookie_flags)

    if success:
        remaining = ('Aktionen jetzt: ' + ', '.join(tokens)) if tokens else 'keine weiteren Aktionen (Log/Stats) aktiv'
        action_note = 'auf Transform umgestellt (Block entfernt)' if had_block else 'Transform-Einstellungen gesetzt (Block war nicht aktiv)'
        message = (f'Cookie Consistency in Profil "{profile_name}" {action_note} '
                  f'(Encrypt: {cookie_encryption}, Proxy: {cookie_proxying}, Flags: {add_cookie_flags}; {remaining}).')
    else:
        message = f'Fehler beim Ändern von Profil "{profile_name}" (nicht lesbar oder Schreibfehler).'
    return jsonify({'success': success, 'message': message})


CSRF_RELAX_COMMENT = 'Über WAF Monitor Analysis hinzugefügt'


@app.route('/analysis/csrf-tag/relax', methods=['POST'])
def csrf_tag_relax():
    """
    Legt für einen geblockten CSRF-Form-Tagging-Treffer eine Relaxation Rule
    an: appfwprofile_csrftag_binding mit Form-Origin-URL UND Form-Action-URL
    (beide Pflichtfelder bei diesem Check). Gilt nur für diese Kombination,
    nicht profilweit.
    """
    if 'auth_token' not in session:
        return jsonify({'success': False, 'message': 'Sitzung abgelaufen. Bitte erneut anmelden.'}), 401

    payload = request.get_json(silent=True) or {}
    profile_name = (payload.get('profile') or '').strip()
    origin_pattern = (payload.get('origin_pattern') or '').strip()
    action_pattern = (payload.get('action_pattern') or '').strip()

    if not profile_name or len(profile_name) > 256:
        return jsonify({'success': False, 'message': 'Kein (gültiges) Profil angegeben.'}), 400
    if not origin_pattern:
        return jsonify({'success': False, 'message': 'Keine Form-Origin-URL angegeben.'}), 400
    if not action_pattern:
        return jsonify({'success': False, 'message': 'Keine Form-Action-URL angegeben.'}), 400
    if len(origin_pattern) > 2048 or len(action_pattern) > 2048:
        return jsonify({'success': False, 'message': 'Muster zu lang.'}), 400
    if '?' in action_pattern:
        return jsonify({'success': False, 'message': (
            'Die Form-Action-URL darf laut NetScaler keinen Query-String enthalten '
            '(führt sonst zu einem Fehler beim Anlegen der Regel). Bitte das "?" und alles '
            'danach aus dem Muster entfernen.')}), 400

    nsip = session.get('nsip')
    token = session.get('auth_token')
    success, error = add_appfw_csrftag_binding(
        nsip, token, profile_name, origin_pattern, action_pattern, comment=CSRF_RELAX_COMMENT)

    if success:
        message = f'CSRF-Form-Tagging-Regel für Profil "{profile_name}" hinzugefügt: {origin_pattern} → {action_pattern}'
        return jsonify({'success': True, 'message': message})

    if error and 'exist' in error.lower():
        message = (f'Für Profil "{profile_name}" existiert bereits eine passende CSRF-Regel ({error}). '
                   'Wird der Request trotzdem blockiert, passen Origin- bzw. Action-URL der '
                   'bestehenden Regel nicht - bitte im Profil prüfen.')
    else:
        message = f'Fehler beim Hinzufügen der CSRF-Regel in Profil "{profile_name}": {error}'
    return jsonify({'success': False, 'message': message})


@app.route('/analysis/cmd-injection/relax', methods=['POST'])
def cmd_injection_relax():
    """
    Legt für einen geblockten Command-Injection-Treffer (HTML) fein granulare
    Relaxation Rules an: je Muster (Keyword/SpecialString) eine Regel, gebunden an
    Feldname + Form-Action-URL. Alle anderen Muster werden weiter geprüft.
    """
    if 'auth_token' not in session:
        return jsonify({'success': False, 'message': 'Sitzung abgelaufen. Bitte erneut anmelden.'}), 401

    payload = request.get_json(silent=True) or {}
    profile_name = (payload.get('profile') or '').strip()
    field = (payload.get('field') or '').strip()
    location = (payload.get('location') or '').strip().upper()
    url_pattern = (payload.get('url_pattern') or '').strip()

    def bad_request(message):
        return jsonify({'success': False, 'message': message}), 400

    if not profile_name or len(profile_name) > 256:
        return bad_request('Kein (gültiges) Profil angegeben.')
    if not field:
        return bad_request('Kein Feldname angegeben.')
    if len(field) > 512:
        return bad_request('Feldname zu lang.')
    if location not in CMD_RELAX_LOCATIONS:
        return bad_request(f'Ungültiger Fundort: {location or "(leer)"}')
    if not url_pattern:
        return bad_request('Keine URL angegeben.')
    if len(url_pattern) > 2048:
        return bad_request('Muster zu lang.')

    tokens, token_error = _validate_relax_tokens(payload.get('tokens'), CMD_TOKEN_TYPES)
    if token_error:
        return bad_request(token_error)

    return _create_token_rules(session.get('nsip'), session.get('auth_token'), profile_name, field,
                               location, url_pattern, tokens, add_appfw_cmdinjection_binding,
                               'Command-Injection')


# Beispiel-URLs, um Deny-URL-Muster zu erkennen, die praktisch ALLES treffen
# (z.B. ".*", "http" oder "^/") und damit die gesamte Anwendung sperren würden.
# Zwei Darstellungen, weil unklar ist, ob NetScaler die URL mit Host oder nur den
# Pfad matcht: ein Muster gilt als zu allgemein, sobald es eine der beiden Mengen
# VOLLSTÄNDIG trifft.
DENY_URL_SAMPLE_SETS = (
    (   # URL mit Schema + Host
        'http://a.example.com/',
        'https://www.test.org/index.html',
        'http://10.0.0.1/some/path/file.php',
        'https://x.y/z',
    ),
    (   # nur Pfad
        '/',
        '/index.html',
        '/some/path/file.php',
        '/z',
    ),
)
DENY_URL_COMMENT = 'Über WAF Monitor Analysis hinzugefügt'


def _deny_pattern_too_broad(pattern):
    """True, wenn das Muster mindestens 3 von 4 Beispielen einer Darstellung trifft
    (= sperrt praktisch alles). Kann Python ein PCRE-Konstrukt nicht kompilieren, wird nicht geprüft -
    dann validiert NetScaler selbst."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')   # PCRE-Syntax löst in Python FutureWarnings aus
            regex = re.compile(pattern)
    except re.error:
        return False
    # "Fast alle" statt "alle": auch z.B. ^/.+ (alles außer "/") soll als zu allgemein gelten.
    return any(sum(1 for sample in sample_set if regex.search(sample)) >= 3 for sample_set in DENY_URL_SAMPLE_SETS)


def _deny_url_action_hint(nsip, token, profile_name):
    """Prüft nach dem Anlegen, ob der Deny-URL-Check im Profil überhaupt
    blockt. Ohne 'block' (oder mit 'none') hat die Regel keine abweisende
    Wirkung. Liefert einen Hinweistext oder '' (auch wenn das Profil nicht
    lesbar ist - der Hinweis ist nur eine Zusatzinformation)."""
    profile = get_appfw_profile(nsip, token, profile_name)
    if not profile:
        return ''
    tokens = parse_action_tokens(profile.get('denyurlaction'))
    if 'block' in tokens:
        return ''
    if not tokens or tokens == ['none']:
        return (' HINWEIS: Der Deny-URL-Check ist im Profil nicht aktiv (Aktion: none/nicht gesetzt) - '
                'die Regel hat erst nach Aktivierung von "block" eine abweisende Wirkung.')
    return (f' HINWEIS: Bei Deny URL ist im Profil nur "{", ".join(tokens)}" gesetzt, kein "block" - '
            'Zugriffe werden geloggt, aber nicht abgewiesen.')


@app.route('/analysis/deny-url/add', methods=['POST'])
def deny_url_add():
    """
    Legt für einen geloggten Aufruf (Policy Hit) eine Deny-URL-Regel im
    betroffenen Profil an: künftige Zugriffe auf URLs, die das (vom Nutzer
    bestätigte bzw. angepasste) Muster treffen, werden abgewiesen.
    """
    if 'auth_token' not in session:
        return jsonify({'success': False, 'message': 'Sitzung abgelaufen. Bitte erneut anmelden.'}), 401

    payload = request.get_json(silent=True) or {}
    profile_name = (payload.get('profile') or '').strip()
    pattern = payload.get('pattern')
    pattern = pattern.strip() if isinstance(pattern, str) else ''

    if not profile_name or len(profile_name) > 256:
        return jsonify({'success': False, 'message': 'Kein (gültiges) Profil angegeben.'}), 400
    if not pattern:
        return jsonify({'success': False, 'message': 'Kein Muster angegeben.'}), 400
    if len(pattern) > 2048:
        return jsonify({'success': False, 'message': 'Muster zu lang.'}), 400
    if _deny_pattern_too_broad(pattern):
        return jsonify({'success': False, 'message': (
            'Das Muster ist zu allgemein: Es würde beliebige URLs treffen und damit die gesamte '
            'Anwendung sperren. Bitte auf die gewünschte URL bzw. den Pfad eingrenzen.')}), 400

    nsip = session.get('nsip')
    token = session.get('auth_token')
    success, error = add_appfw_denyurl_binding(
        nsip, token, profile_name, pattern, comment=DENY_URL_COMMENT)

    if success:
        message = f'Deny-URL-Regel für Profil "{profile_name}" hinzugefügt: {pattern}'
        message += _deny_url_action_hint(nsip, token, profile_name)
        return jsonify({'success': True, 'message': message})

    if error and 'exist' in error.lower():
        message = (f'Die Deny-URL-Regel {pattern} existiert im Profil "{profile_name}" bereits ({error}). '
                   'Wird der Zugriff trotzdem nicht abgewiesen, ist im Profil die Deny-URL-Aktion '
                   '"block" nicht aktiv oder die Policy greift nicht.')
    else:
        message = f'Fehler beim Hinzufügen der Deny-URL-Regel in Profil "{profile_name}": {error}'
    return jsonify({'success': False, 'message': message})


@app.route('/logout')
def logout():
    session.pop('auth_token', None)
    session.pop('nsip', None)
    session.pop('username', None)
    flash('Sie wurden abgemeldet.', 'info')
    return redirect(url_for('login'))


@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error='Seite nicht gefunden'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error='Interner Server-Fehler'), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
