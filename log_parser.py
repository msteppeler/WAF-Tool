"""
Parser für NetScaler-Logzeilen im CEF-Format (Common Event Format).

Filtert aus dem Inhalt von ns.log ausschließlich AppFirewall(WAF)-Einträge
heraus und zerlegt jede Zeile in ein strukturiertes Dict.

Beispielzeile:
Sep 16 07:49:51 <local0.info> 192.168.123.150  CEF:0|Citrix|NetScaler|NS14.1|
APPFW|APPFW_XSS|6|src=... spt=... method=GET request=... msg=... cn1=275
cn2=153 cs1=WAF_Demo_Prof cs2=PPE0 cs3=... cs4=ALERT cs5=2026 act=blocked

Hinweis zu cn1/cn2/cs5: Citrix dokumentiert cs1 (Profil), cs2 (PPE),
cs3 (Transaktions-ID) und cs4 (Schweregrad) recht klar; die genaue
Bedeutung von cn1, cn2 und cs5 ist nicht zweifelsfrei belegt. Sie werden
daher unter ihrem rohen Feldnamen angezeigt, statt eine Bezeichnung zu
raten. Bei Bedarf hier in EXTENSION_LABELS ergänzen.
"""
import re
from urllib.parse import urlsplit

CEF_LINE_RE = re.compile(
    r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'<(?P<facility>[^>]+)>\s+'
    r'(?P<device_ip>\S+)\s+'
    r'CEF:(?P<cef_version>\d+)\|'
    r'(?P<vendor>[^|]*)\|'
    r'(?P<product>[^|]*)\|'
    r'(?P<device_version>[^|]*)\|'
    r'(?P<signature_id>[^|]*)\|'
    r'(?P<name>[^|]*)\|'
    r'(?P<severity>[^|]*)\|'
    r'(?P<extension>.*)$'
)

# CEF-Extension-Felder sind durch (unescapte) Leerzeichen getrennte
# key=value-Paare. Werte können Leerzeichen und escapte "=" (\=) enthalten.
EXTENSION_FIELD_RE = re.compile(r'(\w+)=((?:\\.|[^\\])*?)(?=(?:\s\w+=)|$)')

EXTENSION_LABELS = {
    'src': 'Quell-IP',
    'spt': 'Quell-Port',
    'dst': 'Ziel-IP',
    'dpt': 'Ziel-Port',
    'method': 'HTTP-Methode',
    'request': 'Request-URL',
    'msg': 'Meldung',
    'act': 'Aktion',
    'cs1': 'Profil',
    'cs2': 'PPE',
    'cs3': 'Transaktions-ID',
    'cs4': 'Schweregrad',
    'cn1': 'cn1',
    'cn2': 'cn2',
    'cs5': 'cs5',
}

# Bezeichnungen für den CEF-"Name"-Teil (entspricht dem AppFW-Check).
# Nicht gelistete Namen werden im Rohformat angezeigt.
CHECK_TYPE_LABELS = {
    'APPFW_XSS': 'Cross-Site Scripting (XSS)',
    'APPFW_SQL': 'SQL Injection',
    'APPFW_STARTURL': 'Start URL',
    'APPFW_DENYURL': 'Deny URL',
    'APPFW_COOKIE': 'Cookie Consistency',
    'APPFW_FIELDCONSISTENCY': 'Field Consistency',
    'APPFW_FIELDFORMAT': 'Field Format',
    'APPFW_BUFFEROVERFLOW': 'Buffer Overflow',
    'APPFW_BUFFEROVERFLOW_URL': 'Buffer Overflow (URL)',
    'APPFW_BUFFEROVERFLOW_QUERY': 'Buffer Overflow (Query String)',
    'APPFW_BUFFEROVERFLOW_COOKIE': 'Buffer Overflow (Cookie)',
    'APPFW_BUFFEROVERFLOW_HDR': 'Buffer Overflow (Header)',
    'APPFW_BUFFEROVERFLOW_TOTAL_HDR': 'Buffer Overflow (Header gesamt)',
    'APPFW_CSRF_TAG': 'CSRF Tagging',
    'APPFW_CONTENTTYPE': 'Content-Type',
    'APPFW_CREDITCARD': 'Kreditkarten-Schutz',
    'APPFW_XML_SQL': 'XML SQL Injection',
    'APPFW_JSON_SQL': 'JSON SQL Injection',
    'APPFW_CMD_INJECTION': 'Command Injection',
    'APPFW_JSON_CMD_INJECTION': 'JSON Command Injection',
    'APPFW_XML_XSS': 'XML Cross-Site Scripting',
    'APPFW_XML_WSI': 'XML WSI',
    'APPFW_XML_DOS': 'XML Denial of Service',
    'APPFW_SAFEOBJECT': 'Safe Object',
    'APPFW_POLICY_HIT': 'Policy Hit',
}

# Ordnet den granularen Buffer-Overflow-Event-Namen das NITRO-Profilfeld zu,
# das den jeweiligen Schwellenwert steuert. NetScaler kennt fuer diesen
# Check nur drei tatsaechliche Konfigurationsfelder (URL/Header/Cookie);
# "_QUERY" und "_TOTAL_HDR" sind feinere Event-Bezeichnungen (ab NS 13.x),
# OHNE eigenes Config-Feld. ANNAHME (nicht durch Citrix-Doku 1:1 belegt,
# aber naheliegend, da der Query-String Teil der URL ist):
# _QUERY -> bufferoverflowmaxurllength, _TOTAL_HDR -> bufferoverflowmaxheaderlength.
# Falls sich das bei euch als falsch herausstellt, hier korrigieren.
BUFFER_OVERFLOW_FIELD_MAP = {
    'APPFW_BUFFEROVERFLOW_URL': 'bufferoverflowmaxurllength',
    'APPFW_BUFFEROVERFLOW_QUERY': 'bufferoverflowmaxurllength',
    'APPFW_BUFFEROVERFLOW_COOKIE': 'bufferoverflowmaxcookielength',
    'APPFW_BUFFEROVERFLOW_HDR': 'bufferoverflowmaxheaderlength',
    'APPFW_BUFFEROVERFLOW_TOTAL_HDR': 'bufferoverflowmaxheaderlength',
    'APPFW_BUFFEROVERFLOW': 'bufferoverflowmaxurllength',  # generischer/aelterer Name, Fallback auf URL
}

BUFFER_OVERFLOW_FIELD_LABELS = {
    'bufferoverflowmaxurllength': 'Maximum URL Length',
    'bufferoverflowmaxcookielength': 'Maximum Cookie Length',
    'bufferoverflowmaxheaderlength': 'Maximum Header Length',
}

# Erkennt Meldungen wie:
# "Query string length(960) is greater than maximum allowed(200)."
# Liefert (beobachtete Laenge, aktuell konfiguriertes Maximum) direkt aus
# der von NetScaler selbst gemeldeten Zahl - genau das, was auch das
# native "Click-to-Deploy"-Feature der NetScaler-GUI nutzt.
BUFFER_OVERFLOW_LENGTH_RE = re.compile(
    r'length\s*\(\s*(?P<observed>\d+)\s*\)\s*is\s*greater\s*than\s*maximum\s*allowed\s*\(\s*(?P<max>\d+)\s*\)',
    re.IGNORECASE
)

# Diese Extension-Felder werden bereits als eigene, benannte Attribute
# bereitgestellt (siehe return-Dict unten) und deshalb aus der generischen
# "weitere Details"-Liste ausgeschlossen, damit nichts doppelt erscheint.
CURATED_FIELDS = ['src', 'method', 'act', 'cs1', 'cs4', 'request', 'msg']


def _unescape(value):
    """Entfernt CEF-Escaping (\\= -> =, \\\\ -> \\, ...)."""
    return re.sub(r'\\(.)', r'\1', value).strip()


def _parse_extension(extension):
    fields = {}
    for match in EXTENSION_FIELD_RE.finditer(extension):
        key, raw_value = match.group(1), match.group(2)
        fields[key] = _unescape(raw_value)
    return fields


def _suggest_starturl_pattern(request_url):
    """
    Erzeugt einen Regex-Vorschlag für eine Start-URL-Relaxation-Regel aus
    einer geloggten Request-URL. Start URL prüft laut NetScaler nur den
    Pfad-Teil einer Anfrage, nicht den Query-String - der wird daher
    abgeschnitten. Der verbleibende Teil (Schema+Host+Pfad) wird per
    re.escape() zu einer exakten, verankerten Regex (^...$).
    ANNAHME: falls Start URL bei euch doch inkl. Query-String prüft, hier
    anpassen (einfach 'request_url.split("?")[0]' durch 'request_url'
    ersetzen bzw. urlsplit-Query mit einbeziehen).
    """
    if not request_url:
        return ''
    split = urlsplit(request_url)
    if split.scheme and split.netloc:
        base = f"{split.scheme}://{split.netloc}{split.path}"
    else:
        base = request_url.split('?', 1)[0]
    return '^' + re.escape(base) + '$'


def _parse_start_url(entry):
    """Ergänzt Start-URL-Treffer um den vorgeschlagenen Relaxation-Regex."""
    entry['is_start_url'] = entry['name'] == 'APPFW_STARTURL'
    if entry['is_start_url']:
        entry['su_suggested_pattern'] = _suggest_starturl_pattern(entry.get('request_url', ''))
    return entry


def _parse_buffer_overflow(entry):
    """
    Ergaenzt einen Buffer-Overflow-Log-Eintrag um die Felder, die fuer die
    "Relaxation Rule erstellen" / "Activate"-Buttons auf der Analysis-Seite
    gebraucht werden: welches NITRO-Profilfeld betroffen ist, sowie die von
    NetScaler selbst gemeldete beobachtete Laenge und den aktuell
    konfigurierten Schwellenwert (aus der msg-Zeile geparst).
    """
    field = BUFFER_OVERFLOW_FIELD_MAP.get(entry['name'])
    if not field:
        entry['is_buffer_overflow'] = False
        return entry

    entry['is_buffer_overflow'] = True
    entry['bo_field'] = field
    entry['bo_field_label'] = BUFFER_OVERFLOW_FIELD_LABELS.get(field, field)

    match = BUFFER_OVERFLOW_LENGTH_RE.search(entry.get('message', ''))
    if match:
        entry['bo_observed_length'] = int(match.group('observed'))
        entry['bo_configured_max'] = int(match.group('max'))
        entry['bo_length_source'] = 'log'
    else:
        # Fallback, falls die Meldung nicht dem erwarteten Muster folgt:
        # Zeichenzahl der geloggten Request-URL selbst verwenden. Das ist
        # eine Annaeherung, nicht zwingend exakt das, was NetScaler intern
        # gemessen hat (z.B. bei URL-Encoding-Unterschieden).
        entry['bo_observed_length'] = len(entry.get('request_url', ''))
        entry['bo_configured_max'] = None
        entry['bo_length_source'] = 'estimated'

    return entry


# ---------------------------------------------------------------------------
# SQL-Injection-Relaxation (HTML / XML / JSON)
# ---------------------------------------------------------------------------
# Typische msg-Zeile (NetScaler >= 11.0, HTML-Payload):
#   SQL Keyword check failed for field q="select(;)"
# Der CEF-Parser oben schneidet ein unescaptes `name=` mitten in msg ab
# (es würde als neues CEF-Feld gelesen). NetScaler escaped "=" normalerweise
# als "\=", falls nicht, greift der Fallback auf die rohe Logzeile.
# ANNAHME: Für XML/JSON-Payloads (dort ist das Meldungsformat laut Citrix-Doku
# nicht von der 11.0-Änderung betroffen) gilt dasselbe Grundmuster
# "... check failed for <field|element|attribute|key> <name>". Falls eure
# echten Logs anders aussehen, hier die beiden Regex anpassen.
SQL_MSG_STRICT_RE = re.compile(
    r'check\s+failed\s+for\s+(?P<loc>field|header|cookie|element|attribute|key)\s+'
    r'(?P<name>[^="\s][^="]*?)\s*=\s*"(?P<value>.*?)"(?=\s+\w+=|\s*$)',
    re.IGNORECASE | re.DOTALL
)
SQL_MSG_LOOSE_RE = re.compile(
    r'for\s+(?P<loc>field|header|cookie|element|attribute|key)\s+(?P<name>[^\s="]+)',
    re.IGNORECASE
)

# Wert "as_scan_location_sql" (HTML) je nach Fundort in der Meldung.
SQL_HTML_LOCATIONS = {'field': 'FORMFIELD', 'header': 'HEADER', 'cookie': 'COOKIE'}
SQL_HTML_LOCATION_LABELS = {'FORMFIELD': 'Formularfeld', 'HEADER': 'Header', 'COOKIE': 'Cookie'}
SQL_XML_LOCATION_LABELS = {'ELEMENT': 'Element', 'ATTRIBUTE': 'Attribut'}


# Art des fehlgeschlagenen SQL-Checks aus der Meldung, z.B.
# "SQL Keyword check failed ...", "SQL Special ... check failed ...",
# "SQL Wildchar check failed ...". Wert = NITRO-Bezeichnung von as_value_type_sql.
SQL_CHECK_KIND_RE = re.compile(
    r'(?:SQL|CMD|Command(?:\s+Injection)?)\s+(?P<kind>Keyword|Special\s*\w*|Wild\s*\w*)\s+check', re.IGNORECASE)

SQL_TOKEN_KEYWORD = 'Keyword'
SQL_TOKEN_SPECIAL = 'SpecialString'
SQL_TOKEN_WILDCHAR = 'Wildchar'
SQL_TOKEN_TYPES = (SQL_TOKEN_KEYWORD, SQL_TOKEN_SPECIAL, SQL_TOKEN_WILDCHAR)
# Command Injection kennt nur Keyword und SpecialString (kein Wildchar).
CMD_TOKEN_TYPES = (SQL_TOKEN_KEYWORD, SQL_TOKEN_SPECIAL)

# Meldungswert ab NetScaler 11.0: "<keyword>(<sonderzeichen>)", z.B. select(;)
# oder "..or(;)". Die führenden/nachgestellten Punkte sind ein Auslassungs-
# marker von NetScaler (vor/nach dem Keyword steht weiterer Text) und NICHT
# Teil des Keywords - eine Regel mit "..or" matcht nie (im Praxistest belegt).
SQL_FLAGGED_COMBINED_RE = re.compile(r'^(?P<kw>[^()\s]+)\((?P<sp>.+)\)$')
SQL_ELLIPSIS_RE = re.compile(r'^(?:\.{2,}|\u2026)+|(?:\.{2,}|\u2026)+$')


def _strip_ellipsis(text):
    """Entfernt NetScalers Auslassungsmarker ('..', '...', '…') an den Rändern."""
    return SQL_ELLIPSIS_RE.sub('', text or '')


def _check_kind_to_token_type(message):
    """Token-Typ aus dem 'SQL <Kind> check failed'-Teil der Meldung (oder None)."""
    match = SQL_CHECK_KIND_RE.search(message or '')
    if not match:
        return None
    kind = match.group('kind').lower().replace(' ', '')
    if kind.startswith('keyword'):
        return SQL_TOKEN_KEYWORD
    if kind.startswith('special'):
        return SQL_TOKEN_SPECIAL
    if kind.startswith('wild'):
        return SQL_TOKEN_WILDCHAR
    return None


def _apply_token_preselection(tokens):
    """Setzt 'checked': Ist ein Keyword vorhanden, ist nur dieses vorausgewählt
    (im Standardmodus Sonderzeichen-UND-Keyword genügt es, das Keyword
    freizugeben; zusätzlich freigegebene Sonderzeichen würden die Regel
    unnötig erweitern), sonst alle Muster."""
    has_keyword = any(t['type'] == SQL_TOKEN_KEYWORD for t in tokens)
    for t in tokens:
        t['checked'] = (t['type'] == SQL_TOKEN_KEYWORD) if has_keyword else True
    return tokens


def _parse_injection_tokens(message, flagged):
    """
    Zerlegt den von NetScaler gemeldeten Wert in freigebbare Tokens
    [{'type': Keyword|SpecialString|Wildchar, 'value': ..., 'checked': bool}].

    Erkannte Formate:
      select(;)   -> Keyword "select" + SpecialString ";"   (NetScaler >= 11.0)
      ..or(')     -> Keyword "or" (Auslassungsmarker entfernt) + SpecialString "'"
      select      -> Typ gemäß "SQL <Kind> check failed"
    ANNAHME: Das Klammerformat bedeutet <keyword>(<sonderzeichen>). Der Wert
    enthält nur, was NetScaler tatsächlich beanstandet hat (nicht zwingend
    ALLE problematischen Muster des Eingabewerts). Enthält der Wert Leerzeichen
    (älteres Format mit dem kompletten Eingabewert), werden bewusst KEINE
    Tokens geraten - die UI lässt sie dann manuell erfassen.

    Vorauswahl ('checked'): Im Standardmodus SQLSplCharANDKeyword blockt
    NetScaler nur bei Keyword UND Sonderzeichen - es genügt daher, das
    Keyword freizugeben. Zusätzlich freigegebene Sonderzeichen würden die
    Freigabe unnötig erweitern (z.B. würde "x; drop table t" durchgehen,
    sobald ";" freigegeben ist). Deshalb ist bei vorhandenem Keyword nur
    dieses vorausgewählt; die übrigen Muster bleiben zur Auswahl gelistet.
    """
    flagged = (flagged or '').strip()
    if not flagged or len(flagged) > 128 or re.search(r'\s', flagged):
        return []

    tokens = []
    combined = SQL_FLAGGED_COMBINED_RE.match(flagged)
    if combined:
        keyword = _strip_ellipsis(combined.group('kw'))
        special = combined.group('sp')
        if keyword:
            tokens.append({'type': SQL_TOKEN_KEYWORD, 'value': keyword})
        tokens.append({'type': SQL_TOKEN_SPECIAL, 'value': special})
    else:
        value = _strip_ellipsis(flagged)
        if not value:
            return []
        token_type = _check_kind_to_token_type(message)
        if token_type is None:
            token_type = SQL_TOKEN_KEYWORD if re.fullmatch(r'[A-Za-z_]+', value) else SQL_TOKEN_SPECIAL
        tokens.append({'type': token_type, 'value': value})

    return _apply_token_preselection(tokens)


def _sql_event_kind(event_name):
    """Ordnet einen AppFW-Eventnamen dem SQL-Check-Typ zu: 'html', 'xml',
    'json' oder None (kein SQL-Event). ANNAHME: der JSON-Event heißt analog
    zu APPFW_XML_SQL z.B. APPFW_JSON_SQL - erkannt wird jeder Name mit
    'SQL' und 'JSON'; Namen mit 'SQL' und 'XML' gelten als XML, alle
    übrigen SQL-Events (APPFW_SQL) als HTML."""
    name = (event_name or '').upper()
    if 'SQL' not in name:
        return None
    if 'XML' in name:
        return 'xml'
    if 'JSON' in name:
        return 'json'
    return 'html'


def _extract_check_violation(entry):
    """Liest (Fundort, Feldname, gemeldeter Wert) aus der SQL-Meldung.
    Liefert ('', '', '') wenn nichts erkannt wurde."""
    candidates = [
        entry.get('message', ''),
        (entry.get('raw_line') or '').replace('\\=', '='),
    ]
    for text in candidates:
        match = SQL_MSG_STRICT_RE.search(text)
        if match:
            return match.group('loc').lower(), match.group('name').strip(), match.group('value')
    for text in candidates:
        match = SQL_MSG_LOOSE_RE.search(text)
        if match:
            return match.group('loc').lower(), match.group('name').strip(), ''
    return '', '', ''


def _parse_sql_injection(entry):
    """
    Ergänzt SQL-Injection-Treffer um die Daten für den Button
    "Relaxation Rule erstellen":
      sql_kind        'html' | 'xml' | 'json'
      sql_field       Feld-/Element-/Key-Name aus der Meldung
      sql_location    NITRO-Wert (FORMFIELD/HEADER/COOKIE bzw. ELEMENT/ATTRIBUTE)
      sql_url_pattern anchored Regex der Request-URL (HTML + JSON)
      sql_can_relax   False, wenn für den Regeltyp nötige Angaben fehlen
      sql_scope_note  Klartext, was die Regel bewirkt (Anzeige + Bestätigung)

    Bewusste Entscheidung (HTML): Die Regel gibt NICHT das ganze Feld frei,
    sondern nur einzelne Muster (as_value_type_sql = Keyword / SpecialString /
    Wildchar mit as_value_expr_sql als Literal). Alle übrigen SQL-Angriffsmuster
    werden für Feld + URL weiter geprüft. sql_tokens enthält die aus der
    Meldung erkannten Tokens als Vorschlag; sie sind in der UI editierbar.
    """
    kind = _sql_event_kind(entry.get('name'))
    entry['is_sql_injection'] = kind is not None
    if kind is None:
        return entry

    loc, name, flagged = _extract_check_violation(entry)
    url_pattern = _suggest_starturl_pattern(entry.get('request_url', ''))

    entry['sql_kind'] = kind
    entry['sql_field'] = name
    entry['sql_flagged'] = flagged
    entry['sql_url_pattern'] = url_pattern
    entry['sql_location'] = ''
    entry['sql_can_relax'] = False
    entry['sql_button_label'] = ''
    entry['sql_scope_note'] = ''
    entry['sql_tokens'] = []

    if kind == 'html':
        location = SQL_HTML_LOCATIONS.get(loc, 'FORMFIELD')
        entry['sql_location'] = location
        entry['sql_can_relax'] = bool(name and url_pattern)
        entry['sql_tokens'] = _parse_injection_tokens(entry.get('message', ''), flagged)
        loc_label = SQL_HTML_LOCATION_LABELS[location]
        entry['sql_button_label'] = f'Relaxation Rule erstellen (SQL Injection → {loc_label} „{name}“, einzelne Muster freigeben)'
        entry['sql_scope_note'] = (
            f'Gibt nur die ausgewählten Muster (Keyword, Sonderzeichen, Wildcard) für {loc_label} „{name}“ '
            f'auf {url_pattern} frei. Alle anderen SQL-Muster werden dort weiter geprüft, '
            'andere URLs und Felder bleiben vollständig geschützt.'
        )
    elif kind == 'xml':
        location = 'ATTRIBUTE' if loc == 'attribute' else 'ELEMENT'
        entry['sql_location'] = location
        entry['sql_can_relax'] = bool(name)
        loc_label = SQL_XML_LOCATION_LABELS[location]
        entry['sql_button_label'] = f'Relaxation Rule erstellen (XML SQL Injection → {loc_label} „{name}“, profilweit)'
        entry['sql_scope_note'] = (
            f'ACHTUNG: XML-SQL-Relaxations sind in NetScaler nicht an eine URL gebunden. '
            f'{loc_label} „{name}“ wird im gesamten Profil von der SQL-Prüfung ausgenommen, '
            'nicht nur auf dieser Seite.'
        )
    else:  # json
        entry['sql_can_relax'] = bool(url_pattern)
        entry['sql_button_label'] = 'Relaxation Rule erstellen (JSON SQL Injection → gesamte URL)'
        entry['sql_scope_note'] = (
            f'ACHTUNG: Die JSON-Regel ist URL-basiert. Die SQL-Prüfung entfällt für ALLE Keys '
            f'der URL {url_pattern}, nicht nur für den gemeldeten.'
        )
    return entry


# ---------------------------------------------------------------------------
# Command-Injection-Relaxation (HTML)
# ---------------------------------------------------------------------------
# Aufbau wie bei SQL Injection (appfwprofile_cmdinjection_binding: Feldname +
# Form-Action-URL + Value Type Keyword/SpecialString + Value Expression).
# NICHT BELEGT: der genaue Eventname und der Meldungstext im Log. Erkannt wird
# deshalb jeder Eventname mit CMD/COMMAND; bei unbekanntem Eventnamen zusätzlich
# jede "check failed"-Meldung, die "CMD" bzw. "Command Injection" nennt.
# Feldname/Fundort werden wie bei SQL aus "... check failed for field <name>=..."
# gelesen (_extract_check_violation). Weicht euer Log ab: _cmd_event_kind bzw. die
# beiden SQL_MSG_*_RE anpassen.
CMD_MESSAGE_HINT_RE = re.compile(r'\bCMD\b|command\s+injection', re.IGNORECASE)


def _cmd_event_kind(entry):
    """'html' | 'json' | 'xml' oder None (kein Command-Injection-Event)."""
    name = (entry.get('name') or '').upper()
    if 'CMD' in name or 'COMMAND' in name:
        if 'JSON' in name:
            return 'json'
        if 'XML' in name:
            return 'xml'
        return 'html'
    message = entry.get('message', '') or ''
    if (name not in CHECK_TYPE_LABELS and name.startswith('APPFW_')
            and 'check failed' in message.lower() and CMD_MESSAGE_HINT_RE.search(message)):
        return 'html'
    return None


def _parse_cmd_injection(entry):
    """
    Ergänzt Command-Injection-Treffer um die Daten für den Button:
      is_cmd_injection  True bei Command-Injection-Event
      cmd_kind          'html' | 'json' | 'xml'
      cmd_field         Feldname aus der Meldung
      cmd_location      FORMFIELD | HEADER | COOKIE
      cmd_url_pattern   anchored Regex der Request-URL
      cmd_tokens        vorgeschlagene Muster (Keyword / SpecialString), vorausgewählt
      cmd_can_relax     nur für HTML mit erkanntem Feldnamen (JSON/XML: keine Regel)
    Wie bei SQL werden nur EINZELNE Muster freigegeben, nicht das ganze Feld.
    """
    kind = _cmd_event_kind(entry)
    entry['is_cmd_injection'] = kind is not None
    entry['cmd_kind'] = kind or ''
    entry['cmd_field'] = ''
    entry['cmd_flagged'] = ''
    entry['cmd_location'] = ''
    entry['cmd_url_pattern'] = ''
    entry['cmd_tokens'] = []
    entry['cmd_can_relax'] = False
    entry['cmd_button_label'] = ''
    entry['cmd_scope_note'] = ''
    if kind is None:
        return entry

    # Unbekannter Eventname: lesbares Label statt des rohen Namens
    if entry['label'] == entry['name']:
        entry['label'] = {'json': 'JSON Command Injection', 'xml': 'XML Command Injection'}.get(kind, 'Command Injection')

    if kind != 'html':
        return entry   # JSON/XML: NITRO-Feldnamen der Fein-Regeln nicht verifiziert

    loc, name, flagged = _extract_check_violation(entry)
    url_pattern = _suggest_starturl_pattern(entry.get('request_url', ''))
    location = SQL_HTML_LOCATIONS.get(loc, 'FORMFIELD')
    tokens = [t for t in _parse_injection_tokens(entry.get('message', ''), flagged) if t['type'] in CMD_TOKEN_TYPES]

    entry['cmd_field'] = name
    entry['cmd_flagged'] = flagged
    entry['cmd_location'] = location
    entry['cmd_url_pattern'] = url_pattern
    entry['cmd_tokens'] = _apply_token_preselection(tokens)
    entry['cmd_can_relax'] = bool(name and url_pattern)
    loc_label = SQL_HTML_LOCATION_LABELS[location]
    entry['cmd_button_label'] = f'Relaxation Rule erstellen (Command Injection → {loc_label} „{name}“, einzelne Muster freigeben)'
    entry['cmd_scope_note'] = (
        f'Gibt nur die ausgewählten Muster (Keyword, Sonderzeichen) für {loc_label} „{name}“ '
        f'auf {url_pattern} frei. Alle anderen Command-Injection-Muster werden dort weiter geprüft, '
        'andere URLs und Felder bleiben vollständig geschützt.'
    )
    return entry


# ---------------------------------------------------------------------------
# Cookie Consistency: von Block auf Transform umstellen
# ---------------------------------------------------------------------------
# Anders als bei den anderen Checks ist das keine feingranulare Ausnahme für
# einen einzelnen Treffer, sondern eine PROFILWEITE Umstellung der Aktion.
# ---------------------------------------------------------------------------
# CSRF-Form-Tagging-Relaxation (HTML)
# ---------------------------------------------------------------------------
# Anders als die anderen Checks braucht CSRF Form Tagging ZWEI Muster: die
# Form-Origin-URL und die Form-Action-URL (CLI: -CSRFTag <originURL>
# <actionURL>). NICHT BELEGT: der genaue Eventname und Meldungstext im Log -
# erkannt wird jeder Eventname, der "CSRF" enthält.
#
# WICHTIGE BESONDERHEIT (aus Citrix-Support-Artikeln und -Forenbeiträgen,
# mehrfach in echten, funktionierenden Konfigurationen belegt): Die
# Form-Origin-URL wird bei gleicher Origin von NetScaler häufig nicht als
# vollständige URL, sondern nur als Schema plus "://" ohne Host gemeldet/
# erwartet, z.B. "^http://$". Deshalb wird dieses Muster als Vorschlag für
# die Origin-URL vorbelegt statt eines aus der Origin abgeleiteten Musters.
# ANNAHME - unbedingt gegen die eigene Appliance prüfen (siehe README).
CSRF_ORIGIN_SUGGESTION = '^http://$'


def _parse_csrf_tag(entry):
    """
    Ergänzt CSRF-Form-Tagging-Treffer um die Daten für den Relaxation-Button:
      is_csrf_tag              True bei einem CSRF-Form-Tagging-Event
      csrf_origin_suggestion   Vorschlag für die Form-Origin-URL
      csrf_action_pattern      verankerter Regex der Form-Action-URL, OHNE
                                Query-String (laut Citrix zwingend, sonst
                                schlägt das Binding fehl)
      csrf_can_relax           True, wenn eine Action-URL ermittelt werden konnte
    """
    is_csrf = 'CSRF' in (entry.get('name') or '').upper()
    entry['is_csrf_tag'] = is_csrf
    entry['csrf_origin_suggestion'] = CSRF_ORIGIN_SUGGESTION if is_csrf else ''
    entry['csrf_action_pattern'] = _suggest_starturl_pattern(entry.get('request_url', '')) if is_csrf else ''
    entry['csrf_can_relax'] = is_csrf and bool(entry['csrf_action_pattern'])
    return entry


def _parse_cookie_consistency(entry):
    """Markiert Cookie-Consistency-Treffer für den 'Auf Transform umstellen'-Button."""
    entry['is_cookie_consistency'] = entry['name'] == 'APPFW_COOKIE'
    return entry


# ---------------------------------------------------------------------------
# Policy Hits (Deny-URL-Regel aus einem geloggten Aufruf erzeugen)
# ---------------------------------------------------------------------------
# Mit "logEveryPolicyHit ON" im Profil loggt NetScaler jeden Request, der eine
# WAF-Policy trifft, als APPFW_POLICY_HIT (msg="Application Firewall profile
# invoked", kein cs3/Transaktions-ID). Damit ist die Liste "Not blocked" eine
# Übersicht aller Aufrufe - Grundlage für Deny-URL-Regeln.

def _request_url_base(request_url):
    """schema://host/pfad ohne Query-String ('' wenn keine URL vorhanden)."""
    if not request_url:
        return ''
    split = urlsplit(request_url)
    if split.scheme and split.netloc:
        return f"{split.scheme}://{split.netloc}{split.path}"
    return request_url.split('?', 1)[0]


def _parse_policy_hit(entry):
    """
    Ergänzt Policy-Hit-Einträge um Vorschläge für eine Deny-URL-Regel:
      is_policy_hit           True bei APPFW_POLICY_HIT
      deny_url_base           schema://host/pfad ohne Query-String
      deny_url_path           nur der Pfad
      deny_url_pattern        EMPFOHLEN: Host optional, Query optional
      deny_url_pattern_exact  Schema + Host + Pfad, ohne Query (streng)
      deny_url_pattern_path   nur Pfad (host-unabhängig), Query optional

    Warum "tolerant" der Standard ist: Es ist NICHT belegt, gegen welche Form
    NetScaler das Deny-URL-Muster matcht (URL mit Host, nur Pfad, mit/ohne
    Query-String). Im Praxistest griff das streng verankerte Muster
    ^http://host/pfad$ nicht. Das tolerante Muster trifft alle diese
    Darstellungen DESSELBEN Pfades und (bei bekanntem Host) nur diesen Host:
        ^(?:https?://host)?/pfad(?:[?].*)?$   (Query-Teil in der Praxis als \\?.*)
    """
    entry['is_policy_hit'] = entry['name'] == 'APPFW_POLICY_HIT'
    for key in ('deny_url_base', 'deny_url_path', 'deny_url_pattern',
                'deny_url_pattern_exact', 'deny_url_pattern_path'):
        entry[key] = ''
    if not entry['is_policy_hit']:
        return entry

    request_url = entry.get('request_url', '')
    base = _request_url_base(request_url)
    if not base:
        return entry

    split = urlsplit(request_url)
    has_origin = bool(split.scheme and split.netloc)
    path = split.path if has_origin else base
    path = path or '/'
    optional_query = r'(?:\?.*)?'

    entry['deny_url_base'] = base
    entry['deny_url_path'] = path
    if has_origin:
        # Host aus dem Log fest, Schema http/https und Vorhandensein des Hosts optional
        entry['deny_url_pattern'] = '^(?:https?://' + re.escape(split.netloc) + ')?' + re.escape(path) + optional_query + '$'
    else:
        entry['deny_url_pattern'] = '^' + re.escape(path) + optional_query + '$'
    entry['deny_url_pattern_exact'] = '^' + re.escape(base) + '$'
    entry['deny_url_pattern_path'] = '^' + re.escape(path) + optional_query + '$'
    return entry


def parse_cef_line(line):
    """Zerlegt eine einzelne CEF-Logzeile. Gibt None zurück, wenn es keine
    (gültige) AppFW-CEF-Zeile ist."""
    line = line.strip()
    if not line or 'CEF:' not in line or 'APPFW' not in line:
        return None

    match = CEF_LINE_RE.match(line)
    if not match:
        return None

    data = match.groupdict()
    if data['signature_id'] != 'APPFW':
        return None

    ext = _parse_extension(data['extension'])

    detail_fields = [
        {'key': key, 'label': EXTENSION_LABELS.get(key, key), 'value': value}
        for key, value in ext.items() if key not in CURATED_FIELDS
    ]

    entry = {
        'timestamp': data['timestamp'],
        'device_ip': data['device_ip'],
        'name': data['name'],
        'label': CHECK_TYPE_LABELS.get(data['name'], data['name']),
        'cef_severity': data['severity'],
        'src': ext.get('src', ''),
        'method': ext.get('method', ''),
        'action': ext.get('act', ''),
        'profile': ext.get('cs1', ''),
        'severity_label': ext.get('cs4', ''),
        'message': ext.get('msg', ''),
        'request_url': ext.get('request', ''),
        'details': detail_fields,
        'raw_line': line,
    }
    return _parse_policy_hit(_parse_csrf_tag(_parse_cookie_consistency(_parse_cmd_injection(_parse_sql_injection(_parse_buffer_overflow(_parse_start_url(entry)))))))


def severity_css_class(entry):
    """
    Leitet aus dem NetScaler-Schweregrad (cs4, z.B. 'ALERT') eine CSS-Klasse
    für die farbliche Kennzeichnung der Log-Karte ab. Fällt auf den
    numerischen CEF-Schweregrad zurück, falls cs4 fehlt oder unbekannt ist.
    """
    label = (entry.get('severity_label') or '').strip().lower()
    if label in ('alert', 'critical', 'emergency', 'error'):
        return 'sev-alert'
    if label in ('warning',):
        return 'sev-warning'
    if label in ('notice',):
        return 'sev-notice'
    if label in ('informational', 'info', 'debug'):
        return 'sev-informational'

    try:
        numeric = int(entry.get('cef_severity', ''))
    except (TypeError, ValueError):
        return 'sev-informational'
    if numeric >= 7:
        return 'sev-alert'
    if numeric >= 4:
        return 'sev-warning'
    return 'sev-informational'


def action_css_class(action):
    """CSS-Klasse für die farbliche Kennzeichnung des 'act'-Feldes."""
    action = (action or '').strip().lower()
    if action in ('blocked', 'dropped'):
        return f'act-{action}'
    if action == 'not blocked':
        return 'act-notblocked'
    if not action or action == 'none':
        return 'act-none'
    return 'act-other'


def is_blocked_action(action):
    """True, wenn das 'act'-Feld eine tatsaechliche Blockierung bedeutet."""
    return (action or '').strip().lower() == 'blocked'


def parse_appfw_log(raw_text, max_entries=300):
    """
    Filtert aus dem kompletten ns.log-Inhalt alle AppFW/CEF-Zeilen heraus
    und gibt sie strukturiert zurück, neueste zuerst.
    """
    entries = []
    for line in raw_text.splitlines():
        entry = parse_cef_line(line)
        if entry:
            entry['severity_class'] = severity_css_class(entry)
            entry['action_class'] = action_css_class(entry['action'])
            entry['is_blocked'] = is_blocked_action(entry['action'])
            entries.append(entry)

    entries.reverse()  # ns.log ist chronologisch aufsteigend -> neueste zuerst
    return entries[:max_entries]
