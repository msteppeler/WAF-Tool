"""
Parser für Suricata/Snort-Regeldateien (.rules), wie sie z.B. im kostenlosen,
BSD-lizenzierten ET-Open-Regelwerk von Emerging Threats/Proofpoint verteilt
werden (https://rules.emergingthreats.net/open/...). Reine Textverarbeitung,
kein Netzwerkzugriff - das Laden der Datei selbst erfolgt in app.py.

Format einer Regelzeile (Beispiel):
  alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT Possible
  CVE-2021-44228 Log4j RCE Attempt"; flow:established,to_server;
  content:"${jndi:"; http_uri; nocase; reference:cve,2021-44228;
  classtype:attempted-admin; sid:2034647; rev:3;)

Das Modul liest die Regeln (parse_rules_text), entscheidet je Regel, ob sie sich
selbst in eine native NetScaler-Signaturregel uebersetzen laesst
(classify_for_native_translation), und erzeugt dafuer die Muster (group_to_pcre).
NetScalers eigener Snort-Import (-VendorType Snort) wird NICHT benutzt: er scheiterte
auf der Appliance des Nutzers schon bei der einfachsten Regel. Die Begruendung, die
Belege aus Citrix' eigener Signaturdatei und die Pruefung der Uebersetzung stehen in
TECHNICAL_NOTES.md.
"""
import collections
import re
import requests

REQUEST_TIMEOUT = 60

# ET Open (Proofpoint/Emerging Threats) - kostenlos, BSD-lizenziert, ohne
# Anmeldung abrufbar (bestätigt: rules.emergingthreats.net/OPEN_download_
# instructions.html). Diese "exploit"-Kategorie enthält die Regeln mit dem
# höchsten Anteil an CVE-Referenzen für Web-Angriffe - andere ET-Kategorien
# (z.B. "malware", "dns") sind für den hier gewünschten CVE-Gap-Abgleich
# nicht relevant. Direkter, unkomprimierter Pfad (kein tar.gz nötig) - die
# "suricata/" ohne Versionsnummer liefert laut Verzeichnis-Listing immer
# den aktuellen Stand.
_ET_OPEN_BASE = 'https://rules.emergingthreats.net/open/suricata/rules/'

# Welche ET-Open-Kategoriedateien geladen werden. Urspruenglich nur
# "emerging-exploit" - das war eine unbelegte Annahme und erwies sich als zu
# eng: eine WordPress-Kategorie fand dadurch keine einzige zusaetzliche Regel.
# Laut Verzeichnis-Listing von rules.emergingthreats.net liegt die mit
# Abstand groesste Datei fuer anwendungsspezifische Webangriffe in
# "emerging-web_specific_apps" (rund 5,4 MB, etwa das Vierfache von "exploit"),
# dazu "web_server" (rund 0,5 MB) und "current_events" (rund 0,14 MB, neue
# Schwachstellen). "web_client" ist bewusst NICHT dabei: das sind Angriffe
# auf Browser (Clientseite), nicht auf einen von einer WAF geschuetzten Server.
# Alle vier Dateinamen sind im Listing bzw. in frueheren Abrufen belegt, aber
# aus dieser Sandbox NICHT live abgerufen (siehe TECHNICAL_NOTES.md).
DEFAULT_SNORT_RULES_URLS = [
    _ET_OPEN_BASE + 'emerging-web_specific_apps.rules',
    _ET_OPEN_BASE + 'emerging-web_server.rules',
    _ET_OPEN_BASE + 'emerging-exploit.rules',
    _ET_OPEN_BASE + 'emerging-current_events.rules',
]


def _fetch_rules_text(url):
    """Laedt den Text einer Regeldatei. Gibt (text, None) oder (None, Fehlertext)."""
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
    except Exception as e:
        return None, f'Fehler beim Herunterladen der Snort-Regeldatei: {e}'
    return response.text, None


def fetch_and_parse_snort_rule_files(urls=None):
    """
    Lädt mehrere Regeldateien nacheinander. Jede Datei wird für sich
    behandelt: schlägt eine fehl (Netzwerk, umbenannt/entfernt), werden die
    übrigen trotzdem geladen - ein einzelner Ausfall soll nicht das ganze
    Aktualisieren blockieren. Doppelte SIDs (dieselbe Regel in zwei Dateien)
    werden nur einmal übernommen.

    Gibt (rules, results) zurück: rules ist die zusammengeführte Regelliste
    (leer, wenn nichts geladen werden konnte), results eine Liste von
    {'url', 'name', 'count', 'disabled', 'error'} je Datei, in der Reihenfolge von urls
    (disabled = von ET auskommentierte, also bewusst deaktivierte Regeln).
    """
    urls = urls or DEFAULT_SNORT_RULES_URLS
    merged, seen_sids, results = [], set(), []
    for url in urls:
        name = url.rsplit('/', 1)[-1]
        text, error = _fetch_rules_text(url)
        rules = None
        if not error:
            rules = parse_rules_text(text)
            if not rules:
                error = 'Datei wurde geladen, aber enthielt keine erkennbaren Regeln.'
        if error:
            results.append({'url': url, 'name': name, 'count': 0, 'disabled': 0, 'error': error})
            continue
        added = 0
        for rule in rules:
            if rule['sid'] in seen_sids:
                continue
            seen_sids.add(rule['sid'])
            merged.append(rule)
            added += 1
        results.append({'url': url, 'name': name, 'count': added,
                        'disabled': count_disabled_rules(text), 'error': None})
    return merged, results

# Sticky Buffers/Schlüsselwörter, die eine Regel eindeutig als HTTP-bezogen
# kennzeichnen, auch wenn das Protokoll im Header nicht "http" lautet (in
# älteren Regeln oft "tcp" mit expliziten HTTP-Optionen statt proto "http").
_HTTP_OPTION_KEYWORDS = (
    # Aeltere Schreibweise mit Unterstrich (Snort2/fruehe Suricata); "uricontent"
    # ist die veraltete Kurzform fuer "content" + "http_uri" in einer Option
    'uricontent', 'http_uri', 'http_raw_uri', 'http_header', 'http_raw_header',
    'http_method', 'http_cookie', 'http_user_agent', 'http_client_body',
    'http_server_body', 'http_stat_code', 'http_stat_msg', 'http_host',
    'http_accept', 'http_content_type', 'http_referer', 'urilen',
    # Neuere "Sticky Buffer"-Schreibweise mit Punkt (Suricata 5+) - an einer
    # echten, vom Nutzer hochgeladenen ET-Open-Regel entdeckt (CVE-2013-3568,
    # SID 2027097), die ausschliesslich diese Schreibweise nutzt. Dort war
    # proto bereits "http", daher kein Fehlverhalten, aber ohne diese
    # Ergaenzung waere eine aeltere "tcp"+Sticky-Buffer-Regel in dieser
    # Schreibweise faelschlich NICHT als HTTP-relevant erkannt worden.
    'http.uri', 'http.uri.raw', 'http.header', 'http.header.raw',
    'http.method', 'http.cookie', 'http.user_agent', 'http.request_body',
    'http.response_body', 'http.stat_code', 'http.stat_msg', 'http.host',
    'http.accept', 'http.content_type', 'http.referer', 'http.request_line',
    'http.response_line', 'urilen',
)

_HEADER_RE = re.compile(
    r'^(?P<action>alert|drop|reject|pass|log)\s+(?P<proto>\S+)\s+.*?\((?P<options>.*)\)\s*;?\s*$'
)


def _split_options(options_str):
    """
    Zerlegt den Options-Teil einer Regel (zwischen den äußeren Klammern) an
    Semikolons - aber NICHT innerhalb von Anführungszeichen (z.B. bei
    msg:"..." oder pcre:"/.../i", die selbst Semikolons enthalten können).
    Reiner Zeichen-für-Zeichen-Tokenizer statt eines naiven split(';'),
    genau dafür gedacht.
    """
    parts = []
    current = []
    in_quotes = False
    i = 0
    n = len(options_str)
    while i < n:
        ch = options_str[i]
        if ch == '\\' and i + 1 < n:
            current.append(ch)
            current.append(options_str[i + 1])
            i += 2
            continue
        if ch == '"':
            in_quotes = not in_quotes
            current.append(ch)
        elif ch == ';' and not in_quotes:
            parts.append(''.join(current).strip())
            current = []
        else:
            current.append(ch)
        i += 1
    tail = ''.join(current).strip()
    if tail:
        parts.append(tail)
    return [p for p in parts if p]


def _parse_option(part):
    """Zerlegt ein einzelnes 'schlüssel:wert'-Options-Teil in (key, value).
    Optionen ohne Wert (z.B. 'nocase', 'http_uri') liefern (key, None)."""
    if ':' not in part:
        return part.strip(), None
    key, _, value = part.partition(':')
    return key.strip(), value.strip()


def _normalize_cve(raw):
    """'2021-44228' oder 'CVE-2021-44228' -> 'CVE-2021-44228' (Format, wie
    es auch signature_db/nvd_client für CVE-IDs verwenden)."""
    raw = raw.strip().upper()
    if raw.startswith('CVE-'):
        return raw
    return f'CVE-{raw}'


# Bildet beide Sticky-Buffer-Schreibweisen (alt mit Unterstrich, neu mit
# Punkt) auf einen gemeinsamen, INTERNEN Oertlichkeits-Namen ab - rein zur
# Klassifizierung innerhalb dieses Moduls, NICHT die tatsächlichen
# NetScaler-eigenen <Location>-Werte (die sind noch nicht bestätigt, siehe
# TECHNICAL_NOTES.md - die eigentliche Übersetzung in natives NetScaler-XML
# ist bewusst noch NICHT Teil dieser Funktion).
_STICKY_BUFFER_LOCATIONS = {
    'http_uri': 'URL', 'http.uri': 'URL',
    'http_header': 'HEADER', 'http.header': 'HEADER',
    'http_method': 'METHOD', 'http.method': 'METHOD',
    'http_cookie': 'COOKIE', 'http.cookie': 'COOKIE',
    'http_user_agent': 'USER_AGENT', 'http.user_agent': 'USER_AGENT',
    'http_client_body': 'POST_BODY', 'http.request_body': 'POST_BODY',
}

# Welche internen Orte (siehe oben) in welchen NATIVEN NetScaler-Location-Wert
# uebersetzt werden duerfen. Belegt an der vom Nutzer exportierten Signaturdatei
# (3057 Regeln, Version 161): Citrix bildet seine eigenen aus Snort abgeleiteten
# Regeln genau so ab - HTTP_URL, HTTP_METHOD ("POST"), HTTP_POST_BODY
# ("operation="), HTTP_HEADER, HTTP_COOKIE, jeweils als Match type LITERAL.
# Zusaetzlich bestaetigt durch die von Hand in der GUI angelegte Regel
# ("web-iis-test", HTTP_URL). NICHT uebernommen: USER_AGENT (Snorts
# http_user_agent enthaelt nur den Wert, ohne Headernamen - eine eigene Area
# dafuer gibt es in der Datei nicht).
NATIVE_LOCATION_AREAS = {
    'URL': 'HTTP_URL', 'METHOD': 'HTTP_METHOD', 'POST_BODY': 'HTTP_POST_BODY',
    'HEADER': 'HTTP_HEADER', 'COOKIE': 'HTTP_COOKIE',
}

# Orte, an denen Citrix in seinen eigenen Regeln das "fastmatch"-Muster setzt
# (jede Regel hat genau eines, siehe signature_file_parser). Aus der Datei:
# HTTP_URL 2696, HTTP_METHOD 190, HTTP_RAW_URL 49, HTTP_HEADER 47,
# HTTP_FORM_FIELD 21, HTTP_COOKIE 5 - und KEIN EINZIGES Mal HTTP_POST_BODY.
# Eine Regel, deren Muster nur im Post-Body liegen, bekaeme also kein
# fastmatch an einem Ort, wie ihn Citrix verwendet -> nicht uebersetzbar.
FASTMATCH_AREAS = {'HTTP_URL', 'HTTP_METHOD', 'HTTP_HEADER', 'HTTP_COOKIE'}

# So viele Muster hat Citrix selbst maximal in einer Regel (Verteilung in der
# Datei: 1 Muster 1035x, 2: 992x, 3: 813x, 4: 191x, 5: 21x, 6: 5x).
MAX_NATIVE_PATTERNS = 6

# Grenzen des Signaturformats. NetScaler prueft eine importierte Datei gegen ein Schema und
# lehnt sie GANZ ab, wenn EIN Wert nicht passt (NITRO 3257, "Problem validating Imported
# object against specification") - eine einzige ungueltige Regel verhindert also das ganze
# Objekt. Bestaetigt durch eine echte Fehlermeldung des Nutzers: ein LogString mit 149 Zeichen
# "exceeds maxLength facet value '128'". Die uebrigen Grenzen sind die HOECHSTEN Werte, die in
# Citrix' eigener Datei (3057 Regeln, Version 161) vorkommen - dort sind sie nachweislich gueltig;
# die echten Schema-Grenzen koennen hoeher liegen, aber innerhalb dieser Werte sind wir sicher.
MAX_LOGSTRING_LENGTH = 128   # bestaetigt (Fehlermeldung); Citrix' Datei: Maximum genau 128
MAX_COMMENT_LENGTH = 29      # hoechster vorkommender Kommentar (nur 2 von 3057 Regeln haben einen)
MAX_REFERENCES = 12          # hoechste Zahl <Reference> je Regel in Citrix' Datei
MAX_LITERAL_LENGTH = 132     # laengstes LITERAL-Muster in Citrix' Datei
MAX_PCRE_LENGTH = 253        # laengstes PCRE-Muster in Citrix' Datei

# Optionen ohne Einfluss auf WAS gematcht wird bzw. nur Beschreibung: duerfen
# in einer uebersetzten Regel vorkommen. "fast_pattern" waehlt nur, welches
# Muster Snort vorab fuer die Suche nutzt (Leistungshinweis) - die Regel
# verlangt weiterhin ALLE Muster, daher unbedenklich. "nocase" wird zwar
# toleriert, laesst sich aber nicht abbilden (siehe build_native_signature_rule).
_SAFE_CONTENT_MODIFIERS = {'nocase', 'fast_pattern'}
# "target" legt in Suricata nur fest, welche Seite (Quelle/Ziel) im Alarm als Angriffsziel
# ausgewiesen wird - es aendert NICHT, was die Regel erkennt (steht in 1390 der ET-Regeln
# mit CVE-Bezug und sperrte sie bisher zu Unrecht).
# Positionsangaben, die als zusaetzliches PCRE-Muster abgebildet werden (siehe
# position_groups / group_to_pcre) - Citrix druckt Reihenfolge und Abstand in
# seinen eigenen Regeln ebenfalls als PCRE aus (z.B. "...\\x22.*\\x26.*").
_SUPPORTED_POSITION_KEYS = {'startswith', 'endswith', 'depth', 'offset', 'distance', 'within'}

_ALLOWED_RULE_KEYS = (
    {'msg', 'flow', 'reference', 'classtype', 'sid', 'rev', 'metadata', 'priority', 'gid',
     'content', 'uricontent', 'target'}
    | _SAFE_CONTENT_MODIFIERS | _SUPPORTED_POSITION_KEYS | set(_STICKY_BUFFER_LOCATIONS)
)

# Schluessel, die die Server-ANTWORT pruefen (Status, Antwort-Body, ...). Eine solche
# Regel kann durch eine Anfrage-Regel nicht ersetzt werden.
_RESPONSE_KEYS = {
    'http.response_body', 'http.stat_code', 'http.stat_msg', 'http.response_line',
    'http.server', 'http.location', 'http.response_header', 'http_stat_code', 'http_stat_msg',
    'http_server_body', 'file_data', 'file.data',
}


def _flowbits_harmless(value):
    """flowbits:set / unset / toggle setzen nur einen Merker fuer ANDERE Regeln und aendern
    nicht, was DIESE Regel erkennt. isset / isnotset sind dagegen Bedingungen (die Regel
    feuert nur, wenn eine andere Regel vorher gefeuert hat), und noalert macht die Regel
    zu einer stillen Hilfsregel - beides darf nicht einfach wegfallen."""
    action = (value or '').split(',', 1)[0].strip().lower()
    return action in {'set', 'unset', 'toggle'}

# Positions-/Laengenangaben, die NICHT uebersetzt werden (nur diese gelten noch als
# "position"): sie schraenken ein, was ein Muster treffen darf, und ohne sie waere die
# uebersetzte Regel breiter als das Original und blockierte zu viel.
_POSITION_KEYS = {'isdataat', 'urilen', 'dsize', 'rawbytes', 'bsize'}

# Schlussel -> kurze Bezeichnung fuer die Auswertung in der Oberflaeche
REASON_LABELS = {
    'position': 'Längenangaben (bsize/urilen/isdataat ...)',
    'position_combo': 'Positionsangaben in nicht unterstützter Kombination',
    'pcre': 'pcre-Muster',
    'other_options': 'weitere Optionen (z.B. flowbits, threshold)',
    'location_unsupported': 'nicht unterstützter Ort (z.B. User-Agent, Roh-URI)',
    'no_location': 'Muster ohne erkennbaren Ort',
    'no_content': 'kein content-Muster',
    'negated': 'negierte Muster',
    'escape': 'Escape-Zeichen im Muster',
    'hex': 'ungültige Hex-Schreibweise',
    'response': 'prüft die Server-Antwort',
    'too_many': f'mehr als {MAX_NATIVE_PATTERNS} Muster',
    'too_long': 'Muster zu lang für das Signaturformat',
    'no_fastmatch': 'kein Fast-Match-fähiger Ort (nur Post-Body)',
}


def _parse_content_value(value):
    """Zerlegt den Wert einer content-Option in (Text, negiert). 'content:!"x"'
    ist eine NEGIERTE Bedingung ("x darf NICHT vorkommen") - ohne diese
    Erkennung wuerde der Text faelschlich als normales Suchmuster gelten."""
    raw = (value or '').strip()
    negated = raw.startswith('!')
    if negated:
        raw = raw[1:].strip()
    if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"'):
        raw = raw[1:-1]
    return raw, negated


def _extract_content_matches(options):
    """
    Geht die Options-Liste einer Regel der Reihe nach durch und baut daraus die
    Liste der Muster ("content"/"uricontent") mit Ort und Modifikatoren. Es gibt
    zwei Schreibweisen, die UNTERSCHIEDLICH wirken:

    - Neuere Suricata-Schreibweise mit PUNKT ("http.uri; content:\"/x\";"):
      ein "Sticky Buffer" - der Ort gilt fuer das folgende und alle weiteren
      Muster, bis ein anderer Ort gesetzt wird.
    - Klassische Snort-Schreibweise mit UNTERSTRICH ("content:\"/x\"; nocase;
      http_uri;"): ein Modifikator, der NUR fuer das unmittelbar vorangehende
      Muster gilt - auch wenn dazwischen weitere Modifikatoren wie nocase oder
      fast_pattern stehen (das ist in alten ET-Regeln der Normalfall; die erste
      Fassung kannte nur den Fall "direkt dahinter" und erkannte
      "content; nocase; http_uri" faelschlich als "kein Ort"). Er setzt KEINEN
      Ort fuer spaetere Muster: ein folgendes content ohne eigenen Modifikator
      liegt im Standard-Buffer, nicht in der URL.
    "uricontent" ist die veraltete Kurzform fuer content + http_uri.

    Gibt eine Liste von {'location', 'content', 'negated', 'modifiers'} zurueck,
    in Reihenfolge des Auftretens.
    """
    matches = []
    sticky_location = None
    current = None
    for key, value in options:
        if key in _STICKY_BUFFER_LOCATIONS:
            location = _STICKY_BUFFER_LOCATIONS[key]
            if '.' in key:
                sticky_location = location          # Punkt-Schreibweise: gilt fuer die FOLGENDEN Muster
            elif current is not None and current['location'] is None:
                current['location'] = location      # Unterstrich-Schreibweise: gilt fuer das VORHERIGE Muster
        elif key in ('content', 'uricontent'):
            content_text, negated = _parse_content_value(value)
            current = {'location': 'URL' if key == 'uricontent' else sticky_location,
                       'content': content_text, 'negated': negated, 'modifiers': [], 'mod_values': {}}
            matches.append(current)
        elif current is not None and key not in ('reference', 'sid', 'rev', 'msg', 'classtype', 'metadata'):
            current['modifiers'].append(key)
            current['mod_values'][key] = value
    return matches


def _valid_hex_notation(text):
    """Pruefung der Snort-Hex-Schreibweise im Muster: "|3b|" oder "|0d 0a|",
    Pipes muessen paarig sein und dazwischen nur Hex-Paare stehen. Citrix
    uebernimmt diese Schreibweise unveraendert in seine LITERAL-Muster (228
    Muster in der Datei, z.B. "|00|", "|20|/HTTP/1.")."""
    if '|' not in text:
        return True
    parts = text.split('|')
    if len(parts) % 2 == 0:
        return False
    return all(re.fullmatch(r'(?:[0-9A-Fa-f]{2}\s*)+', seg.strip()) for seg in parts[1::2])


def fit_logstring(msg, limit=MAX_LOGSTRING_LENGTH):
    """
    Macht aus der Snort-Beschreibung einen gueltigen LogString: nur druckbares ASCII (so ist
    es in Citrix' Datei durchgehend), Leerraum zusammengefasst, hoechstens `limit` Zeichen.
    Ist sie zu lang, bleibt eine angehaengte CVE-Angabe erhalten ("... (CVE-2025-1234)") und
    der beschreibende Teil davor wird mit "..." gekuerzt - so macht es Citrix in seinen
    langen Beschreibungen ebenfalls (die CVE steht am Ende).
    """
    text = ' '.join(''.join(c if 32 <= ord(c) <= 126 else ' ' for c in (msg or '')).split())
    if len(text) <= limit:
        return text
    match = re.search(r'\s*(\((?:CVE-\d{4}-\d{4,}[^)]*)\))\s*$', text)
    suffix = (' ' + match.group(1)) if match else ''
    head = text[:match.start()] if match else text
    room = limit - len(suffix) - 3
    return head[:max(room, 0)].rstrip() + '...' + suffix if match else text[:limit - 3].rstrip() + '...'


def content_bytes(text):
    """Bytes eines Snort-content-Textes: |3b| und |0d 0a| sind Hex-Bytes, der Rest Text."""
    out = bytearray()
    for index, part in enumerate(text.split('|')):
        out += part.encode('utf-8') if index % 2 == 0 else bytes.fromhex(part.replace(' ', ''))
    return bytes(out)


def _nonneg_int(value):
    value = (value or '').strip()
    return int(value) if re.fullmatch(r'\d{1,6}', value) else None


MAX_CHAIN_LENGTH = 3   # verkettete Muster je Regex - begrenzt Groesse und Laufzeit des Musters


def position_groups(content_matches):
    """
    Gruppiert die Muster einer Regel nach ORT zu Ketten und prueft die Positionsangaben.
    Eine Gruppe beginnt mit einem Muster ohne relative Angabe (distance/within) und
    umfasst die darauf folgenden relativen Muster desselben Ortes. Jede Gruppe mit
    mindestens einer Positionsangabe wird spaeter zu EINEM zusaetzlichen PCRE-Muster
    (group_to_pcre), alle anderen bleiben reine Literale.

    Unterstuetzt (Semantik wie bei Suricata/Snort):
    - startswith / endswith: Muster am Anfang / Ende des Buffers,
    - depth N: das Muster endet innerhalb der ersten N Bytes,
    - offset N: das Muster beginnt frueher nicht als bei Byte N,
    - distance N: beginnt mindestens N Bytes nach dem Ende des vorherigen Treffers,
    - within N: endet hoechstens N Bytes nach dem Ende des vorherigen Treffers.
    Bewusst NICHT unterstuetzt (Mehrdeutigkeit zwischen Snort und Suricata oder
    unklar abbildbar): depth zusammen mit offset, startswith zusammen mit depth/offset,
    within zusammen mit distance > 0, absolute zusammen mit relativen Angaben an einem
    Muster, nicht-numerische Werte, endswith vor weiteren Mustern, relative Angaben ohne
    vorheriges Muster im selben Buffer, Ketten laenger als MAX_CHAIN_LENGTH.

    Gibt (groups, None) oder (None, Begruendungstext) zurueck.
    """
    groups = []
    current_group = {}   # Ort -> laufende Gruppe
    for m in content_matches:
        mods = set(m['modifiers'])
        values = m.get('mod_values', {})
        entry = {'text': m['content'], 'nocase': 'nocase' in mods, 'length': len(content_bytes(m['content'])),
                 'startswith': 'startswith' in mods, 'endswith': 'endswith' in mods,
                 'depth': None, 'offset': None, 'distance': None, 'within': None}
        for key in ('depth', 'offset', 'distance', 'within'):
            if key in mods:
                parsed = _nonneg_int(values.get(key))
                if parsed is None:
                    return None, f'Der Wert von "{key}" ist keine einfache Zahl ("{values.get(key)}").'
                entry[key] = parsed
        absolute = entry['startswith'] or entry['depth'] is not None or entry['offset'] is not None
        relative = entry['distance'] is not None or entry['within'] is not None
        if absolute and relative:
            return None, 'Absolute (depth/offset/startswith) und relative (distance/within) Angaben an einem Muster.'
        if entry['startswith'] and (entry['depth'] is not None or entry['offset'] is not None):
            return None, 'startswith zusammen mit depth/offset.'
        if entry['depth'] is not None and entry['offset'] is not None:
            return None, 'depth zusammen mit offset (bei Snort und Suricata unterschiedlich definiert).'
        if entry['within'] is not None and entry['distance'] not in (None, 0):
            return None, 'within zusammen mit distance > 0 (bei Snort und Suricata unterschiedlich definiert).'
        if entry['depth'] is not None and entry['depth'] < entry['length']:
            return None, 'depth ist kleiner als das Muster - die Regel koennte nie zutreffen.'
        if entry['within'] is not None and entry['within'] < entry['length']:
            return None, 'within ist kleiner als das Muster - die Regel koennte nie zutreffen.'
        location = m['location']
        if relative:
            group = current_group.get(location)
            if group is None:
                return None, 'distance/within ohne vorheriges Muster im selben Buffer.'
            group['entries'].append(entry)
        else:
            group = {'location': location, 'entries': [entry]}
            groups.append(group)
            current_group[location] = group
    for group in groups:
        entries = group['entries']
        group['constrained'] = any(
            e['startswith'] or e['endswith'] or any(e[k] is not None for k in ('depth', 'offset', 'distance', 'within'))
            for e in entries)
        if any(e['endswith'] for e in entries[:-1]):
            return None, 'endswith an einem Muster, nach dem im selben Buffer noch weitere folgen.'
        if group['constrained'] and len(entries) > MAX_CHAIN_LENGTH:
            return None, f'Mehr als {MAX_CHAIN_LENGTH} verkettete Muster mit Positionsangaben.'
    return groups, None


# Zeichen, die Citrix in seinen 887 PCRE-Mustern mit EINFACHEM Backslash maskiert (Haeufigkeit in
# der Datei: . 136, \\ 48, / 44, [ ] 28, ? 20, - 15, $ 12, ( 9, & % " 5, > ' | ) + 4, : 3, ...).
# Nur fuer sie schreiben wir "\\c" (2 Zeichen); alles andere Nichtalphanumerische wie bisher als
# "\\xHH" (4 Zeichen). Das haelt die Muster kurz - die Grenze liegt bei MAX_PCRE_LENGTH - und
# fuehrt keine Schreibweise ein, die Citrix nicht auch verwendet. "_" braucht keine Maskierung.
_PCRE_BACKSLASH_CHARS = set('./?-$[]\\()&"%>\'|+:<=#~,')


def _pcre_literal(entry):
    """
    Ein Muster als PCRE-Literal. Bei nocase wird jeder Buchstabe zur Zeichenklasse [aA] -
    bewusst NICHT (?i:...), denn Citrix nutzt in seinen PCRE-Mustern nie gruppierte Flags,
    und eine Zeichenklasse geht in jeder PCRE-Version.
    """
    out = []
    for b in content_bytes(entry['text']):
        ch = chr(b)
        if ch.isascii() and ch.isalpha() and entry['nocase']:
            out.append(f'[{ch.lower()}{ch.upper()}]')
        elif ch.isascii() and (ch.isalnum() or ch == '_'):
            out.append(ch)
        elif ch in _PCRE_BACKSLASH_CHARS:
            out.append('\\' + ch)
        else:
            out.append(f'\\x{b:02x}')
    return ''.join(out)


def _gap(low, high):
    """Abstand zwischen zwei Mustern als PCRE-Quantifizierer, in den Formen, die Citrix selbst
    verwendet ({n}, {0,N}, {n,}, .*?): kein Abstand -> leer, genau n -> {n}."""
    if high is None:
        return '.*?' if low == 0 else '.{%d,}?' % low
    if low == high == 0:
        return ''
    if low == high:
        return '.{%d}' % low
    return '.{%d,%d}' % (low, high)


def group_to_pcre(entries):
    """
    Uebersetzt eine Kette von Mustern desselben Ortes samt Positionsangaben in EIN
    PCRE-Muster. Es verwendet nur Konstrukte, die Citrix in seinen eigenen Mustern nutzt:
    "(?s)" (der Punkt trifft auch Zeilenumbrueche), "^" als Anfang des Buffers (ohne das
    m-Flag), "(?!.)" als Ende des Buffers (kein Zeichen folgt mehr; anders als "$" ohne die
    Sonderrolle eines letzten Zeilenumbruchs), Abstaende als .{min,max} bzw. .*? (lazy).
    Beispiel: content:"/a"; content:"b"; distance:0;  ->  (?s)\\x2fa.*?b
    """
    parts = ['(?s)']
    for index, e in enumerate(entries):
        if index == 0:
            if e['startswith']:
                parts.append('^')
            elif e['depth'] is not None:
                parts.append('^' + _gap(0, e['depth'] - e['length']))
            elif e['offset'] is not None:
                parts.append('^' + _gap(e['offset'], None))
        else:
            distance = e['distance'] or 0
            parts.append(_gap(distance, e['within'] - e['length'] if e['within'] is not None else None))
        parts.append(_pcre_literal(e))
    if entries[-1]['endswith']:
        parts.append('(?!.)')
    return ''.join(parts)


def classify_for_native_translation(content_matches, extra_keys=(), flow=None):
    """
    Entscheidet, ob eine Regel einfach genug ist, um sie SELBST (ohne
    NetScalers auf dieser Appliance nachweislich defekte Snort-Umwandlung) in
    ein natives NetScaler-<SignatureRule> zu uebersetzen. Positivliste statt
    Sperrliste: jede Option, die nicht ausdruecklich als unbedenklich bekannt
    ist, macht die Regel NICHT uebersetzbar - sonst wuerde z.B. ein
    "flowbits:isset" oder "threshold" still wegfallen und die uebersetzte Regel
    waere breiter als das Original (und blockiert jetzt).

    Uebersetzbar ist eine Regel, wenn
    - sie 1 bis MAX_NATIVE_PATTERNS Muster ergibt (alle muessen zutreffen, so wie
      Citrix es in seinen Regeln mit mehreren Mustern darstellt; Positionsangaben
      zaehlen als je ein zusaetzliches PCRE-Muster pro Kette),
    - die Positionsangaben (depth, offset, distance, within, startswith, endswith)
      eindeutig abbildbar sind (siehe position_groups),
    - jedes Muster an einem Ort in NATIVE_LOCATION_AREAS steht, nicht negiert,
      nicht leer, ohne Escape-Zeichen, mit gueltiger Hex-Schreibweise,
    - sie nur Optionen aus _ALLOWED_RULE_KEYS nutzt (extra_keys ist leer),
    - sie nicht die Server-Antwort prueft (flow:to_client/from_server),
    - mindestens ein Muster an einem Fast-Match-Ort (FASTMATCH_AREAS) liegt.

    Gibt (True, None, 'ok') oder (False, Begruendungstext, Code) zurueck; die
    Codes sind die Schluessel von REASON_LABELS.
    """
    matches = content_matches
    if not matches:
        return False, 'Keine "content"-Treffer gefunden (z.B. nur pcre-basiert) - nicht übersetzbar.', 'no_content'
    extra = sorted(extra_keys)
    if extra:
        if set(extra) & _RESPONSE_KEYS:
            found = ', '.join(sorted(set(extra) & _RESPONSE_KEYS))
            return False, f'Die Regel prüft die Server-Antwort ({found}) - eine Anfrage-Regel kann sie nicht ersetzen.', 'response'
        if 'pcre' in extra:
            code = 'pcre'
        elif set(extra) & _POSITION_KEYS:
            code = 'position'
        else:
            code = 'other_options'
        return False, f'Nutzt Optionen, die (noch) nicht übersetzt werden: {", ".join(extra)}.', code
    if flow and {t.strip() for t in flow.split(',')} & {'to_client', 'from_server'}:
        return False, 'Die Regel prüft die Server-Antwort (flow) - eine Anfrage-Regel kann sie nicht ersetzen.', 'response'
    if len(matches) > MAX_NATIVE_PATTERNS:
        return False, f'{len(matches)} Muster - mehr als die {MAX_NATIVE_PATTERNS}, die Citrix selbst nutzt.', 'too_many'
    for match in matches:
        if not match['location']:
            return False, 'Kein erkannter Sticky-Buffer/Ort für ein content-Muster - nicht übersetzbar.', 'no_location'
        if match['location'] not in NATIVE_LOCATION_AREAS:
            return False, f'Ort "{match["location"]}" wird nicht übersetzt - nicht übersetzbar.', 'location_unsupported'
        if match['negated']:
            return False, 'Negierter content-Treffer (content:!"...") - nicht übersetzbar.', 'negated'
        if not match['content']:
            return False, 'Leerer content-Treffer - nicht übersetzbar.', 'no_content'
        if '\\' in match['content']:
            return False, 'Der content-Treffer enthält Escape-Zeichen - nicht sicher als Literal übersetzbar.', 'escape'
        if not _valid_hex_notation(match['content']):
            return False, 'Der content-Treffer enthält eine ungültige Hex-Schreibweise (|..|).', 'hex'
    if not any(NATIVE_LOCATION_AREAS[m['location']] in FASTMATCH_AREAS for m in matches):
        return False, ('Alle Muster liegen im Post-Body - dort setzt Citrix nie das Fast-Match-Muster, '
                      'das jede Regel braucht.'), 'no_fastmatch'
    groups, problem = position_groups(matches)
    if problem:
        return False, f'Positionsangaben nicht übersetzbar: {problem}', 'position_combo'
    for match in matches:
        if len(match['content']) > MAX_LITERAL_LENGTH:
            return False, (f'Ein Muster ist {len(match["content"])} Zeichen lang - das Signaturformat erlaubt '
                          f'(soweit bekannt) höchstens {MAX_LITERAL_LENGTH}.'), 'too_long'
    for group in groups:
        if group['constrained'] and len(group_to_pcre(group['entries'])) > MAX_PCRE_LENGTH:
            return False, (f'Das Positions-Muster würde länger als {MAX_PCRE_LENGTH} Zeichen - das '
                          'Signaturformat erlaubt (soweit bekannt) nicht mehr.'), 'too_long'
    total = len(matches) + sum(1 for g in groups if g['constrained'])
    if total > MAX_NATIVE_PATTERNS:
        return False, (f'{len(matches)} Muster plus {total - len(matches)} Positions-Muster = {total}, mehr als die '
                      f'{MAX_NATIVE_PATTERNS}, die Citrix selbst nutzt.'), 'too_many'
    return True, None, 'ok'


def summarize_untranslatable(rules, top_reasons=4, top_keys=5):
    """
    Fasst fuer eine Regelliste zusammen, WARUM HTTP-Regeln mit CVE-Bezug nicht
    uebersetzt werden - als lesbarer Text fuer die Oberflaeche. Je blockierender
    Option steht, bei wie vielen Regeln sie vorkommt UND bei wie vielen sie die
    EINZIGE Huerde ist ("distance 2353 / 120"): nur die zweite Zahl sagt, wie viele
    Regeln sich durch Lockern genau dieser Option gewinnen liessen. Leerer String,
    wenn alle uebersetzbar sind.
    """
    codes, keys, sole = collections.Counter(), collections.Counter(), collections.Counter()
    for r in rules:
        if r.get('native_translatable') or not r.get('is_http') or not r.get('cve_ids'):
            continue
        code = r.get('native_translatable_code')
        codes[code] += 1
        blocking = r.get('native_blocking_keys', [])
        if code in ('position', 'pcre', 'other_options'):
            keys.update(blocking)
            if len(blocking) == 1:
                sole[blocking[0]] += 1
    if not codes:
        return ''
    text = ', '.join(f'{REASON_LABELS.get(c, c)}: {n}' for c, n in codes.most_common(top_reasons))
    if keys:
        text += ('. Blockierende Optionen (Regeln gesamt / davon nur durch diese Option blockiert): '
                 + ', '.join(f'{k} {n} / {sole[k]}' for k, n in keys.most_common(top_keys)))
    return text


def parse_rule_line(line):
    """
    Parst eine einzelne Suricata/Snort-Regelzeile. Gibt None zurück für
    Kommentare, leere Zeilen, oder Zeilen, die nicht wie eine Regel aussehen
    (kein Absturz bei unbekanntem/abweichendem Format - übersprungen statt
    das Laden der gesamten Datei abzubrechen).

    Rückgabe: {'sid', 'msg', 'cve_ids' (Liste), 'classtype', 'rev',
               'proto', 'is_http', 'raw'} oder None.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith('#'):
        return None
    match = _HEADER_RE.match(stripped)
    if not match:
        return None

    proto = match.group('proto').lower()
    options_str = match.group('options')
    options = [_parse_option(p) for p in _split_options(options_str)]
    option_keys = {k for k, v in options}
    option_dict = {}
    cve_ids = []
    for key, value in options:
        if key == 'reference' and value and value.lower().startswith('cve,'):
            cve_ids.append(_normalize_cve(value.split(',', 1)[1]))
        elif key not in option_dict:  # erster Wert gewinnt bei Mehrfachnennung (z.B. mehrere 'content')
            option_dict[key] = value

    sid = option_dict.get('sid')
    if not sid:
        return None  # ohne SID keine eindeutig identifizierbare Regel - überspringen

    msg = (option_dict.get('msg') or '').strip('"')
    is_http = proto == 'http' or bool(option_keys & set(_HTTP_OPTION_KEYWORDS))
    content_matches = _extract_content_matches(options)
    blocking = set(option_keys - _ALLOWED_RULE_KEYS)
    if 'flowbits' in blocking and all(_flowbits_harmless(v) for k, v in options if k == 'flowbits'):
        blocking.discard('flowbits')
    blocking_keys = sorted(blocking)
    translatable, translatable_reason, translatable_code = classify_for_native_translation(
        content_matches, blocking_keys, option_dict.get('flow'))

    return {
        'sid': sid,
        'msg': msg,
        'cve_ids': cve_ids,
        'classtype': option_dict.get('classtype'),
        'rev': option_dict.get('rev'),
        'proto': proto,
        'is_http': is_http,
        'raw': stripped,
        'content_matches': content_matches,
        'native_translatable': translatable,
        'native_translatable_reason': translatable_reason,
        'native_translatable_code': translatable_code,
        'native_blocking_keys': blocking_keys,
    }


_DISABLED_RULE_RE = re.compile(r'^\s*#+\s*(?:alert|drop|reject|pass|log)\s+\S+\s+.*\(.*\bsid\s*:\s*\d+', re.IGNORECASE)


def count_disabled_rules(text):
    """
    Zaehlt auskommentierte Regelzeilen ("#alert http ... sid:123;"). ET Open
    kommentiert Regeln aus, die zu viele Fehlalarme liefern, nicht mehr relevant
    oder zu rechenintensiv sind - sie sind also bewusst DEAKTIVIERT, und
    parse_rules_text() ueberspringt sie. Diese Zahl macht sichtbar, wie viel
    dadurch wegfaellt (bei den Webanwendungs-Dateien ist es viel).
    """
    return sum(1 for line in text.splitlines() if _DISABLED_RULE_RE.match(line))


def parse_rules_text(text):
    """
    Parst eine komplette .rules-Datei (mehrzeiliger Text) in eine Liste von
    Regel-Dicts (siehe parse_rule_line). Zeilen, die nicht geparst werden
    können, werden übersprungen statt die ganze Datei abzulehnen - bei
    Regelwerken mit zehntausenden Zeilen ist das robuster als ein
    Alles-oder-nichts-Parser.
    """
    rules = []
    for line in text.splitlines():
        rule = parse_rule_line(line)
        if rule:
            rules.append(rule)
    return rules

