"""
Parser für die öffentliche Citrix-Signaturdatei (z.B.
https://s3.amazonaws.com/NSAppFwSignatures/sigs/sig-r<release>.xml), die auch
intern die Basis von "default_signatures.xml" auf dem NetScaler ist.

Schema (an einer echten, vom Nutzer bereitgestellten Datei verifiziert -
sig-r14.1b0v183s8.xml, schema_version="8"):

    <SignaturesFile schema_version="8" version="183">
      <Signatures>
        <SignatureRule id="509" category="web-misc" enabled="OFF"
                       actions="block,log" severity="HIGH" year="2000" ...>
          <LogString>WEB-MISC PCCS mysql database admin tool access</LogString>
          <PatternList>...</PatternList>
          <Reference>bugtraq,1557</Reference>
          <Reference>cve,2000-0707</Reference>
          <Reference>nessus,10783</Reference>
        </SignatureRule>
        ...
      </Signatures>
    </SignaturesFile>

WICHTIG: Das "id"-Attribut ist genau die NetScaler-interne Regel-ID, die
"import appfw signature ... -sigRuleId <id>" erwartet - das ist die bisher
fehlende Verbindung zwischen einer CVE-Nummer (aus der NVD) und einer
aktivierbaren NetScaler-Regel. Die <Reference>-Kindelemente enthalten
kommagetrennt Typ und Wert; bei Typ "cve" fehlt das Präfix "CVE-" (die Datei
schreibt z.B. "2000-0707", nicht "CVE-2000-0707") - wird hier auf das
NVD-Format normalisiert, damit ein direkter Abgleich mit den in
signature_db gespeicherten CVE-IDs möglich ist.

NICHT VERIFIZIERT: ob schema_version="8" für alle Citrix-Releases gleich
bleibt, und ob abweichende Schema-Versionen andere Attribut-/Elementnamen
verwenden. Der Parser liest nur die hier belegten Felder und ignoriert
alles andere (auch PatternList, die eigentlichen Erkennungsmuster - die
werden nicht gebraucht, NetScaler wendet sie serverseitig selbst an, sobald
eine Regel per ID aktiviert wird).
"""
import re
import requests
import xml.etree.ElementTree as ET

from snort_rule_parser import (
    NATIVE_LOCATION_AREAS, FASTMATCH_AREAS, position_groups, group_to_pcre,
    fit_logstring, MAX_COMMENT_LENGTH, MAX_REFERENCES,
)

REQUEST_TIMEOUT = 60

MAPPING_URL = 'https://s3.amazonaws.com/NSAppFwSignatures/SignaturesMapping.xml'
SIGS_BASE_URL = 'https://s3.amazonaws.com/NSAppFwSignatures/'


def fetch_signature_mapping(mapping_url=MAPPING_URL):
    """
    Lädt und parst SignaturesMapping.xml - die von Citrix selbst gepflegte
    Übersicht, welche Signaturdatei zu welchem NetScaler-Release/-Build/
    -Schema aktuell gehört (dieselbe Datei, die NetScalers eigener
    Auto-Update-Mechanismus nutzt, siehe "SignatureUrl"-Setting). Damit
    muss die konkrete Signaturdatei-URL nicht mehr manuell gepflegt werden -
    neue Citrix-Releases/-Versionen erscheinen hier automatisch.

    Format (an der echten, unter https://s3.amazonaws.com/NSAppFwSignatures/
    SignaturesMapping.xml abgerufenen Datei verifiziert):
        <AppfwSignatures date="2026/09/15 15:27:13">
          <Signature release="14.1" build="0" version="183" schema_version="8">
            <sig_file><file>sigs/sig-r14.1b0v183s8.xml</file>...</sig_file>
          </Signature>
          ...
        </AppfwSignatures>

    Gibt (entries, mapping_date, None) zurück - entries als Liste von Dicts
    {release, build, version, schema_version, file_url}, absteigend sortiert
    nach version (numerisch) dann schema_version (numerisch), sodass
    entries[0] der jeweils aktuellste Eintrag ist. Bei Fehler
    (None, None, Fehlertext).
    """
    try:
        response = requests.get(mapping_url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
    except Exception as e:
        return None, None, f'Fehler beim Herunterladen der Mapping-Datei: {e}'
    try:
        root = ET.fromstring(response.content)
    except ET.ParseError as e:
        return None, None, f'Fehler beim Parsen der Mapping-Datei: {e}'

    entries = []
    for sig_el in root.iter('Signature'):
        file_el = sig_el.find('./sig_file/file')
        if file_el is None or not (file_el.text or '').strip():
            continue
        try:
            version_num = int(sig_el.get('version', '0'))
            schema_num = int(sig_el.get('schema_version', '0'))
        except ValueError:
            version_num, schema_num = 0, 0
        entries.append({
            'release': sig_el.get('release', ''),
            'build': sig_el.get('build', ''),
            'version': sig_el.get('version', ''),
            'schema_version': sig_el.get('schema_version', ''),
            'file_url': SIGS_BASE_URL + file_el.text.strip(),
            '_sort_key': (version_num, schema_num),
        })
    if not entries:
        return None, None, 'Mapping-Datei wurde geladen, enthielt aber keine erkennbaren Signature-Einträge.'
    entries.sort(key=lambda e: e['_sort_key'], reverse=True)
    for e in entries:
        del e['_sort_key']
    mapping_date = root.get('date', '')
    return entries, mapping_date, None



def _normalize_cve_id(raw_value):
    """'2000-0707' -> 'CVE-2000-0707' (NVD-Format). Ist das Präfix schon
    vorhanden oder der Wert nicht CVE-förmig, wird er unverändert/None
    zurückgegeben."""
    raw_value = (raw_value or '').strip()
    if re.match(r'^\d{4}-\d+$', raw_value):
        return f'CVE-{raw_value}'
    if re.match(r'^CVE-\d{4}-\d+$', raw_value, re.IGNORECASE):
        return raw_value.upper()
    return None


def parse_signature_file(xml_bytes):
    """
    Parst den XML-Inhalt einer Citrix-Signaturdatei. Gibt (rules, meta)
    zurück: rules ist eine Liste von Dicts {rule_id, category, log_string,
    severity, year, enabled, actions, cve_ids: [...]}; meta enthält
    {schema_version, version} aus dem Wurzelelement (leer, falls nicht
    vorhanden).
    """
    root = ET.fromstring(xml_bytes)
    meta = {
        'schema_version': root.get('schema_version', ''),
        'version': root.get('version', ''),
    }
    rules = []
    for rule_el in root.iter('SignatureRule'):
        rule_id = rule_el.get('id')
        if not rule_id:
            continue
        cve_ids = []
        for ref_el in rule_el.findall('Reference'):
            text = (ref_el.text or '').strip()
            if ',' not in text:
                continue
            ref_type, _, ref_value = text.partition(',')
            if ref_type.strip().lower() == 'cve':
                normalized = _normalize_cve_id(ref_value)
                if normalized and normalized not in cve_ids:
                    cve_ids.append(normalized)
        log_string_el = rule_el.find('LogString')
        rules.append({
            'rule_id': rule_id,
            'category': rule_el.get('category', ''),
            'log_string': log_string_el.text if log_string_el is not None else '',
            'severity': rule_el.get('severity', ''),
            'year': rule_el.get('year', ''),
            'enabled': rule_el.get('enabled', ''),
            'actions': rule_el.get('actions', ''),
            'cve_ids': cve_ids,
        })
    return rules, meta


def fetch_and_parse_signature_file(url):
    """
    Lädt eine Citrix-Signaturdatei per HTTP (z.B. die öffentliche S3-URL)
    und parst sie. Gibt (rules, meta, raw_bytes, None) zurück, oder (None,
    None, None, Fehlertext) bei einem Netzwerk-/Parse-Fehler - wird nicht
    als Exception nach oben gereicht, damit der Aufrufer eine klare
    Fehlermeldung zeigen kann statt eines Tracebacks. raw_bytes wird
    zusätzlich zurückgegeben, damit der Aufrufer die Originaldatei (z.B. für
    build_filtered_signature_xml) speichern kann, ohne sie erneut laden zu
    müssen.
    """
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
    except Exception as e:
        return None, None, None, f'Fehler beim Herunterladen: {e}'
    try:
        rules, meta = parse_signature_file(response.content)
    except ET.ParseError as e:
        return None, None, None, f'Fehler beim Parsen der XML-Datei: {e}'
    if not rules:
        return None, None, None, 'Datei wurde geladen, aber enthielt keine erkennbaren SignatureRule-Einträge.'
    return rules, meta, response.content, None


# Eigene, von WAF Monitor erzeugte Regeln bekommen IDs ab diesem Wert - der
# Bereich, in dem auch von Hand in der NetScaler-GUI angelegte Regeln landen
# (die Beispielregel des Nutzers hat die ID 1000000, die Citrix-eigenen Regeln
# liegen darunter, bis ca. 3000 in der Beispieldatei Version 161).
NATIVE_RULE_ID_START = 1000000

# Kategorie der erzeugten Regeln - "web-misc" ist die haeufigste Kategorie in
# der Original-Datei (ueber 1800 von rund 3000 Regeln), also ein sicher
# bekannter, gueltiger Wert. Eine genauere Zuordnung (z.B. nach Produkt)
# waere moeglich, ist aber nicht noetig, damit die Regel greift.
NATIVE_RULE_CATEGORY = 'web-misc'

# Aktion der erzeugten Regeln: "block,log", so wie bei den Citrix-eigenen
# Regeln (auf ausdruecklichen Wunsch des Nutzers direkt blockierend). "log"
# daneben sorgt dafuer, dass blockierte Treffer weiterhin in ns.log und damit
# auf der Logging-Seite erscheinen. ACHTUNG: Diese Regeln stammen aus einem
# fremden Regelwerk (ET Open) und wurden nicht gegen den eigenen Verkehr
# geprueft - False Positives koennen legitime Anfragen blockieren. Wer lieber
# erst nur mitschreiben will, setzt hier "log".
NATIVE_RULE_ACTIONS = 'block,log'


def _pick_fastmatch(patterns):
    """
    Waehlt, welches Muster als "fastmatch" gilt (jede Citrix-Regel hat genau
    eines, siehe Datei: 3008 von 3057 Regeln). Moegliche Orte sind die, an denen
    Citrix es selbst setzt (FASTMATCH_AREAS - nie der Post-Body). Vorrang: ein
    von Snort mit "fast_pattern" markiertes Muster, sonst das laengste Muster
    ausserhalb von HTTP_METHOD (Methodenwoerter wie "POST" sind als Vorfilter
    schwach; Citrix nimmt die Methode vor allem bei seltenen wie PROPFIND/LOCK).
    patterns: Liste von (area, match_dict). Gibt den Index zurueck.
    """
    candidates = [i for i, (area, _m) in enumerate(patterns) if area in FASTMATCH_AREAS]
    marked = [i for i in candidates if 'fast_pattern' in patterns[i][1]['modifiers']]
    if marked:
        return marked[0]
    pool = [i for i in candidates if patterns[i][0] != 'HTTP_METHOD'] or candidates
    return max(pool, key=lambda i: len(patterns[i][1]['content']))


def build_native_signature_rule(rule, rule_id):
    """
    Baut aus einer geparsten, als uebersetzbar eingestuften Snort-Regel (siehe
    snort_rule_parser.classify_for_native_translation) ein natives
    <SignatureRule>-Element im NetScaler-eigenen Format - OHNE NetScalers
    "Snort-Umwandlung" (-VendorType Snort), die auf der Appliance des Nutzers
    selbst bei der denkbar einfachsten Regel mit "Problem converting snort
    rules" scheiterte.

    Aufbau nach drei echten Vorlagen aus der vom Nutzer exportierten Datei:
    (1) einer von Hand in der GUI angelegten Regel (id 1000000, "/test" an
    HTTP_URL), (2) den Citrix-eigenen Regeln mit einem Muster, (3) den
    Citrix-eigenen Regeln mit MEHREREN Mustern (z.B. 803: drei URL-Muster;
    16426: Methode + Post-Body + URL). Ein Snort-content wird zu einem
    <Pattern>, alle Muster einer Regel muessen zutreffen (so stellt Citrix
    Snort-Regeln mit mehreren content-Treffern selbst dar). Positionsangaben werden
    zusaetzlich als PCRE-Muster ausgedrueckt (siehe snort_rule_parser.group_to_pcre;
    am Zufallsvergleich mit einem Referenzmodell der Snort-Semantik geprueft). Genau ein Muster
    traegt type="fastmatch" und steht an erster Stelle (so bei 1868 von 1995
    Regeln mit mehreren Mustern). Der Text eines Musters bleibt unveraendert,
    auch Snorts Hex-Schreibweise wie "|3b|" - Citrix macht es genauso.

    NICHT VERIFIZIERT: ob NetScaler eine so erzeugte Regel beim Import
    akzeptiert und wie sie sich zur Laufzeit verhaelt - das aeussert sich erst
    beim echten Import. Insbesondere ist unbekannt, ob NetScaler beim Literal-
    Vergleich Gross-/Kleinschreibung beachtet; Snorts "nocase" kann nicht
    abgebildet werden (kein entsprechendes Attribut in der Datei gefunden).
    """
    patterns = [(NATIVE_LOCATION_AREAS[m['location']], m) for m in rule['content_matches']]
    fastmatch = _pick_fastmatch(patterns)
    order = [fastmatch] + [i for i in range(len(patterns)) if i != fastmatch]

    el = ET.Element('SignatureRule', {
        'id': str(rule_id), 'enabled': 'ON', 'actions': NATIVE_RULE_ACTIONS,
        'category': NATIVE_RULE_CATEGORY, 'source': '', 'severity': '',
        'type': '', 'version': '1', 'sourceid': '', 'harmscore': '',
    })
    request_patterns = ET.SubElement(ET.SubElement(el, 'PatternList'), 'RequestPatterns')
    for index in order:
        area, match = patterns[index]
        attrs = {'type': 'fastmatch'} if index == fastmatch else {}
        pattern = ET.SubElement(request_patterns, 'Pattern', attrs)
        ET.SubElement(pattern, 'Location', {'area': area})
        ET.SubElement(pattern, 'Match', {'type': 'LITERAL'}).text = match['content']

    # Positionsangaben (depth/offset/distance/within/startswith/endswith): je Kette von Mustern
    # desselben Ortes EIN zusaetzliches PCRE-Muster, das Reihenfolge, Abstand und Anker
    # ausdrueckt. Die Literale oben bleiben als Vorfilter erhalten - so macht es auch Citrix
    # in seinen Regeln (z.B. 16426: Literal "<?xml" plus PCRE am selben Ort).
    groups, problem = position_groups(rule['content_matches'])
    if problem:
        raise ValueError(f'Regel {rule.get("sid")} ist nicht uebersetzbar: {problem}')
    for group in groups:
        if group['constrained']:
            pattern = ET.SubElement(request_patterns, 'Pattern')
            ET.SubElement(pattern, 'Location', {'area': NATIVE_LOCATION_AREAS[group['location']]})
            ET.SubElement(pattern, 'Match', {'type': 'PCRE'}).text = group_to_pcre(group['entries'])

    # LogString auf die Schema-Grenze einpassen (NetScaler lehnt die GANZE Datei ab, wenn einer zu lang ist)
    ET.SubElement(el, 'LogString').text = fit_logstring(rule.get('msg'))
    for cve_id in rule.get('cve_ids', [])[:MAX_REFERENCES]:
        # "CVE-2013-3568" -> "cve,2013-3568" (so steht es in den Citrix-Regeln)
        ET.SubElement(el, 'Reference').text = 'cve,' + cve_id[len('CVE-'):]
    ET.SubElement(el, 'Comment').text = f'WAF Monitor SID {rule["sid"]}'[:MAX_COMMENT_LENGTH]
    return el


def build_filtered_signature_xml(xml_bytes, enabled_rule_ids, extra_rules=None):
    """
    Nimmt den Originalinhalt einer Citrix-Signaturdatei und setzt darin JEDE
    <SignatureRule id="..."> auf enabled="ON", wenn ihre ID in
    enabled_rule_ids vorkommt, sonst auf enabled="OFF" - alles andere an der
    Datei (Regeln, Muster, Referenzen, Struktur) bleibt unverändert.

    extra_rules (optional): Liste geparster Snort-Regeln (siehe
    snort_rule_parser), die als NEUE, native Regeln mit eigenen IDs (ab
    NATIVE_RULE_ID_START) in dieselbe Datei aufgenommen werden - aktiviert,
    und NACH der obigen An/Aus-Schleife angehaengt, damit sie nicht von ihr
    wieder ausgeschaltet werden. So bleibt es bei EINEM Import ueber den
    bewaehrten Citrix-Weg, ohne zweiten Import oder Merge.

    Hintergrund: Ein API-Befehl zum \"Klonen\" eines bestehenden Signatur-
    Objekts existiert laut Citrix nicht (vom Nutzer mit dem Citrix-PM
    abgeklärt; zwei reale NITRO-Fehler 3197 beim Versuch, \"import ... DEFAULT
    <name>\" zu nutzen, bestätigen das). Der stattdessen unterstützte, in der
    Doku belegte Weg ist der Import einer SELBST HOCHGELADENEN Datei
    (`import appfw signatures local:signatures.xml MySignatures`) - deshalb
    wird der gewünschte Regelzustand hier direkt in eine eigene Kopie der
    Datei geschrieben, statt ihn nach dem Import per Einzelaufrufen zu
    setzen.

    Gibt die veränderten Bytes zurück (UTF-8, mit XML-Deklaration) und die
    Anzahl der Citrix-Regeln, die auf ON stehen (ohne die extra_rules).
    """
    enabled_set = {str(r) for r in enabled_rule_ids}
    root = ET.fromstring(xml_bytes)
    changed_on = 0
    for rule_el in root.iter('SignatureRule'):
        rule_id = rule_el.get('id')
        if not rule_id:
            continue
        if rule_id in enabled_set:
            rule_el.set('enabled', 'ON')
            changed_on += 1
        else:
            rule_el.set('enabled', 'OFF')

    if extra_rules:
        signatures_el = root.find('Signatures')
        if signatures_el is None:
            signatures_el = root
        existing_ids = [int(r.get('id')) for r in root.iter('SignatureRule')
                        if (r.get('id') or '').isdigit()]
        next_id = max(NATIVE_RULE_ID_START, (max(existing_ids) + 1) if existing_ids else NATIVE_RULE_ID_START)
        # Sortiert nach SID -> bei jedem Neubau derselben Kategorie dieselben IDs
        for rule in sorted(extra_rules, key=lambda r: (int(r['sid']) if str(r['sid']).isdigit() else 0, str(r['sid']))):
            signatures_el.append(build_native_signature_rule(rule, next_id))
            next_id += 1

    xml_bytes_out = ET.tostring(root, encoding='UTF-8', xml_declaration=True)
    return xml_bytes_out, changed_on
