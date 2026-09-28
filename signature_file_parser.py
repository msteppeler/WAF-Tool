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

REQUEST_TIMEOUT = 60


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


def build_filtered_signature_xml(xml_bytes, enabled_rule_ids):
    """
    Nimmt den Originalinhalt einer Citrix-Signaturdatei und setzt darin JEDE
    <SignatureRule id="..."> auf enabled="ON", wenn ihre ID in
    enabled_rule_ids vorkommt, sonst auf enabled="OFF" - alles andere an der
    Datei (Regeln, Muster, Referenzen, Struktur) bleibt unverändert.

    Hintergrund: Ein API-Befehl zum "Klonen" eines bestehenden Signatur-
    Objekts existiert laut Citrix nicht (vom Nutzer mit dem Citrix-PM
    abgeklärt; zwei reale NITRO-Fehler 3197 beim Versuch, "import ... DEFAULT
    <name>" zu nutzen, bestätigen das). Der stattdessen unterstützte, in der
    Doku belegte Weg ist der Import einer SELBST HOCHGELADENEN Datei
    (`import appfw signatures local:signatures.xml MySignatures`) - deshalb
    wird der gewünschte Regelzustand hier direkt in eine eigene Kopie der
    Datei geschrieben, statt ihn nach dem Import per Einzelaufrufen zu
    setzen.

    Gibt die veränderten Bytes zurück (UTF-8, mit XML-Deklaration).
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
    xml_bytes_out = ET.tostring(root, encoding='UTF-8', xml_declaration=True)
    return xml_bytes_out, changed_on
