"""
Aufbereitung von appfwprofile-Objekten für die Darstellung.

Zerlegt die flache NITRO-Feldliste in einzelne Security Checks
(inkl. Learning/Block/Stat/Log) sowie thematisch gruppierte
General Profile Settings.
"""
import re

CHECK_LABELS = {
    'crosssitescripting': 'Cross-Site Scripting (XSS)',
    'sqlinjection': 'SQL Injection',
    'cmdinjection': 'Command Injection',
    'bufferoverflow': 'Buffer Overflow',
    'cookieconsistency': 'Cookie Consistency',
    'fieldconsistency': 'Field Consistency',
    'fieldformat': 'Field Format',
    'csrftag': 'CSRF Tagging',
    'starturl': 'Start URL',
    'denyurl': 'Deny URL',
    'contenttype': 'Content-Type',
    'creditcard': 'Credit Card',
    'safeobject': 'Safe Object',
    'fileuploadtype': 'File Upload Types',
    'xmlformat': 'XML Format',
    'xmlvalidation': 'XML Validation',
    'xmlwsi': 'XML WSI',
    'xmlattachment': 'XML Attachment',
    'xmlsoapfault': 'XML SOAP Fault',
    'xmldos': 'XML Denial of Service',
    'xmlsqlinjection': 'XML SQL Injection',
    'xmlxss': 'XML Cross-Site Scripting',
    'jsondos': 'JSON Denial of Service',
    'jsonsqlinjection': 'JSON SQL Injection',
    'jsonxss': 'JSON Cross-Site Scripting',
    'clickjacking': 'Clickjacking',
    'formfieldconsistency': 'Form Field Consistency',
    'cookiehijacking': 'Cookie Hijacking',
    'postbodylimit': 'Post Body Limit',
    'infercontenttypexmlpayload': 'Infer Content-Type XML Payload',
    'blockkeyword': 'Block Keywords',
    'jsoncmdinjection': 'JSON Command Injection',
    'rest': 'REST API Schema Validation',
    'grpc': 'gRPC API Schema Validation',
}

# Checks, die laut NetScaler-CLI-Referenz KEIN "Learning" kennen (nur
# Block/Log/Stats/None) - vom Nutzer explizit benannt und gegen die
# offizielle CLI-Doku der jeweiligen "*Action"-Parameter geprüft.
# Einzige gefundene Abweichung: Ein reales, veröffentlichtes NetScaler-
# Profil (Blogbeitrag, siehe README) verwendet "-XMLXSSAction learn log
# stats" - dort würde Learning also funktionieren. Trotzdem wie gewünscht
# entfernt; bitte am eigenen Profil gegenprüfen (siehe README).
CHECKS_WITHOUT_LEARN = {
    'denyurl', 'cookiehijacking', 'bufferoverflow', 'postbodylimit',
    'infercontenttypexmlpayload', 'fileuploadtype', 'cmdinjection',
    'blockkeyword', 'xmlformat', 'xmlxss', 'xmlsqlinjection',
    'xmlvalidation', 'xmlsoapfault', 'jsondos', 'jsonxss',
    'jsonsqlinjection', 'jsoncmdinjection', 'rest', 'grpc',
}

# Manche Detail-Felder folgen nicht der "<check>-Präfix"-Namenskonvention
# von NetScaler (z.B. "sessionlessurlclosure" gehört zu Start URL, nicht zu
# einem Präfix "sessionless"). Diese Felder werden hier explizit dem
# jeweiligen Check zugeordnet, statt in den allgemeinen Einstellungen zu landen.
CHECK_EXTRA_FIELDS = {
    'cookieconsistency': ['cookieencryption', 'cookieproxying', 'addcookieflags', 'cookietransforms'],
    'fieldconsistency': ['sessionlessfieldconsistency'],
    'fieldformat': ['defaultfieldformatmaxoccurrences', 'defaultfieldformattype', 'fieldtype'],
    'starturl': ['sessionlessurlclosure', 'refererheadercheck'],
    'creditcard': ['creditcardxout'],
}

# Felder, die trotz passendem Namens-Präfix NIEMALS als Check-Detail gezeigt
# werden sollen - bestätigt kein appfwprofile-Feld, sondern (laut Citrix-
# Dokumentation und einem echten NITRO-278-Fehler) ausschließlich ein
# Bindungs-Parameter für eine einzelne Kartennummer/einen Regex
# (bind appfw profile -creditCardNumber ...), kein Mehrfachauswahl-Feld für
# Kartentypen. Ohne diesen Ausschluss würde die generische Präfix-Erkennung
# es trotzdem wieder aufgreifen, sollte es in irgendeiner NetScaler-Version
# doch im appfwprofile-Objekt auftauchen.
DETAIL_FIELD_BLOCKLIST = {'creditcardnumber'}

# Checkbox-Listen-Felder, die IMMER angezeigt werden sollen, auch wenn sie in
# der rohen NITRO-Antwort ganz fehlen (nicht nur leer sind) - z.B. wenn
# NetScaler ein unkonfiguriertes Mehrfachauswahl-Feld nicht zurückgibt statt
# es mit einem leeren Wert zu liefern. Aktuell leer: der ursprüngliche
# Credit-Card-Eintrag hier beruhte auf einem falschen Feldnamen (siehe
# "creditcardnumber existiert nicht" weiter unten) und wurde entfernt.
CHECKBOX_FIELD_DEFAULTS = {}

# Für ausgewählte Detail-Felder sind die von NetScaler tatsächlich akzeptierten
# Werte bekannt (dieselben Werte/Labels wie im Cookie-Consistency-Transform-
# Dialog der Logging-Seite, siehe cookie_consistency_actions.js) - dafür wird
# im Dashboard ein Dropdown statt eines freien Textfelds angeboten, damit sich
# kein Tippfehler einschleichen kann. Nicht gelistete Felder bekommen ein
# freies Textfeld (NetScaler validiert beim Speichern selbst).
DETAIL_FIELD_OPTIONS = {
    'cookieencryption': [('none', 'None'), ('decryptOnly', 'Decrypt Only'),
                         ('encryptSessionOnly', 'Encrypt Session Only'), ('encryptAll', 'Encrypt All')],
    'cookieproxying': [('none', 'None'), ('sessionOnly', 'Session Only')],
    'addcookieflags': [('none', 'None'), ('secure', 'Secure'), ('httpOnly', 'HTTP Only'), ('all', 'All')],

    # NICHT VERIFIZIERT (siehe README/TECHNICAL_NOTES) - nach dem bereits im
    # Projekt für den SQL-Injection-Dialog verwendeten Namensschema
    # abgeleitet (SQLSplChar/SQLKeyword/SQLSplCharORKeyword/
    # SQLSplCharANDKeyword als NetScaler-CLI-Werte für -SQLInjectionType),
    # "None" dabei nach Nutzerangabe (GUI-Dropdown) ergänzt. Bitte gegen
    # eine echte Appliance prüfen (z.B. einmal in der GUI umstellen und den
    # NITRO-Wert per Postman auslesen), Rückmeldung willkommen.
    'cmdinjectiontype': [('None', 'None'), ('CMDSplChar', 'CMD Special Character'),
                        ('CMDKeyword', 'CMD Keyword'), ('CMDSplCharORKeyword', 'CMD Special Character Or Keyword'),
                        ('CMDSplCharANDKeyword', 'CMD Special Character And Keyword')],
    'jsoncmdinjectiontype': [('None', 'None'), ('CMDSplChar', 'CMD Special Character'),
                            ('CMDKeyword', 'CMD Keyword'), ('CMDSplCharORKeyword', 'CMD Special Character Or Keyword'),
                            ('CMDSplCharANDKeyword', 'CMD Special Character And Keyword')],
    'jsonsqlinjectiontype': [('None', 'None'), ('SQLSplChar', 'SQL Special Character'),
                            ('SQLKeyword', 'SQL Keyword'), ('SQLSplCharORKeyword', 'SQL Special Character Or Keyword'),
                            ('SQLSplCharANDKeyword', 'SQL Special Character And Keyword')],
    'xmlsqlinjectiontype': [('None', 'None'), ('SQLSplChar', 'SQL Special Character'),
                           ('SQLKeyword', 'SQL Keyword'), ('SQLSplCharORKeyword', 'SQL Special Character Or Keyword'),
                           ('SQLSplCharANDKeyword', 'SQL Special Character And Keyword')],
    'sqlinjectiontype': [('None', 'None'), ('SQLSplChar', 'SQL Special Character'),
                        ('SQLKeyword', 'SQL Keyword'), ('SQLSplCharORKeyword', 'SQL Special Character Or Keyword'),
                        ('SQLSplCharANDKeyword', 'SQL Special Character And Keyword')],

    # NICHT VERIFIZIERT - Werte aus der Citrix-CLI-Referenz zu
    # -SQLInjectionParseComments abgeleitet (checkall/ansinested/ansi/
    # nested), Anzeige-Labels nach Nutzerangabe. Bitte gegen eine echte
    # Appliance prüfen.
    'sqlinjectionparsecomments': [('checkall', 'Check All Comments'), ('ansinested', 'ANSI/Nested'),
                                  ('ansi', 'ANSI'), ('nested', 'Nested')],
    'xmlsqlinjectionparsecomments': [('checkall', 'Check All Comments'), ('ansinested', 'ANSI/Nested'),
                                     ('ansi', 'ANSI'), ('nested', 'Nested')],
}
_ON_OFF_OPTIONS = [('ON', 'ON'), ('OFF', 'OFF')]

# Mehrfachauswahl-Felder (Checkbox-Liste statt Dropdown/Textfeld) - der
# NITRO-Wert ist hier eine Liste statt eines Einzelwerts. Aktuell leer: der
# ursprüngliche Credit-Card-Eintrag ("creditcardnumber" mit auswählbaren
# Kartentypen) beruhte auf einer falschen Annahme. Laut Citrix-Dokumentation
# (docs.netscaler.com, "Credit card check") erkennt der Check automatisch
# die gängigen Kartenmuster - es gibt keine Auswahl "welche Kartentypen
# prüfen". "creditCardNumber" existiert auf NetScaler nur als Bindungs-
# Parameter (bind appfw profile -creditCardNumber <nummer/regex> <url>, zur
# Ausnahme einer EINZELNEN Kartennummer von der Prüfung), kein appfwprofile-
# Feld - daher der reale NITRO-Fehler 278 "Invalid argument
# [creditcardnumber]" beim Versuch, es per PUT zu setzen. Bestätigt vom
# Nutzer an der echten Appliance, entfernt statt mit einem neuen falschen
# Feldnamen zu raten; bleibt als Dict-Infrastruktur für ein mögliches
# künftiges, echtes Mehrfachauswahl-Feld.
DETAIL_FIELD_CHECKBOX_OPTIONS = {}

# Verständliche Bezeichnungen für die Detail-Felder eines Checks, statt der
# rohen NITRO-Feldnamen (z.B. "cookieencryption" -> "Encrypt Server
# Cookies"). Bewusst auf Englisch, unabhängig von der gewählten Tool-Sprache
# - dieselbe Begründung wie bei "Learning"/"Block"/"Security Checks": das
# sind NetScalers eigene GUI-Begriffe (wo bekannt, wortgleich mit der
# NetScaler-Oberfläche übernommen), ein Administrator soll sie unabhängig
# von der Tool-Sprache wiedererkennen.
#
# Deckt die Felder ab, die in diesem Projekt bisher konkret vorkamen
# (CHECK_EXTRA_FIELDS oben) sowie weitere, aus der Citrix-CLI-Referenz
# bekannte Felder derselben Checks. Ein nicht gelistetes Feld zeigt
# weiterhin seinen rohen NITRO-Namen (kein Absturz, nur weniger hübsch) -
# bei Bedarf hier einfach ergänzen.
DETAIL_FIELD_LABELS = {
    # Cookie Consistency
    'cookieencryption': 'Encrypt Server Cookies',
    'cookieproxying': 'Proxy Server Cookies',
    'addcookieflags': 'Flags to add in Cookies',
    'cookietransforms': 'Cookie Transforms',
    # Field Consistency
    'sessionlessfieldconsistency': 'Sessionless Field Consistency',
    # Field Format
    'defaultfieldformatmaxoccurrences': 'Max Field Occurrences',
    'defaultfieldformattype': 'Default Field Type',
    'fieldtype': 'Field Type Overrides',
    # Start URL
    'sessionlessurlclosure': 'Sessionless URL Closure',
    'refererheadercheck': 'Referer Header Check',
    # SQL Injection
    'sqlinjectiontype': 'SQL Injection Type',
    'sqlinjectionparsecomments': 'SQL Comments Handling',
    'sqlinjectionchecksqlwildchars': 'Check SQL Wildcards',
    # Cross-Site Scripting
    'crosssitescriptingtransformunsafehtml': 'Transform Unsafe HTML',
    'crosssitescriptingcheckcompleteurls': 'Check Complete URLs',
    # Buffer Overflow
    'bufferoverflowmaxurllength': 'Max URL Length',
    'bufferoverflowmaxheaderlength': 'Max Header Length',
    'bufferoverflowmaxcookielength': 'Max Cookie Length',
    'bufferoverflowmaxquerylength': 'Maximum Query Length',
    'bufferoverflowmaxtotalheaderlength': 'Maximum Total Header Length',
    # Command Injection
    'cmdinjectiontype': 'Command Injection Type',
    'cmdinjectiongrammar': 'Check using CMD Grammar',
    # JSON Command Injection
    'jsoncmdinjectiongrammar': 'Check using CMD Grammar',
    'jsoncmdinjectiontype': 'Check Request Containing',
    # JSON SQL Injection
    'jsonsqlinjectiongrammar': 'Check using SQL Grammar',
    'jsonsqlinjectiontype': 'Check Request Containing',
    # XML SQL Injection
    'xmlsqlinjectionchecksqlwildchars': 'Check for SQL Wildcard Characters',
    'xmlsqlinjectionparsecomments': 'SQL Comments Handling',
    'xmlsqlinjectiontype': 'Check Request Containing',
    # Credit Card
    'creditcardxout': 'X-Out',
    'creditcardmaxallowed': 'Max Credit Card Numbers Allowed',
    # Field Format
    'fieldformatmaxlength': 'Maximum Length',
    'fieldformatminlength': 'Minimum Length',
    # Post Body Limit
    'postbodylimit': 'Post Body Limit (Bytes)',
    # File Upload Types
    'fileuploadtypesaction': 'File Upload Types Action',
    # Deny URL / Custom Signatures - kein eigenes bekanntes Extra-Feld über die Action hinaus
}


def _build_detail_entry(key, value):
    """
    Reichert einen rohen Detail-Feldwert für die editierbare Anzeige an:
    {'value', 'input', 'options', 'label'}. 'input' ist 'select' (bekannte
    oder ON/OFF-Werte), 'text' (sonstiger einfacher Wert - Zahl/Zeichenkette)
    oder 'readonly' (Liste/Dict - z.B. verschachtelte Bindungsdaten; zu
    riskant, um sie generisch editierbar zu machen, NetScaler validiert
    einfache Textfelder ohnehin beim Speichern selbst). 'label' ist die
    verständliche Bezeichnung aus DETAIL_FIELD_LABELS, oder der rohe
    Feldname, falls nicht gelistet.
    """
    label = DETAIL_FIELD_LABELS.get(key, key)
    if key in DETAIL_FIELD_CHECKBOX_OPTIONS:
        # NITRO liefert eine Liste ausgewählter Token; defensiv auch einen
        # einzelnen String (z.B. leerzeichengetrennt) in eine Liste zerlegt,
        # falls NetScaler das Feld doch nicht als Array liefert.
        if isinstance(value, list):
            selected = [str(v) for v in value]
        elif isinstance(value, str) and value:
            selected = value.split()
        else:
            selected = []
        return {'value': selected, 'input': 'checkbox-list',
               'options': DETAIL_FIELD_CHECKBOX_OPTIONS[key], 'label': label}
    if key in DETAIL_FIELD_OPTIONS:
        return {'value': value, 'input': 'select', 'options': DETAIL_FIELD_OPTIONS[key], 'label': label}
    if isinstance(value, bool):
        return {'value': 'ON' if value else 'OFF', 'input': 'select', 'options': _ON_OFF_OPTIONS, 'label': label}
    if isinstance(value, str) and value in ('ON', 'OFF'):
        return {'value': value, 'input': 'select', 'options': _ON_OFF_OPTIONS, 'label': label}
    if isinstance(value, (str, int, float)):
        return {'value': value, 'input': 'text', 'label': label}
    return {'value': value, 'input': 'readonly', 'label': label}

# Lesbare Bezeichnungen für ausgewählte allgemeine Profil-Felder
# (General Profile Settings). Nicht gelistete Felder werden mit ihrem
# rohen Feldnamen angezeigt.
GENERAL_FIELD_LABELS = {
    'type': 'Profiltyp',
    'comment': 'Kommentar',
    'defaults': 'Standard-Vorlage',
    'weblogaction': 'Weblogging',
    'errorurl': 'Error-URL',
    'redirecturl': 'Weiterleitungs-URL',
    'htmlerrorobject': 'HTML-Fehlerobjekt',
    'xmlerrorobject': 'XML-Fehlerobjekt',
    'xmlerrorurl': 'XML-Error-URL',
    'postbodylimit': 'POST-Body-Limit',
    'postbodylimitaction': 'POST-Body-Limit-Aktion',
    'fileuploadmaxnum': 'Max. Datei-Uploads',
    'importsizelimit': 'Import-Größenlimit',
    'requestcontenttype': 'Request Content-Type',
    'responsecontenttype': 'Response Content-Type',
    'sessioncookiename': 'Session-Cookie-Name',
    'logeverypolicyhit': 'Jeden Policy-Treffer loggen',
    'sessiontimeout': 'Session-Timeout',
    'trace': 'Trace',
    'streaming': 'Streaming',
}

# Thematische Gruppierung der "General Profile Settings", angelehnt an die
# Gliederung der NetScaler GUI. Felder, die keiner Gruppe zugeordnet sind,
# landen automatisch in der Gruppe "Weitere Einstellungen".
GENERAL_FIELD_GROUPS = [
    ('Allgemein', ['type', 'comment', 'defaults', 'weblogaction', 'trace', 'streaming']),
    ('Fehlerseiten & Weiterleitung', ['errorurl', 'redirecturl', 'htmlerrorobject', 'xmlerrorobject', 'xmlerrorurl']),
    ('Content- & Größenlimits', ['postbodylimit', 'postbodylimitaction', 'fileuploadmaxnum',
                                  'importsizelimit', 'requestcontenttype', 'responsecontenttype']),
    ('Sitzung & Logging', ['sessioncookiename', 'logeverypolicyhit', 'sessiontimeout']),
]

def parse_action_tokens(raw_value):
    """
    Zerlegt den Wert eines "*action"-Feldes in einzelne Aktions-Tokens.
    NITRO liefert diese Felder je nach Version/Konfiguration entweder als
    Liste (["block", "learn"]) oder als String, der mit Leerzeichen ODER
    Kommas getrennt sein kann ("block learn" bzw. "block,learn").
    """
    if raw_value is None:
        return []
    if isinstance(raw_value, list):
        tokens = [str(t).lower() for t in raw_value]
    else:
        tokens = re.split(r'[\s,]+', str(raw_value).strip().lower())
    return [t for t in tokens if t]

def structure_profile_checks(profile):
    """
    Zerlegt ein appfwprofile-Objekt in einzelne Sicherheits-Checks.
    Jedes Feld, das auf "action" endet (z.B. "sqlinjectionaction"), wird
    als eigener Check behandelt. Die zugehörigen Aktions-Tokens
    (learn/block/log/stat/...) werden ausgewertet. Zugehörige Detail-Felder
    werden zum einen automatisch über den gemeinsamen Feld-Präfix erkannt,
    zum anderen über CHECK_EXTRA_FIELDS für Felder mit abweichender
    Namenskonvention ergänzt.
    Alle übrigen, nicht zugeordneten Felder werden als "General Profile
    Settings" zurückgegeben.
    """
    checks = []
    handled_keys = set()
    action_keys = sorted(k for k in profile.keys() if k.lower().endswith('action'))

    for action_key in action_keys:
        prefix = action_key[:-len('action')]
        if not prefix:
            continue

        tokens = parse_action_tokens(profile.get(action_key))

        detail_fields = {}
        for key, value in profile.items():
            if key == action_key:
                continue
            # Checkbox-Listen-Felder (z.B. Kreditkarten-Typen) werden auch bei
            # einem LEEREN Wert aufgenommen - "keine Typen ausgewählt" ist bei
            # einem editierbaren Mehrfachauswahl-Feld ein normaler, gültiger
            # Zustand, kein "Feld existiert nicht"; sonst verschwindet die
            # ganze Checkbox-Liste, sobald nichts ausgewählt ist (realer
            # Fehler, der beim Nutzer genau so auftrat).
            if key in DETAIL_FIELD_BLOCKLIST:
                continue
            if key.lower().startswith(prefix) and (
                key in DETAIL_FIELD_CHECKBOX_OPTIONS or value not in (None, '', [], {})
            ):
                detail_fields[key] = value

        for extra_key in CHECK_EXTRA_FIELDS.get(prefix, []):
            if extra_key in profile:
                value = profile.get(extra_key)
                if extra_key in DETAIL_FIELD_CHECKBOX_OPTIONS or value not in (None, '', [], {}):
                    detail_fields[extra_key] = value
            elif extra_key in CHECKBOX_FIELD_DEFAULTS:
                # Feld fehlt in der NITRO-Antwort komplett (nicht nur leer) -
                # trotzdem mit Standardwert anzeigen, siehe Kommentar oben.
                detail_fields[extra_key] = CHECKBOX_FIELD_DEFAULTS[extra_key]

        handled_keys.add(action_key)
        handled_keys.update(detail_fields.keys())

        checks.append({
            'key': prefix,
            'action_field': action_key,
            'label': CHECK_LABELS.get(prefix, prefix),
            'supports_learn': prefix not in CHECKS_WITHOUT_LEARN,
            'learn': 'learn' in tokens,
            'block': 'block' in tokens,
            'log': 'log' in tokens,
            'stat': 'stats' in tokens,  # NITRO-Token heisst 'stats' (Plural), nicht 'stat' - vorher falsch
            'active': bool(tokens) and tokens != ['none'],
            'details': {key: _build_detail_entry(key, value) for key, value in detail_fields.items()}
        })

    general_fields_raw = {
        key: value for key, value in profile.items()
        if key not in handled_keys and key != 'name' and value not in (None, '', [], {})
    }

    general_groups = []
    grouped_keys = set()
    for group_name, keys in GENERAL_FIELD_GROUPS:
        items = [
            {'key': key, 'label': GENERAL_FIELD_LABELS.get(key, key), 'value': general_fields_raw[key]}
            for key in keys if key in general_fields_raw
        ]
        if items:
            items.sort(key=lambda item: item['label'])
            general_groups.append({'name': group_name, 'fields': items})
            grouped_keys.update(keys)

    remaining_items = [
        {'key': key, 'label': GENERAL_FIELD_LABELS.get(key, key), 'value': value}
        for key, value in general_fields_raw.items() if key not in grouped_keys
    ]
    if remaining_items:
        remaining_items.sort(key=lambda item: item['label'])
        general_groups.append({'name': 'Weitere Einstellungen', 'fields': remaining_items})

    return checks, general_groups

def enrich_profiles_with_checks(profile_list):
    enriched = []
    for p in profile_list:
        checks, general = structure_profile_checks(p)
        merged = dict(p)
        merged['_checks'] = checks
        merged['_general'] = general
        enriched.append(merged)
    return enriched
