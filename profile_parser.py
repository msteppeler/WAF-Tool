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
    'creditcard': 'Kreditkarten-Schutz',
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
}

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
            if key.lower().startswith(prefix) and value not in (None, '', [], {}):
                detail_fields[key] = value

        for extra_key in CHECK_EXTRA_FIELDS.get(prefix, []):
            value = profile.get(extra_key)
            if extra_key in profile and value not in (None, '', [], {}):
                detail_fields[extra_key] = value

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
            'details': detail_fields
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
