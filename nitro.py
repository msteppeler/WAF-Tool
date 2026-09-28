"""
NITRO-API-Client für NetScaler.

Kapselt Login, Requests und alle lesenden/schreibenden Zugriffe auf
appfwpolicy / appfwprofile. Enthält keine Flask- oder UI-Logik.
"""
import base64
import re
from urllib.parse import quote
import requests

PROTOCOL = "http"

def nitro_login(nsip, username, password):
    url = f"{PROTOCOL}://{nsip}/nitro/v1/config/login"
    payload = {"login": {"username": username, "password": password}}
    try:
        response = requests.post(url, json=payload, verify=False, timeout=10)
        response.raise_for_status()
        data = response.json()
        token = data.get("sessionid") or data.get("nitro_auth_token")
        return token
    except Exception as e:
        print(f"Login-Fehler: {e}")
        return None

def nitro_request(nsip, token, endpoint, method='GET', data=None):
    url = f"{PROTOCOL}://{nsip}{endpoint}"
    headers = {"Content-Type": "application/json", "NITRO_AUTH_TOKEN": token}
    cookies = {"NITRO_AUTH_TOKEN": token}
    try:
        if method.upper() == 'GET':
            response = requests.get(url, headers=headers, cookies=cookies, verify=False, timeout=10)
        elif method.upper() == 'POST':
            response = requests.post(url, headers=headers, cookies=cookies, json=data, verify=False, timeout=10)
        elif method.upper() == 'PUT':
            response = requests.put(url, headers=headers, cookies=cookies, json=data, verify=False, timeout=10)
        elif method.upper() == 'DELETE':
            response = requests.delete(url, headers=headers, cookies=cookies, verify=False, timeout=10)
        else:
            raise ValueError(f"Unsupported method: {method}")
        response.raise_for_status()
        # NITRO liefert bei manchen Config-Updates (PUT/DELETE) einen leeren
        # Body mit HTTP 200/204 zurück. response.json() würde dabei eine
        # Exception werfen und faelschlich als Fehler durchgehen - daher
        # wird ein leerer Erfolg hier explizit als {} behandelt (truthy,
        # aber von None bei echten Fehlern unterscheidbar).
        if not response.content or not response.content.strip():
            return {}
        return response.json()
    except Exception as e:
        print(f"FEHLER bei NITRO-Request ({endpoint}): {e}")
        return None

def _as_list(value):
    """
    Normalisiert ein NITRO-Ergebnisfeld auf eine Liste. NITRO liefert bei
    GENAU EINEM Treffer - egal ob bei einer nach Name abgefragten Bindung
    (z.B. lbvserver_service_binding/<name>) oder einer normalen Auflistung
    (z.B. appfwsignatures mit nur einem Objekt) - ein einzelnes Objekt statt
    eines Arrays mit einem Element. Real aufgetreten (siehe README) für
    appfwsignatures; um denselben Fehler nicht an jeder weiteren Stelle
    einzeln nachzuvollziehen, wird JEDE Listen-Rückgabe aus NITRO über diese
    Funktion normalisiert. Ohne sie würde über die Dict-Keys (Strings) statt
    über das eigentliche Objekt iteriert (AttributeError -> 500).
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def get_waf_policies(nsip, token):
    result = nitro_request(nsip, token, "/nitro/v1/config/appfwpolicy")
    return _as_list(result.get("appfwpolicy")) if result else []

def get_waf_profiles(nsip, token):
    result = nitro_request(nsip, token, "/nitro/v1/config/appfwprofile")
    return _as_list(result.get("appfwprofile")) if result else []

def get_appfw_profile(nsip, token, profile_name):
    """Liest ein einzelnes appfwprofile-Objekt (Read-Modify-Write vor einem Update)."""
    result = nitro_request(nsip, token, f"/nitro/v1/config/appfwprofile/{profile_name}")
    if not result:
        return None
    profiles = result.get("appfwprofile", [])
    if not profiles:
        return None
    return profiles[0] if isinstance(profiles, list) else profiles

def update_appfw_profile(nsip, token, profile_name, updates):
    """
    Aktualisiert ein appfwprofile per PUT mit den in 'updates' übergebenen
    Feldern (z.B. {'bufferoverflowmaxurllength': 960}). 'updates' sollte
    bereits alle zu erhaltenden Werte enthalten (z.B. bestehende Action-
    Tokens), da NITRO PUT das jeweilige Feld ersetzt, nicht zusammenführt.
    Gibt True bei Erfolg zurück, False bei einem HTTP-/NITRO-Fehler.
    """
    endpoint = f"/nitro/v1/config/appfwprofile/{profile_name}"
    data = {"appfwprofile": {"name": profile_name, **updates}}
    result = nitro_request(nsip, token, endpoint, method='PUT', data=data)
    return result is not None

def get_policy_vserver_bindings(nsip, token, policy_name):
    """
    Ermittelt, an welche vServer (LB/CS) eine WAF-Policy gebunden ist.
    Nutzt den NITRO-Endpunkt appfwpolicy_binding, der u.a. die
    Unterobjekte appfwpolicy_lbvserver_binding, appfwpolicy_csvserver_binding
    und appfwpolicy_appfwglobal_binding liefert.
    """
    endpoint = f"/nitro/v1/config/appfwpolicy_binding/{policy_name}"
    result = nitro_request(nsip, token, endpoint)
    if not result:
        return []

    entries = result.get("appfwpolicy_binding", [])
    if not entries:
        return []
    entry = entries[0] if isinstance(entries, list) else entries

    vservers = []
    # Tokens, die NITRO im "boundto"-Feld als Bindepunkt-/Typinfo voranstellt
    # z.B. "REQ VSERVER lb-juice" -> der eigentliche vServer-Name ist "lb-juice"
    boundto_keywords = {
        "REQ", "RESP", "VSERVER", "POLICYLABEL", "GLOBAL",
        "OVERRIDE", "DEFAULT", "OTHERTCP", "REQUEST", "RESPONSE"
    }
    for key in ("appfwpolicy_lbvserver_binding", "appfwpolicy_csvserver_binding"):
        for b in _as_list(entry.get(key)):
            boundto = b.get("boundto") or b.get("name") or ""
            tokens = [t for t in boundto.split() if t.upper() not in boundto_keywords]
            vserver_name = tokens[-1] if tokens else None
            if vserver_name and vserver_name not in vservers:
                vservers.append(vserver_name)

    if entry.get("appfwpolicy_appfwglobal_binding"):
        vservers.append("Global gebunden")

    return vservers

def get_policy_stats(nsip, token):
    result = nitro_request(nsip, token, "/nitro/v1/stat/appfwpolicy")
    stats_list = _as_list(result.get("appfwpolicy")) if result else []
    stats_dict = {}
    for s in stats_list:
        name = s.get('name')
        if name:
            stats_dict[name] = s
    return stats_dict

def get_system_file(nsip, token, filelocation, filename):
    """
    Liest eine Datei über den NITRO-Endpunkt "systemfile" (z.B. ns.log aus
    /var/log). Die Datei wird von NITRO Base64-kodiert und IMMER
    VOLLSTÄNDIG zurückgegeben - es gibt kein Offset/Tail-Lesen über diese
    API. Bei einer aktiven Appliance kann das mehrere MB umfassen; das
    ist bei häufigem Polling zu bedenken (siehe get_appfw_log_entries).
    Gibt den dekodierten Text zurück, oder None bei Fehler
    (z.B. fehlende Berechtigung oder Datei nicht vorhanden).
    """
    endpoint = (
        "/nitro/v1/config/systemfile?args=filelocation:"
        f"{quote(filelocation, safe='')},filename:{quote(filename, safe='')}"
    )
    result = nitro_request(nsip, token, endpoint)
    if not result:
        return None
    files = result.get("systemfile", [])
    if not files:
        return None
    file_obj = files[0] if isinstance(files, list) else files
    content_b64 = file_obj.get("filecontent")
    if not content_b64:
        return None
    try:
        return base64.b64decode(content_b64).decode("utf-8", errors="replace")
    except Exception as e:
        print(f"FEHLER beim Dekodieren von {filename}: {e}")
        return None

def get_appfw_log_text(nsip, token, filelocation='/var/log', filename='ns.log'):
    """Liest die komplette Logdatei (siehe get_system_file) und gibt den
    Rohtext zurück, oder None bei Fehler."""
    return get_system_file(nsip, token, filelocation, filename)

def add_appfw_starturl_binding(nsip, token, profile_name, starturl_pattern, comment=None):
    """
    Fügt eine neue Start-URL-Relaxation-Regel zu einem Profil hinzu
    (POST auf appfwprofile_starturl_binding). 'starturl_pattern' ist ein
    regulärer Ausdruck (PCRE) - im Unterschied zu Cookie/Field Consistency
    gibt es für Start URL kein separates isRegex-Flag, der Wert wird immer
    als Regex interpretiert. Gibt True bei Erfolg zurück.
    """
    endpoint = "/nitro/v1/config/appfwprofile_starturl_binding"
    binding = {"name": profile_name, "starturl": starturl_pattern}
    if comment:
        binding["comment"] = comment
    data = {"appfwprofile_starturl_binding": binding}
    result = nitro_request(nsip, token, endpoint, method='POST', data=data)
    return result is not None

def _extract_nitro_error(response):
    """Liest die Fehlermeldung aus einer NITRO-Fehlerantwort
    (z.B. {"errorcode": 273, "message": "Resource already exists"}).
    Fällt auf den HTTP-Status zurück, wenn kein JSON geliefert wird."""
    try:
        body = response.json()
        message = body.get("message")
        if message:
            code = body.get("errorcode")
            return f"{message} (NITRO {code})" if code else str(message)
    except ValueError:
        pass
    return f"HTTP {response.status_code}"

def add_appfw_binding(nsip, token, binding_type, binding):
    """
    Legt ein Binding-Objekt (z.B. appfwprofile_sqlinjection_binding) per POST
    an. Gibt (True, None) bei Erfolg zurück, sonst (False, Fehlertext) - der
    Fehlertext stammt direkt von NetScaler (z.B. "Resource already exists"
    oder eine Regex-Fehlermeldung), damit die UI die Ursache anzeigen kann.
    """
    url = f"{PROTOCOL}://{nsip}/nitro/v1/config/{binding_type}"
    headers = {"Content-Type": "application/json", "NITRO_AUTH_TOKEN": token}
    cookies = {"NITRO_AUTH_TOKEN": token}
    try:
        response = requests.post(
            url, headers=headers, cookies=cookies,
            json={binding_type: binding}, verify=False, timeout=10
        )
    except Exception as e:
        print(f"FEHLER bei NITRO-Request ({binding_type}): {e}")
        return False, f"Verbindungsfehler zum NetScaler: {e}"
    if response.ok:
        return True, None
    error = _extract_nitro_error(response)
    print(f"FEHLER bei NITRO-Request ({binding_type}): {error}")
    return False, error

def add_appfw_sqlinjection_binding(nsip, token, profile_name, field_name, action_url_regex,
                                   location='FORMFIELD', value_type=None, value_expr=None,
                                   comment=None):
    """
    HTML-SQL-Injection-Relaxation (appfwprofile_sqlinjection_binding), an
    Feldname UND Form-Action-URL gebunden. Der Feldname wird als Literal
    angelegt (isregex_sql=NOTREGEX), die URL ist wie bei NetScaler-Learning
    ein verankerter Regex.

    Mit value_type + value_expr (fein granulare Regel) wird NUR dieses eine
    Muster freigegeben; alle übrigen SQL-Muster werden für Feld + URL weiter
    geprüft. value_type: Keyword | SpecialString | Wildchar; value_expr wird
    als Literal angelegt (isvalueregex_sql=NOTREGEX). Ohne value_type/-expr
    würde das ganze Feld von ALLEN SQL-Prüfungen ausgenommen - das nutzt die
    App bewusst nicht mehr für HTML.
    location: FORMFIELD | HEADER | COOKIE.
    """
    binding = {
        "name": profile_name,
        "sqlinjection": field_name,
        "isregex_sql": "NOTREGEX",
        "formactionurl_sql": action_url_regex,
        "as_scan_location_sql": location,
        "state": "ENABLED",
    }
    if value_type and value_expr:
        binding["as_value_type_sql"] = value_type
        binding["as_value_expr_sql"] = value_expr
        binding["isvalueregex_sql"] = "NOTREGEX"
    if comment:
        binding["comment"] = comment
    return add_appfw_binding(nsip, token, "appfwprofile_sqlinjection_binding", binding)

def add_appfw_xmlsqlinjection_binding(nsip, token, profile_name, element_name,
                                      location='ELEMENT', comment=None):
    """
    XML-SQL-Injection-Relaxation (appfwprofile_xmlsqlinjection_binding).
    ACHTUNG: Diese Regel hat in NetScaler keinen URL-Bezug - sie gilt für
    das genannte Element/Attribut im gesamten Profil.
    location: ELEMENT | ATTRIBUTE.
    """
    binding = {
        "name": profile_name,
        "xmlsqlinjection": element_name,
        "isregex_xmlsql": "NOTREGEX",
        "as_scan_location_xmlsql": location,
        "state": "ENABLED",
    }
    if comment:
        binding["comment"] = comment
    return add_appfw_binding(nsip, token, "appfwprofile_xmlsqlinjection_binding", binding)

def add_appfw_jsonsqlurl_binding(nsip, token, profile_name, url_regex, comment=None):
    """
    JSON-SQL-Injection-Relaxation (appfwprofile_jsonsqlurl_binding), an die
    URL gebunden. ACHTUNG: Es wird nur das URL-Feld gesetzt - die SQL-Prüfung
    entfällt damit für ALLE Keys dieser URL (nicht nur den gemeldeten).
    """
    binding = {
        "name": profile_name,
        "jsonsqlurl": url_regex,
        "state": "ENABLED",
    }
    if comment:
        binding["comment"] = comment
    return add_appfw_binding(nsip, token, "appfwprofile_jsonsqlurl_binding", binding)

def add_appfw_denyurl_binding(nsip, token, profile_name, url_regex, comment=None):
    """
    Legt eine Deny-URL-Regel an (appfwprofile_denyurl_binding). Anders als die
    meisten Relaxations ist das eine Ergänzung (Regel), keine Ausnahme: Zugriffe
    auf URLs, die 'url_regex' (PCRE) treffen, werden gemäß denyurlaction des
    Profils abgewiesen. Deny URL hat Vorrang vor Start URL.
    Gibt (True, None) bei Erfolg zurück, sonst (False, Fehlertext).
    """
    binding = {
        "name": profile_name,
        "denyurl": url_regex,
        "state": "ENABLED",
    }
    if comment:
        binding["comment"] = comment
    return add_appfw_binding(nsip, token, "appfwprofile_denyurl_binding", binding)

def add_appfw_cmdinjection_binding(nsip, token, profile_name, field_name, action_url_regex,
                                   location='FORMFIELD', value_type=None, value_expr=None,
                                   comment=None):
    """
    HTML-Command-Injection-Relaxation (appfwprofile_cmdinjection_binding), an
    Feldname UND Form-Action-URL gebunden - Aufbau wie bei SQL Injection, aber
    mit dem Suffix _cmd. Mit value_type + value_expr wird NUR dieses eine Muster
    freigegeben (value_type: Keyword | SpecialString; value_expr als Literal,
    isvalueregex_cmd=NOTREGEX); alle übrigen Command-Injection-Muster werden für
    Feld + URL weiter geprüft. Der Feldname wird als Literal angelegt
    (isregex_cmd=NOTREGEX), die URL ist ein verankerter Regex.
    location: FORMFIELD | HEADER | COOKIE.
    """
    binding = {
        "name": profile_name,
        "cmdinjection": field_name,
        "isregex_cmd": "NOTREGEX",
        "formactionurl_cmd": action_url_regex,
        "as_scan_location_cmd": location,
        "state": "ENABLED",
    }
    if value_type and value_expr:
        binding["as_value_type_cmd"] = value_type
        binding["as_value_expr_cmd"] = value_expr
        binding["isvalueregex_cmd"] = "NOTREGEX"
    if comment:
        binding["comment"] = comment
    return add_appfw_binding(nsip, token, "appfwprofile_cmdinjection_binding", binding)

def set_cookie_consistency_transform(nsip, token, profile_name, cookie_encryption,
                                     cookie_proxying, add_cookie_flags):
    """
    Stellt den Cookie-Consistency-Check von 'block' auf 'transform' um: liest
    das Profil, entfernt 'block' aus cookieconsistencyaction (log/stats/learn
    bleiben erhalten), aktiviert cookieTransforms und setzt die drei
    Transform-Einstellungen. cookieTransforms muss laut NetScaler-Doku ON
    sein, sonst wirken die drei Einstellungen nicht ("no cookie
    transformations are performed regardless of any other settings").
    Gibt (True, aktualisierte Action-Tokens, ob 'block' vorher gesetzt war)
    oder (False, None, False) zurück; ist das Profil nicht lesbar, wird
    nichts geschrieben.
    """
    profile = get_appfw_profile(nsip, token, profile_name)
    if profile is None:
        return False, None, False

    from profile_parser import parse_action_tokens
    original_tokens = parse_action_tokens(profile.get('cookieconsistencyaction'))
    had_block = 'block' in original_tokens
    tokens = [t for t in original_tokens if t not in ('block', 'none')]

    success = update_appfw_profile(nsip, token, profile_name, {
        'cookieconsistencyaction': tokens,
        'cookietransforms': 'ON',
        'cookieencryption': cookie_encryption,
        'cookieproxying': cookie_proxying,
        'addcookieflags': add_cookie_flags,
    })
    return success, tokens, had_block

def add_appfw_csrftag_binding(nsip, token, profile_name, origin_url_regex, action_url_regex, comment=None):
    """
    CSRF-Form-Tagging-Relaxation (appfwprofile_csrftag_binding). Anders als
    die meisten Checks braucht CSRF ZWEI Muster:
      csrftag           - Form-Origin-URL (PCRE)
      csrfformactionurl  - Form-Action-URL (PCRE), OHNE Query-String
    ANNAHME (Feldnamen nicht mit letzter Sicherheit verifiziert, siehe
    README): "csrftag" = Origin-URL, "csrfformactionurl" = Action-URL - das
    folgt der Namenskonvention aller anderen Bindings (Hauptfeld ohne Suffix
    + "formactionurl_<check>"/"<check>formactionurl") und der Reihenfolge
    der CLI-Syntax "-CSRFTag <originURL> <actionURL>".
    Gibt (True, None) bei Erfolg zurück, sonst (False, Fehlertext).
    """
    binding = {
        "name": profile_name,
        "csrftag": origin_url_regex,
        "csrfformactionurl": action_url_regex,
        "state": "ENABLED",
    }
    if comment:
        binding["comment"] = comment
    return add_appfw_binding(nsip, token, "appfwprofile_csrftag_binding", binding)

# ---------------------------------------------------------------------------
# VServer / Service (Grundlage für die objektbezogene Regel-Erstellung)
# ---------------------------------------------------------------------------
# ANNAHME: Es werden nur LB- und CS-VServer sowie klassische Services/
# ServiceGroups gelesen - GSLB, VPN und andere VServer-Typen sind nicht
# abgedeckt, da sie fuer AppFW-Bindungen unüblich sind.

def get_lb_vservers(nsip, token):
    result = nitro_request(nsip, token, "/nitro/v1/config/lbvserver")
    return _as_list(result.get("lbvserver")) if result else []

def get_cs_vservers(nsip, token):
    result = nitro_request(nsip, token, "/nitro/v1/config/csvserver")
    return _as_list(result.get("csvserver")) if result else []

def get_services(nsip, token):
    result = nitro_request(nsip, token, "/nitro/v1/config/service")
    return _as_list(result.get("service")) if result else []

def get_servicegroups(nsip, token):
    result = nitro_request(nsip, token, "/nitro/v1/config/servicegroup")
    return _as_list(result.get("servicegroup")) if result else []

def get_lbvserver_service_bindings(nsip, token, vserver_name):
    """Services/ServiceGroups, die an einen LB-VServer gebunden sind."""
    endpoint = f"/nitro/v1/config/lbvserver_service_binding/{quote(vserver_name, safe='')}"
    result = nitro_request(nsip, token, endpoint)
    return _as_list(result.get("lbvserver_service_binding")) if result else []

def get_lbvserver_servicegroup_bindings(nsip, token, vserver_name):
    endpoint = f"/nitro/v1/config/lbvserver_servicegroup_binding/{quote(vserver_name, safe='')}"
    result = nitro_request(nsip, token, endpoint)
    return _as_list(result.get("lbvserver_servicegroup_binding")) if result else []

def get_csvserver_lbvserver_binding(nsip, token, vserver_name):
    """An welchen LB-VServer ein CS-VServer per Default weiterleitet (falls konfiguriert)."""
    endpoint = f"/nitro/v1/config/csvserver_lbvserver_binding/{quote(vserver_name, safe='')}"
    result = nitro_request(nsip, token, endpoint)
    return _as_list(result.get("csvserver_lbvserver_binding")) if result else []

def get_vserver_appfwpolicy_bindings(nsip, token, vserver_type, vserver_name):
    """
    Liest die an einen VServer gebundenen AppFW-Policies inkl. Priorität -
    die Umkehrrichtung von get_policy_vserver_bindings() (dort: Policy ->
    VServer-Namen; hier: VServer -> volle Bindungsobjekte mit Priorität).
    vserver_type: 'lb' oder 'cs'.
    """
    binding = "lbvserver_appfwpolicy_binding" if vserver_type == "lb" else "csvserver_appfwpolicy_binding"
    endpoint = f"/nitro/v1/config/{binding}/{quote(vserver_name, safe='')}"
    result = nitro_request(nsip, token, endpoint)
    return _as_list(result.get(binding)) if result else []

def add_appfw_policy(nsip, token, policy_name, rule, profile_name, comment=None):
    """
    Legt eine neue AppFW-Policy an (POST appfwpolicy). CLI-Äquivalent:
    "add appfw policy <name> <rule> <profilename>". Gibt (True, None) bei
    Erfolg zurück, sonst (False, Fehlertext).
    """
    body = {"name": policy_name, "rule": rule, "profilename": profile_name}
    if comment:
        body["comment"] = comment
    return add_appfw_binding(nsip, token, "appfwpolicy", body)

def add_vserver_appfwpolicy_binding(nsip, token, vserver_type, vserver_name, policy_name, priority):
    """
    Bindet eine bestehende AppFW-Policy an einen LB- oder CS-VServer. CLI-
    Äquivalent: "bind lb/cs vserver <name> -policyName <policy> -priority <n>".
    ANNAHME (nicht gegen eine echte Appliance verifiziert): anders als bei
    Responder-/Rewrite-Bindungen ist "-type REQUEST|RESPONSE" bei AppFW-
    Policy-Bindungen laut den gefundenen CLI-Beispielen optional und wird
    hier bewusst weggelassen, da eine AppFW-Policy Request UND Response
    abdeckt. Falls die eigene Appliance das Feld doch verlangt, hier
    "type": "REQUEST" ergänzen.
    WICHTIG: KEIN "comment"-Feld senden - anders als appfwprofile_*_binding
    (SQL/CMD/DenyURL/CSRF) lehnt lbvserver_appfwpolicy_binding /
    csvserver_appfwpolicy_binding dieses Feld ab (NITRO-Fehler 278 "Invalid
    argument [comment]", real aufgetreten - siehe README).
    vserver_type: 'lb' oder 'cs'. Gibt (True, None) oder (False, Fehlertext) zurück.
    """
    binding_type = "lbvserver_appfwpolicy_binding" if vserver_type == "lb" else "csvserver_appfwpolicy_binding"
    body = {"name": vserver_name, "policyname": policy_name, "priority": priority}
    return add_appfw_binding(nsip, token, binding_type, body)

def add_appfw_profile(nsip, token, profile_name, defaults, comment=None):
    """
    Legt ein neues, leeres appfwprofile an. CLI-Äquivalent:
    "add appfw profile <name> -defaults <defaults> [-comment ...]".
    defaults: 'basic' | 'advanced' | 'core' | 'cve'. Typ (HTML/XML) und
    Signatur werden bewusst NICHT hier mitgeschickt, sondern per separatem
    update_appfw_profile()-Aufruf gesetzt - laut Citrix-Doku können
    "defaults" und "type" nicht im selben Aufruf gesetzt werden ("add appfw
    profile" mit -defaults, danach "set appfw profile" für -type).
    Gibt (True, None) oder (False, Fehlertext) zurück.
    """
    body = {"name": profile_name, "defaults": defaults}
    if comment:
        body["comment"] = comment
    return add_appfw_binding(nsip, token, "appfwprofile", body)

def _parse_signature_objects_report(text):
    """
    Parst den Freitext im "response"-Feld von GET appfwsignatures (Format
    der CLI-Ausgabe "show appfw signatures") in einzelne Objekte. Beispiel
    einer Zeile: '1)\\tUrl: default_signatures.xml\\tName: "*Default
    Signatures"\\n\\tCreation Date: ...'. Jeder Eintrag beginnt am
    Zeilenanfang mit "<Zahl>)\\t" und geht bis zum nächsten solchen Marker
    oder bis zur abschließenden "Total signatures Size:"-Zusammenfassung.
    Eingebaute Signatur-Sets (von Citrix mitgeliefert) sind an einem
    führenden "*" im Namen erkennbar, z.B. "*Default Signatures" -
    entsprechend als is_default=True markiert (Analogon zu
    DEFAULT_PROFILE_NAMES bei Profilen).

    Zusätzlich zu name/url/is_default werden die übrigen, je nach Objekt
    unterschiedlich vorhandenen Metadaten mitgelesen (alle optional - z.B.
    fehlt "Comment"/"AutoEnable" bei eingebauten Sets, "Encrypted Version"
    oft bei eigenen): date_label ("Creation Date" oder "Import Date", je
    nachdem was im Text steht), date_value, base_version, size (Bytes als
    int, falls vorhanden), comment, autoenable, encrypted_version. Für die
    "Details anzeigen"-Ansicht der Signatur-Objekte gedacht - anders als bei
    den lokalen Signatur-Kategorien gibt es hier keine CVE-Liste, nur diese
    Objekt-Metadaten aus dem Text.
    """
    if not text:
        return []
    blocks = re.split(r'\n(?=\d+\)\t)', text.strip())
    entries = []
    for block in blocks:
        name_match = re.search(r'Name:\s*"([^"]*)"', block)
        if not name_match:
            continue
        url_match = re.search(r'Url:\s*([^\t\n]+)', block)
        date_match = re.search(r'(Creation|Import) Date:\s*([^\t\n]+)', block)
        base_version_match = re.search(r'Base Version:\s*"([^"]*)"', block)
        size_match = re.search(r'Size:\s*([\d,]+)\s*bytes', block)
        comment_match = re.search(r'Comment:\s*"([^"]*)"', block)
        autoenable_match = re.search(r'AutoEnable New Signatures:\s*"([^"]*)"', block)
        encrypted_match = re.search(r'Encrypted Version:\s*"([^"]*)"', block)
        name = name_match.group(1)
        entries.append({
            'name': name,
            'url': url_match.group(1).strip() if url_match else '',
            'is_default': name.startswith('*'),
            'date_label': (date_match.group(1) + ' Date') if date_match else '',
            'date_value': date_match.group(2).strip() if date_match else '',
            'base_version': base_version_match.group(1) if base_version_match else '',
            'size': int(size_match.group(1).replace(',', '')) if size_match else None,
            'comment': comment_match.group(1) if comment_match else '',
            'autoenable': autoenable_match.group(1) if autoenable_match else '',
            'encrypted_version': encrypted_match.group(1) if encrypted_match else '',
        })
    return entries


def get_appfw_signature_objects(nsip, token):
    """
    Liste der auf dem NetScaler vorhandenen Signature-Objekte. GET
    appfwsignatures OHNE Namen liefert NICHT, wie bei appfwpolicy/
    appfwprofile üblich, eine Liste einzelner Objekte, sondern ein
    einzelnes appfwsignatures-Objekt mit einem "response"-Feld im
    CLI-Textformat - deshalb der separate Text-Parser oben, statt der
    sonst üblichen strukturierten Auswertung.
    """
    result = nitro_request(nsip, token, "/nitro/v1/config/appfwsignatures")
    if not result:
        return []
    objs = _as_list(result.get("appfwsignatures"))
    if not objs or not isinstance(objs[0], dict):
        return []
    return _parse_signature_objects_report(objs[0].get("response", ""))

def delete_appfw_signature_object(nsip, token, signature_name):
    """
    Löscht ein Signatur-Objekt (DELETE appfwsignatures/<name>). CLI-
    Äquivalent: "rm appfw signature <name>". NetScaler weist das laut
    Erwartung ab, solange das Objekt noch einem Profil zugewiesen ist
    (die App prüft das zusätzlich selbst vorab, siehe app.py -
    doppelt abgesichert, damit die Fehlermeldung klar ist statt eines
    rohen NITRO-Fehlers).
    Gibt (True, None) bei Erfolg zurück, sonst (False, Fehlertext).
    """
    url = f"{PROTOCOL}://{nsip}/nitro/v1/config/appfwsignatures/{quote(signature_name, safe='')}"
    headers = {"Content-Type": "application/json", "NITRO_AUTH_TOKEN": token}
    cookies = {"NITRO_AUTH_TOKEN": token}
    try:
        response = requests.delete(url, headers=headers, cookies=cookies, verify=False, timeout=10)
    except Exception as e:
        print(f"FEHLER bei NITRO-Request (delete appfwsignatures {signature_name}): {e}")
        return False, f"Verbindungsfehler zum NetScaler: {e}"
    if response.ok:
        return True, None
    error = _extract_nitro_error(response)
    print(f"FEHLER bei NITRO-Request (delete appfwsignatures {signature_name}): {error}")
    return False, error

def upload_system_file(nsip, token, filelocation, filename, content_bytes):
    """
    Lädt eine Datei auf den NetScaler hoch (POST systemfile). Offiziell
    dokumentiertes Beispiel (developer-docs.netscaler.com,
    "Performing Citrix ADC Resource Operations"):
        {"systemfile": {"filename": "cert1.crt",
                        "filelocation": "/nsconfig/ssl.html",
                        "filecontent": "<Base64>", "fileencoding": "BASE64"}}
    Überschreibt eine gleichnamige, bereits vorhandene Datei stillschweigend
    (kein "-overwrite"-Flag hier gesetzt/geprüft).
    Gibt (True, None) bei Erfolg zurück, sonst (False, Fehlertext).
    """
    body = {
        "filename": filename,
        "filelocation": filelocation,
        "filecontent": base64.b64encode(content_bytes).decode("ascii"),
        "fileencoding": "BASE64",
    }
    url = f"{PROTOCOL}://{nsip}/nitro/v1/config/systemfile"
    headers = {"Content-Type": "application/json", "NITRO_AUTH_TOKEN": token}
    cookies = {"NITRO_AUTH_TOKEN": token}
    try:
        response = requests.post(
            url, headers=headers, cookies=cookies,
            json={"systemfile": body}, verify=False, timeout=60
        )
    except Exception as e:
        print(f"FEHLER bei NITRO-Request (upload systemfile {filename}): {e}")
        return False, f"Verbindungsfehler zum NetScaler: {e}"
    if response.ok:
        return True, None
    error = _extract_nitro_error(response)
    print(f"FEHLER bei NITRO-Request (upload systemfile {filename}): {error}")
    return False, error


def import_appfw_signature_from_file(nsip, token, filelocation, filename, name):
    """
    Erstellt ein neues Signatur-Objekt aus einer zuvor per
    upload_system_file() hochgeladenen Datei. CLI-Äquivalent (laut
    Citrix-Doku belegtes Beispiel): "import appfw signatures
    local:signatures.xml MySignatures".

    HINTERGRUND (siehe README): Ein API-Befehl zum Klonen eines
    BESTEHENDEN Signatur-Objekts existiert laut Citrix nicht (vom Nutzer
    mit dem Citrix-PM abgeklärt; zwei reale NITRO-Fehler 3197 beim Versuch,
    "import ... DEFAULT <name>" zu nutzen - auch ohne jede Regel-Filterung -
    bestätigen das). Der stattdessen unterstützte Weg ist der Import einer
    SELBST HOCHGELADENEN Datei. Der gewünschte Regelzustand (welche Regeln
    aktiv sind) wird deshalb bereits VOR dem Hochladen direkt in die Datei
    geschrieben (siehe signature_file_parser.build_filtered_signature_xml),
    nicht nachträglich per Einzelaufrufen.

    **NICHT VERIFIZIERT**: Weder das genaue Verzeichnis für hochgeladene
    Signaturdateien noch die exakte Auflösung von "src" für eine solche
    Datei (hier: "local:<filename>", dem Dokubeispiel folgend - alternativ
    könnte der vollständige Pfad wie z.B. "/var/tmp/<filename>" nötig sein,
    falls "local:" nicht wie erwartet aufgelöst wird).

    Gibt (True, None) bei Erfolg zurück, sonst (False, Fehlertext).
    """
    body = {"name": name, "src": f"local:{filename}"}
    url = f"{PROTOCOL}://{nsip}/nitro/v1/config/appfwsignatures?action=import"
    headers = {"Content-Type": "application/json", "NITRO_AUTH_TOKEN": token}
    cookies = {"NITRO_AUTH_TOKEN": token}
    try:
        response = requests.post(
            url, headers=headers, cookies=cookies,
            json={"appfwsignatures": body}, verify=False, timeout=60
        )
    except Exception as e:
        print(f"FEHLER bei NITRO-Request (import appfwsignatures {name} von Datei): {e}")
        return False, f"Verbindungsfehler zum NetScaler: {e}"
    if response.ok:
        return True, None
    error = _extract_nitro_error(response)
    print(f"FEHLER bei NITRO-Request (import appfwsignatures {name} von Datei): {error}")
    return False, error
