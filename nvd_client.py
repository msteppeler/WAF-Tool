"""
Client für die NVD-API (National Vulnerability Database), um CVEs zu einem
Produkt-Stichwort zu finden. cve.org selbst bietet keine durchsuchbare
Stichwort-API, nur einen kompletten Datei-Export - die NVD macht dieselben
Daten durchsuchbar und ist die praktikable Zugriffsart auf sie.

NICHT LIVE GETESTET: Aus dieser Umgebung besteht kein Netzwerkzugriff auf
services.nvd.nist.gov (Egress-Allowlist). Die Anfrage- und Antwortstruktur
folgt der öffentlich dokumentierten, seit Jahren stabilen NVD-API 2.0
(https://nvd.nist.gov/developers/vulnerabilities) - im Unterschied zu den
undokumentierten NetScaler-Eigenheiten in diesem Projekt ist das ein
ausgereifter, weit verbreiteter Standard, aber bitte trotzdem beim ersten
echten Lauf gegenprüfen.
"""
import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 15

# Ohne eigenen NVD-API-Key gilt ein Limit von 5 Anfragen / 30 Sekunden -
# für die hier vorgesehene interaktive Nutzung (Klick auf "Anlegen", nicht
# Massenabfragen) ausreichend. Ein Key kann optional über die Umgebungs-
# variable gesetzt werden, um das Limit auf 50/30s zu erhöhen.
import os
NVD_API_KEY = os.environ.get('NVD_API_KEY')


def search_cves_by_keyword(keyword, results_limit=15):
    """
    Sucht CVEs, deren Beschreibung das Stichwort enthält (NVD "keywordSearch").
    Gibt eine Liste von Dicts {cve_id, description, published} zurück, oder
    eine leere Liste bei einem Netzwerk-/API-Fehler (wird nicht als
    Ausnahme nach oben gereicht - ein einzelner fehlgeschlagener Suchbegriff
    soll das Anlegen der übrigen Kategorie-Daten nicht verhindern).
    """
    params = {"keywordSearch": keyword, "resultsPerPage": results_limit}
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"FEHLER bei NVD-Anfrage (keyword={keyword!r}): {e}")
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        descriptions = cve.get("descriptions", [])
        description = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
        results.append({
            "cve_id": cve_id,
            "description": description,
            "published": cve.get("published", ""),
        })
    return results
