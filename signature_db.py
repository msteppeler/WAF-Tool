"""
Lokale Persistenz für Signatur-Kategorien (IIS/Apache/OWA/SharePoint/
WordPress/...) und ihre gegen die NVD abgeglichenen CVEs.

Bewusst SQLite statt Postgres: einzelne Datei, kein eigener Container,
passt zur Nutzung hier (periodisch neu befüllt, dazwischen nur gelesen,
keine parallelen Schreibzugriffe mehrerer Nutzer auf dieselben Zeilen).

WICHTIG FÜR DEN BETRIEB (Docker): Der DB-Pfad liegt per Default relativ
zum Arbeitsverzeichnis. Für Persistenz über einen Container-Neustart
hinweg muss das Verzeichnis, in dem die Datei liegt, als Volume gemountet
werden - sonst ist die Kategorie-Liste nach einem Neustart leer (die
Verbindung zum NetScaler selbst ist davon nicht betroffen, das bleibt wie
bisher rein session-basiert).
"""
import os
import sqlite3
import functools
import re
import time

from snort_rule_parser import parse_rule_line

DB_PATH = os.environ.get('WAF_MONITOR_DB_PATH', os.path.join(os.path.dirname(__file__), 'waf_monitor.db'))


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS signature_categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                search_terms TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS signature_category_cves (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category_id INTEGER NOT NULL REFERENCES signature_categories(id) ON DELETE CASCADE,
                cve_id TEXT NOT NULL,
                description TEXT,
                matched_term TEXT,
                published TEXT,
                UNIQUE(category_id, cve_id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS signature_category_assignments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category_id INTEGER NOT NULL REFERENCES signature_categories(id) ON DELETE CASCADE,
                profile_name TEXT NOT NULL,
                created_at REAL NOT NULL,
                UNIQUE(category_id, profile_name)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS signature_rules (
                rule_id TEXT PRIMARY KEY,
                category TEXT,
                log_string TEXT,
                severity TEXT,
                year TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS signature_rule_cves (
                rule_id TEXT NOT NULL REFERENCES signature_rules(rule_id) ON DELETE CASCADE,
                cve_id TEXT NOT NULL,
                PRIMARY KEY (rule_id, cve_id)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_signature_rule_cves_cve ON signature_rule_cves(cve_id)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS signature_rules_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                source_url TEXT,
                schema_version TEXT,
                file_version TEXT,
                rule_count INTEGER,
                updated_at REAL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS signature_source_file (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                content BLOB,
                updated_at REAL
            )
        """)
        # Snort/Suricata-Regeln (z.B. ET Open) - eigene, von den Citrix-
        # Regeln getrennte Tabellen, da anderes Format/andere Herkunft.
        # Dient dem Lücken-Abgleich: welche CVEs haben eine Snort-Regel,
        # aber keine passende Citrix-Regel (siehe app.py, Kategorie "In
        # NetScaler erstellen").
        conn.execute("""
            CREATE TABLE IF NOT EXISTS snort_rules (
                sid TEXT PRIMARY KEY,
                msg TEXT,
                classtype TEXT,
                rev TEXT,
                is_http INTEGER,
                raw_rule TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS snort_rule_cves (
                sid TEXT NOT NULL REFERENCES snort_rules(sid) ON DELETE CASCADE,
                cve_id TEXT NOT NULL,
                PRIMARY KEY (sid, cve_id)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_snort_rule_cves_cve ON snort_rule_cves(cve_id)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS snort_rules_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                source_url TEXT,
                rule_count INTEGER,
                http_rule_count INTEGER,
                updated_at REAL
            )
        """)


def create_category(name, search_terms):
    """search_terms: Liste von Suchbegriffen (str), als ';'-getrennter String abgelegt."""
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO signature_categories (name, search_terms, created_at) VALUES (?, ?, ?)",
            (name, ';'.join(search_terms), time.time())
        )
        return cur.lastrowid


def add_category_cves(category_id, cves):
    """cves: Liste von Dicts {cve_id, description, matched_term, published}."""
    with get_connection() as conn:
        for cve in cves:
            conn.execute(
                """INSERT OR IGNORE INTO signature_category_cves
                   (category_id, cve_id, description, matched_term, published)
                   VALUES (?, ?, ?, ?, ?)""",
                (category_id, cve['cve_id'], cve.get('description', ''),
                 cve.get('matched_term', ''), cve.get('published', ''))
            )


def list_categories():
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM signature_categories ORDER BY name").fetchall()
        categories = []
        for row in rows:
            cves = conn.execute(
                "SELECT cve_id, description, matched_term, published FROM signature_category_cves "
                "WHERE category_id = ? ORDER BY cve_id",
                (row['id'],)
            ).fetchall()
            cve_dicts = [dict(c) for c in cves]
            rule_map = find_rule_ids_for_cves([c['cve_id'] for c in cve_dicts])
            for c in cve_dicts:
                c['rule_ids'] = rule_map.get(c['cve_id'], [])
            matched_count = sum(1 for c in cve_dicts if c['rule_ids'])
            categories.append({
                'id': row['id'],
                'name': row['name'],
                'search_terms': row['search_terms'].split(';') if row['search_terms'] else [],
                'cve_count': len(cve_dicts),
                'matched_rule_count': matched_count,
                'cves': cve_dicts,
            })
        return categories


def get_category(category_id):
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM signature_categories WHERE id = ?", (category_id,)).fetchone()
        if not row:
            return None
        cves = conn.execute(
            "SELECT * FROM signature_category_cves WHERE category_id = ? ORDER BY cve_id",
            (category_id,)
        ).fetchall()
        cve_dicts = [dict(c) for c in cves]
        rule_map = find_rule_ids_for_cves([c['cve_id'] for c in cve_dicts])
        for c in cve_dicts:
            c['rule_ids'] = rule_map.get(c['cve_id'], [])
        return {
            'id': row['id'],
            'name': row['name'],
            'search_terms': row['search_terms'].split(';') if row['search_terms'] else [],
            'cves': cve_dicts,
        }


def category_name_exists(name):
    with get_connection() as conn:
        row = conn.execute("SELECT 1 FROM signature_categories WHERE name = ?", (name,)).fetchone()
        return row is not None


def count_assignments(category_id):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM signature_category_assignments WHERE category_id = ?", (category_id,)
        ).fetchone()
        return row[0]


def delete_category(category_id):
    with get_connection() as conn:
        conn.execute("DELETE FROM signature_categories WHERE id = ?", (category_id,))


def add_assignment(category_id, profile_name):
    with get_connection() as conn:
        conn.execute(
            """INSERT OR IGNORE INTO signature_category_assignments
               (category_id, profile_name, created_at) VALUES (?, ?, ?)""",
            (category_id, profile_name, time.time())
        )


def list_assignments_by_profile():
    """Gibt {profile_name: [Kategorie-Namen]} zurück, für die Anzeige auf den Profil-Karten."""
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT a.profile_name, c.name AS category_name
            FROM signature_category_assignments a
            JOIN signature_categories c ON c.id = a.category_id
            ORDER BY a.profile_name, c.name
        """).fetchall()
        result = {}
        for row in rows:
            result.setdefault(row['profile_name'], []).append(row['category_name'])
        return result


def replace_signature_rules(rules, source_url, schema_version, file_version):
    """
    Ersetzt die komplette lokale Regel-Datenbank durch 'rules' (Liste von
    Dicts wie von signature_file_parser.parse_signature_file() geliefert).
    Kompletter Ersatz statt Merge, da die Quelle (Citrix-Signaturdatei)
    selbst der vollständige, autoritative Stand ist.
    """
    with get_connection() as conn:
        conn.execute("DELETE FROM signature_rule_cves")
        conn.execute("DELETE FROM signature_rules")
        for rule in rules:
            conn.execute(
                """INSERT INTO signature_rules (rule_id, category, log_string, severity, year)
                   VALUES (?, ?, ?, ?, ?)""",
                (rule['rule_id'], rule.get('category', ''), rule.get('log_string', ''),
                 rule.get('severity', ''), rule.get('year', ''))
            )
            for cve_id in rule.get('cve_ids', []):
                conn.execute(
                    "INSERT OR IGNORE INTO signature_rule_cves (rule_id, cve_id) VALUES (?, ?)",
                    (rule['rule_id'], cve_id)
                )
        conn.execute(
            """INSERT INTO signature_rules_meta (id, source_url, schema_version, file_version, rule_count, updated_at)
               VALUES (1, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                   source_url=excluded.source_url, schema_version=excluded.schema_version,
                   file_version=excluded.file_version, rule_count=excluded.rule_count,
                   updated_at=excluded.updated_at""",
            (source_url, schema_version, file_version, len(rules), time.time())
        )


def get_signature_rules_meta():
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM signature_rules_meta WHERE id = 1").fetchone()
        return dict(row) if row else None


def save_source_file(content_bytes):
    """Speichert die zuletzt geladene, unveränderte Original-Signaturdatei
    (Rohbytes) - Grundlage für build_filtered_signature_xml() beim
    Erstellen eines NetScaler-Signatur-Objekts."""
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO signature_source_file (id, content, updated_at) VALUES (1, ?, ?)
               ON CONFLICT(id) DO UPDATE SET content=excluded.content, updated_at=excluded.updated_at""",
            (content_bytes, time.time())
        )


def get_source_file():
    """Gibt die gespeicherten Rohbytes der zuletzt geladenen Signaturdatei
    zurück, oder None, falls noch keine geladen wurde."""
    with get_connection() as conn:
        row = conn.execute("SELECT content FROM signature_source_file WHERE id = 1").fetchone()
        return row['content'] if row else None


def find_rule_ids_for_cves(cve_ids):
    """Die NetScaler-Regel-IDs, die laut lokaler Regel-Datenbank auf die jeweilige CVE
    referenzieren (üblicherweise 0 oder 1, gelegentlich mehrere) - gibt
    {cve_id: [rule_id, ...]} zurück."""
    if not cve_ids:
        return {}
    with get_connection() as conn:
        placeholders = ','.join('?' for _ in cve_ids)
        rows = conn.execute(
            f"SELECT cve_id, rule_id FROM signature_rule_cves WHERE cve_id IN ({placeholders})",
            list(cve_ids)
        ).fetchall()
        result = {cve_id: [] for cve_id in cve_ids}
        for row in rows:
            result[row['cve_id']].append(row['rule_id'])
        return result


def replace_snort_rules(rules, source_url):
    """
    Ersetzt die komplette lokale Snort-Regel-Datenbank durch 'rules' (Liste
    von Dicts wie von snort_rule_parser.parse_rules_text() geliefert).
    Kompletter Ersatz statt Merge, analog zu replace_signature_rules() -
    die Quelldatei (z.B. ET Open) ist selbst der vollständige Stand.
    """
    with get_connection() as conn:
        conn.execute("DELETE FROM snort_rule_cves")
        conn.execute("DELETE FROM snort_rules")
        http_count = 0
        for rule in rules:
            if rule.get('is_http'):
                http_count += 1
            conn.execute(
                """INSERT INTO snort_rules (sid, msg, classtype, rev, is_http, raw_rule)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (rule['sid'], rule.get('msg', ''), rule.get('classtype'),
                 rule.get('rev'), 1 if rule.get('is_http') else 0, rule['raw'])
            )
            for cve_id in rule.get('cve_ids', []):
                conn.execute(
                    "INSERT OR IGNORE INTO snort_rule_cves (sid, cve_id) VALUES (?, ?)",
                    (rule['sid'], cve_id)
                )
        conn.execute(
            """INSERT INTO snort_rules_meta (id, source_url, rule_count, http_rule_count, updated_at)
               VALUES (1, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                   source_url=excluded.source_url, rule_count=excluded.rule_count,
                   http_rule_count=excluded.http_rule_count, updated_at=excluded.updated_at""",
            (source_url, len(rules), http_count, time.time())
        )


def get_snort_rules_meta():
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM snort_rules_meta WHERE id = 1").fetchone()
        return dict(row) if row else None


def find_snort_rules_for_cves(cve_ids):
    """
    Wie find_rule_ids_for_cves(), aber für die Snort-Regel-Datenbank - gibt
    {cve_id: [Snort-Regel-Dict, ...]} zurück, NUR für als HTTP-relevant
    erkannte Regeln (is_http=1) - der in app.py verlangte Filterschritt
    "nur HTTP-relevante Regeln" wird also bereits hier auf Datenbankebene
    angewendet, nicht erst nachträglich.
    """
    if not cve_ids:
        return {}
    with get_connection() as conn:
        placeholders = ','.join('?' for _ in cve_ids)
        rows = conn.execute(
            f"""SELECT c.cve_id, r.sid, r.msg, r.classtype, r.rev, r.raw_rule
                FROM snort_rule_cves c JOIN snort_rules r ON r.sid = c.sid
                WHERE c.cve_id IN ({placeholders}) AND r.is_http = 1""",
            list(cve_ids)
        ).fetchall()
        result = {cve_id: [] for cve_id in cve_ids}
        for row in rows:
            result[row['cve_id']].append({
                'sid': row['sid'], 'msg': row['msg'],
                'classtype': row['classtype'], 'rev': row['rev'], 'raw': row['raw_rule'],
            })
        return result


# ---------------------------------------------------------------------------
# CVEs aus den Regelwerken ableiten (statt nur aus der NVD)
# ---------------------------------------------------------------------------
# Hintergrund: Die NVD-Stichwortsuche liefert pro Begriff nur die erste Seite
# mit 15 Treffern (vermutlich die aeltesten), die Citrix-Datei kennt aber z.B.
# 216 verschiedene WordPress-CVEs, fast alle von 2018 bis 2025 - eine
# WordPress-Kategorie traf davon nur 2. Deshalb wird der Kategorie zusaetzlich
# jede CVE zugeordnet, deren REGELTEXT (Citrix: Kategorie + LogString, Snort:
# msg) das Stichwort enthaelt. Die NVD liefert dann nur noch Beschreibung und
# Datum fuer ihre eigenen Treffer; fuer diese regelbasierten CVEs steht die
# Regelbeschreibung in der Beschreibung und das Datum bleibt leer.

# Markierung im Feld matched_term: zeigt in der Oberflaeche, woher die CVE
# stammt (die Detailansicht zeigt matched_term als Badge), und erlaubt es, diese
# Zeilen beim erneuten Abgleich gezielt zu ersetzen, ohne NVD-Zeilen anzufassen.
RULE_SOURCE_PREFIX = 'Regeltext: '

# Wörter, die in Produktbezeichnungen vorkommen, aber in Regeltexten nicht
# (oder nur zufaellig) - "Microsoft IIS" heisst dort "WEB-IIS ...", "Apache
# HTTP Server" nur "Apache ...". Uebrig bleibt der unterscheidende Kern.
_GENERIC_TERM_WORDS = {'microsoft', 'server', 'http', 'the', 'and', 'for', 'web', 'application', 'app', 'of'}


def _term_patterns(term):
    """Wandelt einen Suchbegriff in Regex-Muster fuer den Regeltext um: jedes
    unterscheidende Wort muss als GANZES Wort vorkommen ("iis" darf nicht in
    "radiis" treffen, "d-link" bleibt ein Wort)."""
    words = [w for w in term.strip().lower().split() if w]
    core = [w for w in words if w not in _GENERIC_TERM_WORDS] or words
    return [re.compile(r'(?<![a-z0-9])' + re.escape(w) + r'(?![a-z0-9])') for w in core]


def _first_matching_term(term_patterns, text):
    text = (text or '').lower()
    for term, patterns in term_patterns:
        if patterns and all(p.search(text) for p in patterns):
            return term
    return None


@functools.lru_cache(maxsize=20000)
def _is_translatable(raw_rule):
    """Ob eine Snort-Regel automatisch uebersetzbar ist. Zwischengespeichert: beim Abgleich mehrerer
    Kategorien (nach "Regel-Datenbank aktualisieren") treffen dieselben Regeln mehrfach zu."""
    parsed = parse_rule_line(raw_rule)
    return bool(parsed and parsed['native_translatable'])


def find_rule_derived_cves(terms):
    """
    Sucht in den geladenen Regeldatenbanken nach CVEs, deren Regeltext einen der
    Suchbegriffe enthaelt. Gibt (derived, snort_complex_only) zurueck:
    derived = {cve_id: {'description', 'matched_term', 'source'}} mit source
    'Citrix' oder 'Snort'; snort_complex_only = Menge der CVEs, zu denen es
    NUR Snort-Regeln gibt, die das Tool nicht uebersetzen kann (diese werden
    nicht in die Kategorie aufgenommen - sie waeren nicht umsetzbar -, aber
    gezaehlt, damit die Meldung sie benennen kann).

    Citrix hat Vorrang: hat eine CVE eine Citrix-Regel, wird keine Snort-Regel
    zusaetzlich gebraucht. Snort-Regeln zaehlen nur, wenn sie als HTTP erkannt
    UND einfach genug fuer die automatische Uebersetzung sind.
    """
    term_patterns = [(t, _term_patterns(t)) for t in terms if t and t.strip()]
    derived = {}
    snort_complex = set()
    if not term_patterns:
        return derived, snort_complex

    with get_connection() as conn:
        citrix_rows = conn.execute(
            """SELECT r.rule_id, r.category, r.log_string, c.cve_id
               FROM signature_rules r JOIN signature_rule_cves c ON c.rule_id = r.rule_id
               ORDER BY CAST(r.rule_id AS INTEGER)""").fetchall()
        snort_rows = conn.execute(
            """SELECT r.sid, r.msg, r.raw_rule, c.cve_id
               FROM snort_rules r JOIN snort_rule_cves c ON c.sid = r.sid
               WHERE r.is_http = 1 ORDER BY CAST(r.sid AS INTEGER)""").fetchall()

    for row in citrix_rows:
        if row['cve_id'] in derived:
            continue
        term = _first_matching_term(term_patterns, f"{row['category']} {row['log_string']}")
        if term:
            derived[row['cve_id']] = {
                'description': f"Citrix-Regel {row['rule_id']}: {row['log_string']}",
                'matched_term': term, 'source': 'Citrix'}

    for row in snort_rows:
        if row['cve_id'] in derived:
            continue
        term = _first_matching_term(term_patterns, row['msg'])
        if not term:
            continue
        if _is_translatable(row['raw_rule']):
            derived[row['cve_id']] = {
                'description': f"Snort SID {row['sid']}: {row['msg']}",
                'matched_term': term, 'source': 'Snort'}
            snort_complex.discard(row['cve_id'])
        else:
            snort_complex.add(row['cve_id'])
    return derived, snort_complex - set(derived)


def sync_rule_derived_cves(category_id):
    """
    Gleicht die regelbasierten CVEs EINER Kategorie mit den aktuell geladenen
    Regelwerken ab: entfernt die zuvor so eingetragenen Zeilen (matched_term
    beginnt mit RULE_SOURCE_PREFIX) und traegt sie neu ein - so verschwinden
    CVEs, deren Regel in einer neuen Regelversion nicht mehr existiert, und
    neue kommen hinzu. NVD-Zeilen bleiben unangetastet; eine CVE, die schon
    aus der NVD in der Kategorie steht, wird nicht doppelt aufgenommen.

    Gibt {'citrix': n, 'snort': n, 'snort_complex': n, 'snort_complex_cves': [...]}
    zurueck (neu eingetragene CVEs je Quelle, bzw. CVEs, zu denen es nur zu komplexe
    Snort-Regeln gibt, die den Suchbegriff nennen - nicht aufgenommen, aber benannt),
    oder None, wenn die Kategorie nicht existiert.
    """
    with get_connection() as conn:
        row = conn.execute("SELECT search_terms FROM signature_categories WHERE id = ?", (category_id,)).fetchone()
        if not row:
            return None
        terms = [t for t in (row['search_terms'] or '').split(';') if t.strip()]
        conn.execute(
            "DELETE FROM signature_category_cves WHERE category_id = ? AND matched_term LIKE ?",
            (category_id, RULE_SOURCE_PREFIX + '%'))
        existing = {r['cve_id'] for r in conn.execute(
            "SELECT cve_id FROM signature_category_cves WHERE category_id = ?", (category_id,)).fetchall()}

    derived, snort_complex = find_rule_derived_cves(terms)
    complex_cves = sorted(snort_complex - existing)
    stats = {'citrix': 0, 'snort': 0, 'snort_complex': len(complex_cves), 'snort_complex_cves': complex_cves}
    new_rows = []
    for cve_id, info in derived.items():
        if cve_id in existing:
            continue
        stats['citrix' if info['source'] == 'Citrix' else 'snort'] += 1
        new_rows.append({'cve_id': cve_id, 'description': info['description'],
                         'matched_term': RULE_SOURCE_PREFIX + info['matched_term'], 'published': ''})
    add_category_cves(category_id, new_rows)
    return stats


def sync_all_categories_rule_derived_cves():
    """Wie sync_rule_derived_cves(), fuer alle Kategorien - nach jedem
    "Regel-Datenbank aktualisieren" aufgerufen. Gibt {Kategoriename: stats}."""
    with get_connection() as conn:
        categories = conn.execute("SELECT id, name FROM signature_categories ORDER BY name").fetchall()
    return {c['name']: sync_rule_derived_cves(c['id']) for c in categories}
