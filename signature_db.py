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
import time

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


def find_rule_ids_for_cve(cve_id):
    """Liste der NetScaler-Regel-IDs, die laut lokaler Regel-Datenbank auf
    diese CVE referenzieren (üblicherweise 0 oder 1, gelegentlich mehrere)."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT rule_id FROM signature_rule_cves WHERE cve_id = ?", (cve_id,)
        ).fetchall()
        return [r['rule_id'] for r in rows]


def find_rule_ids_for_cves(cve_ids):
    """Wie find_rule_ids_for_cve(), aber für mehrere CVEs auf einmal - gibt
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
