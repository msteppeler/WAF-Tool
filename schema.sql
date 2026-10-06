-- WAF Monitor: SQLite-Schema für die Signatur-Kategorien-Funktion.
--
-- Nur zur Ansicht/Dokumentation gedacht - beim normalen Betrieb legt
-- signature_db.init_db() dieses Schema selbst an (CREATE TABLE IF NOT
-- EXISTS), diese Datei muss dafür NICHT manuell ausgeführt werden. Nützlich
-- z.B., um das Schema ohne Python-Kenntnisse einzusehen, oder um eine leere
-- Datenbankdatei vorab anzulegen (sqlite3 waf_monitor.db < schema.sql).
--
-- Enthält bewusst KEINE Daten (kein tatsächliches Zugangsdaten- oder
-- CVE-Material) - siehe .gitignore, waf_monitor.db selbst wird nicht
-- versioniert.

CREATE TABLE IF NOT EXISTS signature_categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    search_terms TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS signature_category_cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category_id INTEGER NOT NULL REFERENCES signature_categories(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    description TEXT,
    matched_term TEXT,
    published TEXT,
    UNIQUE(category_id, cve_id)
);

CREATE TABLE IF NOT EXISTS signature_category_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category_id INTEGER NOT NULL REFERENCES signature_categories(id) ON DELETE CASCADE,
    profile_name TEXT NOT NULL,
    created_at REAL NOT NULL,
    UNIQUE(category_id, profile_name)
);

CREATE TABLE IF NOT EXISTS signature_rules (
    rule_id TEXT PRIMARY KEY,
    category TEXT,
    log_string TEXT,
    severity TEXT,
    year TEXT
);

CREATE TABLE IF NOT EXISTS signature_rule_cves (
    rule_id TEXT NOT NULL REFERENCES signature_rules(rule_id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    PRIMARY KEY (rule_id, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_signature_rule_cves_cve ON signature_rule_cves(cve_id);

CREATE TABLE IF NOT EXISTS signature_rules_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    source_url TEXT,
    schema_version TEXT,
    file_version TEXT,
    rule_count INTEGER,
    updated_at REAL
);

CREATE TABLE IF NOT EXISTS signature_source_file (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    content BLOB,
    updated_at REAL
);
