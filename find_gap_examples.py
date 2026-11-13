#!/usr/bin/env python3
"""
Einmal-Hilfsskript (nicht Teil der eigentlichen App): listet CVEs, die laut
der aktuell geladenen Snort-Regeldatenbank (ET Open) eine HTTP-relevante
Regel haben, aber laut der aktuell geladenen Citrix-Regeldatenbank KEINE
passende Regel - also genau die Fälle, die beim Erstellen einer Kategorie als
eigene, native Regeln aufgenommen würden. Dient nur der manuellen Kontrolle/Suche nach
einem Testbeispiel, wird von der App selbst nicht aufgerufen.

Voraussetzung: "Regel-Datenbank aktualisieren" wurde mindestens einmal
ausgeführt (befüllt beide Tabellen, Citrix UND Snort).

Aufruf: python3 find_gap_examples.py [max_beispiele]
        python3 find_gap_examples.py --category WordPress   (Aufschluesselung je CVE einer Kategorie)
        python3 find_gap_examples.py --term owncloud        (alle Regeln, die ein Stichwort nennen, und warum sie (nicht) genutzt werden)
        python3 find_gap_examples.py --reasons              (wie viele Snort-Regeln uebersetzbar sind und woran der Rest scheitert)
"""
import sys
import signature_db as db
from snort_rule_parser import parse_rule_line, summarize_untranslatable

def describe_patterns(parsed):
    """Alle Muster einer uebersetzbaren Regel als Text, z.B. METHOD 'POST' + URL '/x'."""
    return ' + '.join(f"{m['location']} {m['content']!r}" for m in parsed['content_matches'])


def source_names(meta):
    """Namen der ET-Dateien, aus denen die Snort-Datenbank besteht (aus source_url)."""
    names = [u.strip().rsplit('/', 1)[-1] for u in (meta.get('source_url') or '').split(',') if u.strip()]
    return ', '.join(n.replace('emerging-', '').replace('.rules', '') for n in names) or 'unbekannt'


def show_reasons():
    """Der Trichter der geladenen Snort-Regeln (geladen -> HTTP -> mit CVE -> uebersetzbar) und die
    Gruende, warum der Rest nicht uebersetzt wird - dieselben Angaben, die beim Aktualisieren der
    Regel-Datenbank ins Server-Log geschrieben werden, hier jederzeit aus der Datenbank berechnet."""
    meta = db.get_snort_rules_meta()
    if not meta or not meta.get('rule_count'):
        print('Snort-Regel-Datenbank ist leer - bitte "Regel-Datenbank aktualisieren" ausfuehren.')
        return
    with db.get_connection() as conn:
        parsed = [p for p in (parse_rule_line(r['raw_rule']) for r in conn.execute('SELECT raw_rule FROM snort_rules')) if p]
    http = [p for p in parsed if p['is_http']]
    with_cve = [p for p in http if p['cve_ids']]
    ok = [p for p in with_cve if p['native_translatable']]
    print(f"Snort-Regel-Datenbank: {meta['rule_count']} Regeln, aus: {source_names(meta)}")
    print(f"{len(http)} HTTP-relevant, {len(with_cve)} davon mit CVE-Bezug, {len(ok)} davon uebersetzbar.")
    print('Nicht uebersetzbar wegen:', summarize_untranslatable(with_cve) or '-')


def show_term(term):
    """Zeigt ALLE Regeln der geladenen Regelwerke, deren Text das Stichwort nennt - und bei
    Snort-Regeln, ob und warum sie uebersetzt werden koennen. Beantwortet "gibt es
    ueberhaupt Regeln zu <Produkt>, und warum wird keine genutzt?" unabhaengig von einer
    Kategorie. Auskommentierte (von ET deaktivierte) Regeln sind nicht in der Datenbank."""
    patterns = db._term_patterns(term)
    meta = db.get_snort_rules_meta()
    print(f'Stichwort "{term}"')
    print('Snort-Regel-Datenbank:',
          f"{meta['rule_count']} Regeln, {meta['http_rule_count']} HTTP-relevant, aus: {source_names(meta)}"
          if meta and meta.get('rule_count') else 'LEER - "Regel-Datenbank aktualisieren" ausfuehren!')
    print()
    with db.get_connection() as conn:
        snort = conn.execute("SELECT sid, msg, is_http, raw_rule FROM snort_rules ORDER BY CAST(sid AS INTEGER)").fetchall()
        snort_cves = {}
        for r in conn.execute("SELECT sid, cve_id FROM snort_rule_cves").fetchall():
            snort_cves.setdefault(r['sid'], []).append(r['cve_id'])
        citrix = conn.execute("SELECT rule_id, category, log_string FROM signature_rules ORDER BY CAST(rule_id AS INTEGER)").fetchall()
        citrix_cves = {}
        for r in conn.execute("SELECT rule_id, cve_id FROM signature_rule_cves").fetchall():
            citrix_cves.setdefault(r['rule_id'], []).append(r['cve_id'])

    hits = [r for r in snort if db._first_matching_term([(term, patterns)], r['msg'])]
    counts = {'ok': 0, 'complex': 0, 'nonhttp': 0, 'nocve': 0}
    print(f'Snort-Regeln, die "{term}" im Text nennen: {len(hits)}')
    for row in hits[:40]:
        cves = ', '.join(snort_cves.get(row['sid'], [])) or 'KEINE CVE-Referenz'
        parsed = parse_rule_line(row['raw_rule'])
        if not row['is_http']:
            status = 'nicht als HTTP erkannt'; counts['nonhttp'] += 1
        elif not snort_cves.get(row['sid']):
            status = 'HTTP, aber ohne CVE-Referenz (kann keiner Kategorie zugeordnet werden)'; counts['nocve'] += 1
        elif parsed and parsed['native_translatable']:
            status = 'UEBERSETZBAR'; counts['ok'] += 1
        else:
            status = 'zu komplex: ' + (parsed['native_translatable_reason'] if parsed else 'Regel nicht lesbar'); counts['complex'] += 1
        print(f"  SID {row['sid']}  [{status}]  {cves}: {row['msg']}")
    if len(hits) > 40:
        print(f'  ... und {len(hits) - 40} weitere')

    chits = [r for r in citrix if db._first_matching_term([(term, patterns)], f"{r['category']} {r['log_string']}")]
    print(f'\nCitrix-Regeln, die "{term}" im Text nennen: {len(chits)}')
    for row in chits[:15]:
        print(f"  Regel {row['rule_id']}  {', '.join(citrix_cves.get(row['rule_id'], [])) or 'keine CVE-Referenz'}: {row['log_string']}")
    if len(chits) > 15:
        print(f'  ... und {len(chits) - 15} weitere')

    print()
    if not hits and not chits:
        print(f'Weder im geladenen Snort- noch im Citrix-Regelwerk nennt eine Regel "{term}".')
        print('Moegliche Gruende: es gibt (aktive) Regeln dazu nicht, die Regeln nennen das Produkt anders, oder die')
        print('Snort-Datenbank ist unvollstaendig (siehe "aus:" oben - sollten vier Dateien sein).')
    else:
        print(f"Zusammenfassung Snort: {counts['ok']} uebersetzbar, {counts['complex']} zu komplex, "
              f"{counts['nocve']} ohne CVE-Referenz, {counts['nonhttp']} nicht als HTTP erkannt; Citrix: {len(chits)} Regeln.")


def show_category(name):
    """Zeigt fuer JEDE CVE einer Kategorie, wo sie landet: Citrix-Regel, uebersetzbare
    Snort-Regel, nur zu komplexe Snort-Regel (mit Grund) oder gar keine Snort-Regel.
    Beantwortet die Frage "warum bekommt meine Kategorie so wenige Regeln?"."""
    categories = db.list_categories()
    match = [c for c in categories if c['name'].lower() == name.lower()]
    if not match:
        print(f'Kategorie "{name}" nicht gefunden. Vorhandene Kategorien: '
              + (', '.join(c['name'] for c in categories) or '(keine)'))
        return
    category = db.get_category(match[0]['id'])
    snort_meta = db.get_snort_rules_meta()
    print(f'Kategorie "{category["name"]}": {len(category["cves"])} CVEs')
    print('Snort-Regel-Datenbank:',
          f"{snort_meta['rule_count']} Regeln, {snort_meta['http_rule_count']} HTTP-relevant"
          if snort_meta and snort_meta.get('rule_count') else 'LEER - "Regel-Datenbank aktualisieren" ausfuehren!')
    print()

    counts = {'citrix': 0, 'snort_ok': 0, 'snort_complex': 0, 'snort_nonhttp': 0, 'none': 0}
    with db.get_connection() as conn:
        for cve in category['cves']:
            cve_id = cve['cve_id']
            if cve['rule_ids']:
                counts['citrix'] += 1
                print(f"  {cve_id}  Citrix-Regel {', '.join(cve['rule_ids'])}")
                continue
            rows = conn.execute(
                """SELECT r.sid, r.msg, r.is_http, r.raw_rule FROM snort_rule_cves c
                   JOIN snort_rules r ON r.sid = c.sid WHERE c.cve_id = ?""", (cve_id,)).fetchall()
            if not rows:
                counts['none'] += 1
                print(f"  {cve_id}  keine Citrix-Regel, KEINE Snort-Regel im geladenen Regelwerk")
                continue
            http_rows = [r for r in rows if r['is_http']]
            if not http_rows:
                counts['snort_nonhttp'] += 1
                print(f"  {cve_id}  keine Citrix-Regel; {len(rows)} Snort-Regel(n), aber keine als HTTP erkannt "
                      f"(SID {rows[0]['sid']}: {rows[0]['msg']})")
                continue
            parsed = [(r, parse_rule_line(r['raw_rule'])) for r in http_rows]
            ok = [(r, p) for r, p in parsed if p and p['native_translatable']]
            if ok:
                counts['snort_ok'] += 1
                r, p = ok[0]
                print(f"  {cve_id}  UEBERSETZBAR: SID {r['sid']}, Muster {describe_patterns(p)}: {r['msg']}")
            else:
                counts['snort_complex'] += 1
                r, p = parsed[0]
                reason = p['native_translatable_reason'] if p else 'Regel nicht lesbar'
                print(f"  {cve_id}  zu komplex: SID {r['sid']} ({r['msg']}) - {reason}")
    print()
    print(f"Zusammenfassung: {counts['citrix']} Citrix, {counts['snort_ok']} per Snort uebersetzbar, "
          f"{counts['snort_complex']} nur zu komplexe Snort-Regel, {counts['snort_nonhttp']} Snort-Regel ohne HTTP-Erkennung, "
          f"{counts['none']} ohne jede Snort-Regel.")


def main():
    if len(sys.argv) > 2 and sys.argv[1] == '--category':
        show_category(' '.join(sys.argv[2:]))
        return
    if len(sys.argv) > 1 and sys.argv[1] == '--reasons':
        show_reasons()
        return
    if len(sys.argv) > 2 and sys.argv[1] == '--term':
        show_term(' '.join(sys.argv[2:]))
        return
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 20

    sig_meta = db.get_signature_rules_meta()
    snort_meta = db.get_snort_rules_meta()
    if not sig_meta or not sig_meta.get('rule_count'):
        print('Citrix-Regel-Datenbank ist leer - bitte zuerst "Regel-Datenbank aktualisieren" ausfuehren.')
        return
    if not snort_meta or not snort_meta.get('rule_count'):
        print('Snort-Regel-Datenbank (ET Open) ist leer oder konnte nicht geladen werden - '
              'bitte zuerst "Regel-Datenbank aktualisieren" ausfuehren und auf Fehler in der Meldung achten.')
        return

    print(f"Citrix-Regel-Datenbank: {sig_meta['rule_count']} Regeln "
          f"(Schema {sig_meta['schema_version']}, Version {sig_meta['file_version']})")
    print(f"Snort-Regel-Datenbank:  {snort_meta['rule_count']} Regeln "
          f"({snort_meta['http_rule_count']} HTTP-relevant), aus: {source_names(snort_meta)}")
    print()

    with db.get_connection() as conn:
        # Alle CVEs, die mindestens eine HTTP-relevante Snort-Regel haben
        snort_cves = [r['cve_id'] for r in conn.execute(
            """SELECT DISTINCT c.cve_id FROM snort_rule_cves c
               JOIN snort_rules r ON r.sid = c.sid WHERE r.is_http = 1"""
        ).fetchall()]
        if not snort_cves:
            print('Keine einzige CVE in der Snort-Datenbank hat eine HTTP-relevante Regel - nichts zu zeigen.')
            return

        # Davon die, die KEINE Citrix-Regel haben
        placeholders = ','.join('?' for _ in snort_cves)
        citrix_covered = {r['cve_id'] for r in conn.execute(
            f"SELECT DISTINCT cve_id FROM signature_rule_cves WHERE cve_id IN ({placeholders})",
            snort_cves
        ).fetchall()}
        gap_cves = [c for c in snort_cves if c not in citrix_covered]

    print(f"{len(snort_cves)} CVEs mit HTTP-relevanter Snort-Regel insgesamt, "
          f"davon {len(gap_cves)} ohne jede Citrix-Regel.\n")

    # Nur Regeln zeigen, die das Tool auch wirklich selbst in eine native
    # NetScaler-Regel uebersetzen kann (siehe snort_rule_parser.classify_for_
    # native_translation) - alle anderen wuerden beim Erstellen uebersprungen
    # bzw. abgelehnt und taugen daher nicht als Testbeispiel.
    translatable, skipped = [], 0
    with db.get_connection() as conn:
        for cve_id in gap_cves:
            rows = conn.execute(
                """SELECT r.sid, r.msg, r.raw_rule FROM snort_rule_cves c
                   JOIN snort_rules r ON r.sid = c.sid
                   WHERE c.cve_id = ? AND r.is_http = 1""",
                (cve_id,)
            ).fetchall()
            for row in rows:
                parsed = parse_rule_line(row['raw_rule'])
                if parsed and parsed['native_translatable']:
                    translatable.append((cve_id, row['sid'], row['msg'], describe_patterns(parsed)))
                else:
                    skipped += 1

    print(f"{len(translatable)} Regeln davon sind einfach genug fuer die automatische Uebersetzung "
          f"({skipped} weitere zu komplex, werden uebersprungen):\n")
    for cve_id, sid, msg, content in translatable[:limit]:
        print(f"  {cve_id}  (Snort SID {sid}, Muster {content}): {msg}")
    if len(translatable) > limit:
        print(f"\n... und {len(translatable) - limit} weitere (Aufruf mit groesserer Zahl zeigt mehr).")

    print("\nZum Testen: eine eigene Kategorie mit genau einer dieser CVEs als Suchbegriff "
          "(z.B. dem betroffenen Produktnamen aus der Snort-Meldung) anlegen und ueber "
          '"In NetScaler erstellen" laufen lassen - die Erfolgsmeldung sollte dann den Satz '
          '"Zusaetzlich N Snort-Regel(n) ... als eigene Regeln uebernommen" enthalten.')


if __name__ == '__main__':
    main()
