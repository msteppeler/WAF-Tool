/* SQL-Injection-Relaxation.
 * html: Token-Dialog (injection_token_dialog.js) - einzelne Muster (Keyword /
 *       SpecialString / Wildchar) prüfen, ändern, ergänzen; je Muster eine Regel.
 * xml / json: einfacher Bestätigungsdialog (NetScaler bietet dort keine
 *       feinere Granularität bzw. sie ist nicht verifiziert). */

var SQL_TOKEN_DIALOG = {
    title: 'SQL-Injection: einzelne Muster freigeben',
    endpoint: '/analysis/sql-injection/relax',
    kind: 'html',
    typeLabels: {
        Keyword: 'Keyword',
        SpecialString: 'Sonderzeichen / Special String',
        Wildchar: 'Wildcard'
    },
    help: [
        'Vorauswahl: Im Standardmodus (Sonderzeichen UND Keyword) blockt NetScaler nur, wenn beides '
        + 'gefunden wird - die Freigabe des Keywords genügt. Freigegebene Sonderzeichen erweitern die Regel '
        + 'unnötig: Ist z. B. „;“ frei, geht „x; drop table t“ durch. Bleibt der Block bestehen '
        + '(anderer Prüfmodus), zusätzlich die Sonderzeichen wählen.',
        'NetScaler meldet nur, was es beanstandet hat - nicht zwingend alle auffälligen Muster des '
        + 'Eingabewerts. Fehlende Muster hier ergänzen oder nach erneutem Test über den nächsten '
        + 'Log-Eintrag freigeben. Keyword-Regeln gelten auch bei aktivierter SQL-Grammar. Meldet der '
        + 'Wildcard-Check später ein Wildchar, dieses als „Wildcard“ ergänzen.'
    ]
};

function handleSqlInjectionRelax(button) {
    if (button.dataset.kind === 'html') {
        openInjectionTokenDialog(button, SQL_TOKEN_DIALOG);
    } else {
        confirmSqlRelaxSimple(button);
    }
}

function confirmSqlRelaxSimple(button) {
    var kind = button.dataset.kind;
    var field = button.dataset.field;
    var location = button.dataset.location;
    var urlPattern = button.dataset.urlPattern;
    var flagged = button.dataset.flagged;
    var kindLabels = { xml: 'XML SQL Injection', json: 'JSON SQL Injection' };

    var lines = [
        'Folgende ' + (kindLabels[kind] || 'SQL-Injection') + '-Relaxation-Regel zum Profil "' + button.dataset.profile + '" hinzufügen?',
        ''
    ];
    if (field) {
        lines.push((kind === 'json' ? 'Gemeldeter Key: ' : 'Feld/Element: ') + field + (location ? ' (' + location + ')' : ''));
    }
    if (flagged) lines.push('Gemeldeter Wert: ' + flagged);
    if (kind !== 'xml') lines.push('URL-Muster: ' + urlPattern);
    lines.push('');
    lines.push(button.dataset.scopeNote);

    if (!window.confirm(lines.join('\n'))) return;

    setActionButtonBusy(button, 'Wird gespeichert…');
    postAnalysisWriteAction('/analysis/sql-injection/relax', {
        profile: button.dataset.profile,
        kind: kind,
        field: field,
        location: location,
        url_pattern: urlPattern
    }, button);
}
