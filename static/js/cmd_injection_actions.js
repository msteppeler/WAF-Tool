/* Command-Injection-Relaxation (HTML): Token-Dialog aus injection_token_dialog.js
 * mit den Mustertypen Keyword und SpecialString (Command Injection kennt kein
 * Wildchar). Je Muster wird eine Regel angelegt, gebunden an Feld + URL. */

var CMD_TOKEN_DIALOG = {
    title: 'Command Injection: einzelne Muster freigeben',
    endpoint: '/analysis/cmd-injection/relax',
    kind: 'html',
    typeLabels: {
        Keyword: 'Keyword (Befehl)',
        SpecialString: 'Sonderzeichen / Special String'
    },
    help: [
        'Vorauswahl: Im Standardmodus (CMDSplCharANDKeyword) blockt NetScaler nur, wenn Sonderzeichen '
        + 'UND Keyword gefunden werden - die Freigabe des Keywords genügt. Freigegebene Sonderzeichen erweitern '
        + 'die Regel unnötig: Ist z. B. „;“ frei, geht „x; cat y“ durch. Bleibt der Block bestehen '
        + '(anderer Prüfmodus, z. B. nur Sonderzeichen), zusätzlich die Sonderzeichen wählen.',
        'Freigegeben wird nur, was hier steht: Ein freigegebener Befehl (z. B. „ping“) darf in diesem Feld auf '
        + 'dieser URL danach mit beliebigen Sonderzeichen vorkommen. NetScaler meldet nur, was es beanstandet hat - '
        + 'nicht zwingend alle auffälligen Muster; fehlende hier ergänzen oder nach erneutem Test über den nächsten '
        + 'Log-Eintrag freigeben.'
    ]
};

function handleCmdInjectionRelax(button) {
    openInjectionTokenDialog(button, CMD_TOKEN_DIALOG);
}
