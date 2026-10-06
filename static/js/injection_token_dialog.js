/* Generischer Dialog "einzelne Muster freigeben" (SQL Injection, Command Injection).
 *
 * Zeigt die aus der Log-Meldung erkannten Muster (Keyword / SpecialString / ...)
 * zur Prüfung, lässt sie abwählen, ändern und ergänzen und legt je Muster eine
 * Relaxation Rule an. Die Unterschiede zwischen den Checks (Titel, Hilfetexte,
 * erlaubte Mustertypen, Endpunkt) kommen über das cfg-Objekt:
 *   cfg.title, cfg.endpoint, cfg.kind (optional, wird mitgesendet),
 *   cfg.typeLabels  { Typ: Anzeigename, ... }  (Reihenfolge = Auswahlreihenfolge)
 *   cfg.help        [Absatz, ...]              (Erklärtexte unter dem Kontext)
 * Erwartete data-Attribute am Button: profile, field, location, url-pattern,
 * flagged, tokens (JSON-Liste [{type, value, checked}]), scope-note. */

function injEl(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}

function showInjectionToast(message, isError) {
    var toast = injEl('div', 'sql-toast' + (isError ? ' sql-toast-error' : ''), message);
    document.body.appendChild(toast);
    setTimeout(function () { toast.remove(); }, 10000);
}

function openInjectionTokenDialog(button, cfg) {
    var profile = button.dataset.profile;
    var field = button.dataset.field;
    var location = button.dataset.location;
    var urlPattern = button.dataset.urlPattern;
    var flagged = button.dataset.flagged;
    var typeKeys = Object.keys(cfg.typeLabels);
    var tokens = [];
    try { tokens = JSON.parse(button.dataset.tokens || '[]'); } catch (e) { tokens = []; }

    var overlay = injEl('div', 'sql-dialog-overlay');
    var dialog = injEl('div', 'sql-dialog');
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    overlay.appendChild(dialog);

    dialog.appendChild(injEl('h3', 'sql-dialog-title', cfg.title));

    var context = injEl('div', 'sql-dialog-context');
    [
        ['Profil', profile],
        ['Feld', field + ' (' + location + ')'],
        ['URL-Muster', urlPattern],
        ['Gemeldeter Wert', flagged || '–']
    ].forEach(function (pair) {
        var row = injEl('div', 'sql-dialog-context-row');
        row.appendChild(injEl('span', 'k', pair[0]));
        row.appendChild(injEl('span', 'v', pair[1]));
        context.appendChild(row);
    });
    dialog.appendChild(context);

    dialog.appendChild(injEl('p', 'sql-dialog-note', button.dataset.scopeNote));
    cfg.help.forEach(function (paragraph) {
        dialog.appendChild(injEl('p', 'sql-dialog-help', paragraph));
    });

    var rows = injEl('div', 'sql-token-rows');
    dialog.appendChild(rows);

    function addRow(type, value, checked) {
        var row = injEl('div', 'sql-token-row');

        var check = document.createElement('input');
        check.type = 'checkbox';
        check.checked = checked !== false;
        check.setAttribute('aria-label', 'Muster freigeben');
        row.appendChild(check);

        var select = document.createElement('select');
        typeKeys.forEach(function (key) {
            var option = document.createElement('option');
            option.value = key;
            option.textContent = cfg.typeLabels[key];
            select.appendChild(option);
        });
        select.value = type && cfg.typeLabels[type] ? type : typeKeys[0];
        row.appendChild(select);

        var input = document.createElement('input');
        input.type = 'text';
        input.className = 'sql-token-input';
        input.value = value || '';
        input.placeholder = 'exaktes Muster, z. B. or oder ;';
        input.autocomplete = 'off';
        input.spellcheck = false;
        row.appendChild(input);

        var remove = injEl('button', 'sql-token-remove', '×');
        remove.type = 'button';
        remove.title = 'Zeile entfernen';
        remove.addEventListener('click', function () { row.remove(); });
        row.appendChild(remove);

        rows.appendChild(row);
        return input;
    }

    tokens.forEach(function (t) { addRow(t.type, t.value, t.checked !== false); });
    if (tokens.length === 0) {
        dialog.insertBefore(
            injEl('p', 'sql-dialog-warn',
                'Aus der Meldung konnten keine Muster erkannt werden - bitte unten manuell erfassen.'),
            rows);
        addRow('Keyword', '', true);
    }

    var addButton = injEl('button', 'sql-dialog-add', '+ Muster hinzufügen');
    addButton.type = 'button';
    addButton.addEventListener('click', function () { addRow('Keyword', '', true).focus(); });
    dialog.appendChild(addButton);

    var errorLine = injEl('div', 'sql-dialog-error');
    dialog.appendChild(errorLine);

    var actions = injEl('div', 'sql-dialog-actions');
    var cancel = injEl('button', 'sql-dialog-cancel', 'Abbrechen');
    cancel.type = 'button';
    var submit = injEl('button', 'sql-dialog-submit', 'Regeln erstellen');
    submit.type = 'button';
    actions.appendChild(cancel);
    actions.appendChild(submit);
    dialog.appendChild(actions);

    function close() {
        document.removeEventListener('keydown', onKey);
        overlay.remove();
        if (document.body.contains(button)) button.focus();
    }
    function onKey(event) { if (event.key === 'Escape') close(); }
    document.addEventListener('keydown', onKey);
    cancel.addEventListener('click', close);

    submit.addEventListener('click', function () {
        var selected = [];
        rows.querySelectorAll('.sql-token-row').forEach(function (row) {
            if (!row.querySelector('input[type=checkbox]').checked) return;
            var value = row.querySelector('.sql-token-input').value;
            if (value === '') return;
            selected.push({ type: row.querySelector('select').value, value: value });
        });
        if (selected.length === 0) {
            errorLine.textContent = 'Bitte mindestens ein Muster auswählen bzw. ausfüllen.';
            return;
        }
        close();
        var payload = {
            profile: profile, field: field, location: location,
            url_pattern: urlPattern, tokens: selected
        };
        if (cfg.kind) payload.kind = cfg.kind;
        submitInjectionTokens(button, cfg.endpoint, payload);
    });

    document.body.appendChild(overlay);
    var firstInput = rows.querySelector('.sql-token-input');
    if (firstInput) firstInput.focus();
}

function submitInjectionTokens(button, endpoint, payload) {
    setActionButtonBusy(button, 'Wird gespeichert…');

    // Der periodische Refresh ersetzt die Log-Karten; ist der Button dann nicht
    // mehr im DOM, wird das Ergebnis als Hinweis eingeblendet statt zu verpuffen.
    function report(success, message) {
        if (document.body.contains(button)) {
            setActionButtonResult(button, success, message);
        } else {
            showInjectionToast(message, !success);
        }
    }

    fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    })
        .then(function (response) {
            return response.json().then(function (data) { return { status: response.status, data: data }; });
        })
        .then(function (result) {
            if (result.status === 401) {
                report(false, 'Sitzung abgelaufen – bitte neu anmelden.');
                return;
            }
            report(!!result.data.success, result.data.message || 'Unbekannter Fehler.');
        })
        .catch(function () {
            report(false, 'Netzwerkfehler – bitte erneut versuchen.');
        });
}
