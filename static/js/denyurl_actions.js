/* Deny-URL-Regel aus einem geloggten Aufruf (Policy Hit) erzeugen.
 * Öffnet einen Dialog mit dem vorgeschlagenen Muster (editierbar, mit
 * Live-Prüfung gegen die geloggte URL) und legt die Regel per NITRO an. */

function denyEl(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}

function showDenyToast(message, isError) {
    var toast = denyEl('div', 'sql-toast' + (isError ? ' sql-toast-error' : ''), message);
    document.body.appendChild(toast);
    setTimeout(function () { toast.remove(); }, 12000);
}

function handleDenyUrlAdd(button) {
    var profile = button.dataset.profile;
    var fullUrl = button.dataset.url;
    var baseUrl = button.dataset.baseUrl;
    var path = button.dataset.path;
    var presets = {
        tolerant: button.dataset.pattern,
        exact: button.dataset.patternExact,
        path: button.dataset.patternPath
    };
    var search = '';
    try { search = new URL(fullUrl).search; } catch (e) { search = ''; }

    // Darstellungen, in denen NetScaler die URL gegen das Muster prüfen könnte
    // (nicht belegt) - das Muster sollte alle treffen.
    var forms = [
        ['URL mit Host', baseUrl],
        ['URL mit Host + Query', baseUrl + search],
        ['nur Pfad', path],
        ['Pfad + Query', path + search]
    ];

    var overlay = denyEl('div', 'sql-dialog-overlay');
    var dialog = denyEl('div', 'sql-dialog');
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    overlay.appendChild(dialog);

    dialog.appendChild(denyEl('h3', 'sql-dialog-title', 'Deny URL: Zugriff auf diese URL abweisen'));

    var context = denyEl('div', 'sql-dialog-context');
    [['Profil', profile], ['Geloggte URL', fullUrl]].forEach(function (pair) {
        var row = denyEl('div', 'sql-dialog-context-row');
        row.appendChild(denyEl('span', 'k', pair[0]));
        row.appendChild(denyEl('span', 'v', pair[1]));
        context.appendChild(row);
    });
    dialog.appendChild(context);

    dialog.appendChild(denyEl('label', 'sql-dialog-note', 'Variante:'));
    var presetSelect = document.createElement('select');
    presetSelect.className = 'deny-preset-select';
    [
        ['tolerant', 'Empfohlen: Host und Query-String egal'],
        ['exact', 'Streng: Schema + Host + Pfad, ohne Query'],
        ['path', 'Nur Pfad (unabhängig vom Host)'],
        ['custom', 'Angepasst']
    ].forEach(function (pair) {
        var option = document.createElement('option');
        option.value = pair[0];
        option.textContent = pair[1];
        presetSelect.appendChild(option);
    });
    dialog.appendChild(presetSelect);

    dialog.appendChild(denyEl('label', 'sql-dialog-note', 'Deny-URL-Muster (PCRE-Regex):'));
    var input = document.createElement('input');
    input.type = 'text';
    input.className = 'deny-pattern-input';
    input.value = presets.tolerant;
    input.autocomplete = 'off';
    input.spellcheck = false;
    dialog.appendChild(input);

    var checkLine = denyEl('div', 'deny-check-line');
    dialog.appendChild(checkLine);

    dialog.appendChild(denyEl('p', 'sql-dialog-help',
        'Achtung: Ab sofort werden alle Zugriffe, die dieses Muster treffen, abgewiesen (sofern die '
        + 'Deny-URL-Aktion des Profils „block“ enthält). Deny URL hat Vorrang vor Start URL. '
        + 'Es ist nicht belegt, gegen welche Darstellung der URL NetScaler das Muster prüft (mit Host, nur Pfad, '
        + 'mit/ohne Query-String). Die empfohlene Variante trifft deshalb alle Darstellungen desselben Pfades; '
        + 'die Prüfzeile zeigt, welche das aktuelle Muster abdeckt. Mit einem gröberen Muster '
        + '(z. B. Verzeichnis oder Endung) lassen sich mehrere URLs auf einmal sperren - dann besonders sorgfältig prüfen.'));

    var errorLine = denyEl('div', 'sql-dialog-error');
    dialog.appendChild(errorLine);

    var actions = denyEl('div', 'sql-dialog-actions');
    var cancel = denyEl('button', 'sql-dialog-cancel', 'Abbrechen');
    cancel.type = 'button';
    var submit = denyEl('button', 'sql-dialog-submit', 'Deny-Regel erstellen');
    submit.type = 'button';
    actions.appendChild(cancel);
    actions.appendChild(submit);
    dialog.appendChild(actions);

    // Live-Prüfung: welche URL-Darstellungen trifft das Muster? (JavaScript-Regex ist
    // nicht identisch mit PCRE - daher nur ein Hinweis.)
    function updateCheck() {
        var value = input.value;
        checkLine.className = 'deny-check-line';
        if (value.trim() === '') {
            checkLine.textContent = '';
            return;
        }
        var regex;
        try {
            regex = new RegExp(value);
        } catch (e) {
            checkLine.classList.add('deny-check-neutral');
            checkLine.textContent = 'Muster lässt sich hier nicht prüfen (PCRE-Syntax) - NetScaler validiert beim Anlegen.';
            return;
        }
        var hits = forms.map(function (form) { return regex.test(form[1]); });
        var matched = hits.filter(Boolean).length;
        var text = forms.map(function (form, i) { return (hits[i] ? '✓ ' : '✗ ') + form[0]; }).join('   ');
        if (matched === forms.length) {
            checkLine.classList.add('deny-check-ok');
            checkLine.textContent = 'Trifft alle Darstellungen:  ' + text;
        } else if (matched === 0) {
            checkLine.classList.add('deny-check-warn');
            checkLine.textContent = '⚠ Trifft keine Darstellung der geloggten URL - der Aufruf würde weiter durchgelassen.  ' + text;
        } else {
            checkLine.classList.add('deny-check-neutral');
            checkLine.textContent = 'Trifft nur einen Teil - greift nur, wenn NetScaler genau diese Darstellung prüft:  ' + text;
        }
    }
    presetSelect.addEventListener('change', function () {
        if (presets[presetSelect.value] !== undefined) {
            input.value = presets[presetSelect.value];
            updateCheck();
        }
    });
    input.addEventListener('input', function () {
        presetSelect.value = 'custom';
        for (var key in presets) {
            if (presets[key] === input.value) { presetSelect.value = key; break; }
        }
        updateCheck();
    });
    updateCheck();

    function close() {
        document.removeEventListener('keydown', onKey);
        overlay.remove();
        if (document.body.contains(button)) button.focus();
    }
    function onKey(event) { if (event.key === 'Escape') close(); }
    document.addEventListener('keydown', onKey);
    cancel.addEventListener('click', close);

    submit.addEventListener('click', function () {
        var value = input.value.trim();
        if (value === '') {
            errorLine.textContent = 'Bitte ein Muster angeben.';
            return;
        }
        close();
        submitDenyUrl(button, { profile: profile, pattern: value });
    });

    document.body.appendChild(overlay);
    input.focus();
    input.setSelectionRange(input.value.length, input.value.length);
}

function submitDenyUrl(button, payload) {
    setActionButtonBusy(button, 'Wird gespeichert…');

    // Ersetzt der periodische Refresh die Log-Karte, ist der Button nicht mehr
    // im DOM - das Ergebnis erscheint dann als Hinweis statt zu verpuffen.
    function report(success, message) {
        if (document.body.contains(button)) {
            setActionButtonResult(button, success, message);
        } else {
            showDenyToast(message, !success);
        }
    }

    fetch('/analysis/deny-url/add', {
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
