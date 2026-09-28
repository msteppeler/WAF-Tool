/* CSRF-Form-Tagging-Relaxation. Anders als die meisten Checks braucht
 * dieser ZWEI Muster (Form-Origin-URL und Form-Action-URL), daher ein
 * eigener, einfacher Zwei-Felder-Dialog statt des Token-Dialogs. */

function csrfEl(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}

function showCsrfToast(message, isError) {
    var toast = csrfEl('div', 'sql-toast' + (isError ? ' sql-toast-error' : ''), message);
    document.body.appendChild(toast);
    setTimeout(function () { toast.remove(); }, 12000);
}

function handleCsrfTagRelax(button) {
    var profile = button.dataset.profile;
    var originSuggestion = button.dataset.origin;
    var actionSuggestion = button.dataset.action;

    var overlay = csrfEl('div', 'sql-dialog-overlay');
    var dialog = csrfEl('div', 'sql-dialog');
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    overlay.appendChild(dialog);

    dialog.appendChild(csrfEl('h3', 'sql-dialog-title', 'CSRF Form Tagging: Relaxation Rule erstellen'));

    var context = csrfEl('div', 'sql-dialog-context');
    var row = csrfEl('div', 'sql-dialog-context-row');
    row.appendChild(csrfEl('span', 'k', 'Profil'));
    row.appendChild(csrfEl('span', 'v', profile));
    context.appendChild(row);
    dialog.appendChild(context);

    dialog.appendChild(csrfEl('p', 'sql-dialog-warn',
        'Besonderheit dieses Checks: NetScaler meldet die Form-Origin-URL bei gleicher Origin oft '
        + 'nicht als vollständige URL, sondern nur als Schema, z. B. "^http://$" statt '
        + '"^http://shop.example.com$". Der Vorschlag unten übernimmt deshalb bewusst NICHT die '
        + 'geloggte Origin, sondern dieses in der Praxis gebräuchliche Muster. Bitte nach dem Anlegen '
        + 'unbedingt testen (siehe README) und bei Bedarf anpassen.'));

    dialog.appendChild(csrfEl('label', 'sql-dialog-note', 'Form-Origin-URL (PCRE-Regex):'));
    var originInput = document.createElement('input');
    originInput.type = 'text';
    originInput.className = 'deny-pattern-input';
    originInput.value = originSuggestion;
    originInput.autocomplete = 'off';
    originInput.spellcheck = false;
    dialog.appendChild(originInput);

    dialog.appendChild(csrfEl('label', 'sql-dialog-note', 'Form-Action-URL (PCRE-Regex, ohne Query-String):'));
    var actionInput = document.createElement('input');
    actionInput.type = 'text';
    actionInput.className = 'deny-pattern-input';
    actionInput.value = actionSuggestion;
    actionInput.autocomplete = 'off';
    actionInput.spellcheck = false;
    dialog.appendChild(actionInput);

    var actionHint = csrfEl('div', 'deny-check-line deny-check-neutral',
        'Ein Query-String ("?...") in der Action-URL führt laut Citrix zu einem Fehler beim Anlegen der Regel.');
    dialog.appendChild(actionHint);

    var errorLine = csrfEl('div', 'sql-dialog-error');
    dialog.appendChild(errorLine);

    var actions = csrfEl('div', 'sql-dialog-actions');
    var cancel = csrfEl('button', 'sql-dialog-cancel', 'Abbrechen');
    cancel.type = 'button';
    var submit = csrfEl('button', 'sql-dialog-submit', 'Regel erstellen');
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
        var origin = originInput.value.trim();
        var action = actionInput.value.trim();
        if (!origin) { errorLine.textContent = 'Bitte eine Form-Origin-URL angeben.'; return; }
        if (!action) { errorLine.textContent = 'Bitte eine Form-Action-URL angeben.'; return; }
        if (action.indexOf('?') !== -1) {
            errorLine.textContent = 'Die Form-Action-URL darf kein "?" enthalten (siehe Hinweis oben).';
            return;
        }
        close();
        submitCsrfTagRelax(button, { profile: profile, origin_pattern: origin, action_pattern: action });
    });

    document.body.appendChild(overlay);
    originInput.focus();
}

function submitCsrfTagRelax(button, payload) {
    setActionButtonBusy(button, 'Wird gespeichert…');

    function report(success, message) {
        if (document.body.contains(button)) {
            setActionButtonResult(button, success, message);
        } else {
            showCsrfToast(message, !success);
        }
    }

    fetch('/analysis/csrf-tag/relax', {
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
