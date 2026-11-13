/* Cookie Consistency: von Block auf Transform umstellen.
 * Öffnet einen Dialog mit den drei NetScaler-Transform-Einstellungen
 * (Encrypt Server Cookies / Proxy Server Cookies / Flags to add in Cookies)
 * und schreibt sie zusammen mit der Aktionsänderung in EINEM Request. */

function cookieEl(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}

function showCookieToast(message, isError) {
    var toast = cookieEl('div', 'sql-toast' + (isError ? ' sql-toast-error' : ''), message);
    document.body.appendChild(toast);
    setTimeout(function () { toast.remove(); }, 12000);
}

function cookieAddSelect(dialog, labelText, options, defaultValue) {
    dialog.appendChild(cookieEl('label', 'sql-dialog-note', labelText));
    var select = document.createElement('select');
    select.className = 'cookie-transform-select';
    options.forEach(function (pair) {
        var option = document.createElement('option');
        option.value = pair[0];
        option.textContent = pair[1];
        if (pair[0] === defaultValue) option.selected = true;
        select.appendChild(option);
    });
    dialog.appendChild(select);
    return select;
}

function handleCookieConsistencyTransform(button) {
    var profile = button.dataset.profile;
    var wasBlocked = button.dataset.wasBlocked !== 'false';

    var overlay = cookieEl('div', 'sql-dialog-overlay');
    var dialog = cookieEl('div', 'sql-dialog');
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    overlay.appendChild(dialog);

    dialog.appendChild(cookieEl('h3', 'sql-dialog-title',
        wasBlocked ? 'Cookie Consistency: auf Transform umstellen' : 'Cookie Consistency: Transform-Einstellungen anpassen'));

    var context = cookieEl('div', 'sql-dialog-context');
    var row = cookieEl('div', 'sql-dialog-context-row');
    row.appendChild(cookieEl('span', 'k', 'Profil'));
    row.appendChild(cookieEl('span', 'v', profile));
    context.appendChild(row);
    dialog.appendChild(context);

    dialog.appendChild(cookieEl('p', 'sql-dialog-note', wasBlocked
        ? ('Entfernt „Block“ aus der Cookie-Consistency-Aktion (Log/Stats bleiben erhalten), aktiviert '
           + 'Cookie Transforms und setzt die folgenden Einstellungen. Gilt profilweit für alle Requests über '
           + 'dieses Profil, nicht nur für diesen Treffer.')
        : ('Dieser Treffer wird bereits nicht blockiert (an der Cookie-Consistency-Aktion ändert sich nichts). '
           + 'Aktiviert Cookie Transforms und setzt die folgenden Einstellungen. Gilt profilweit für alle '
           + 'Requests über dieses Profil, nicht nur für diesen Treffer.')));

    var encryptSelect = cookieAddSelect(dialog, 'Encrypt Server Cookies', [
        ['none', 'None'],
        ['decryptOnly', 'Decrypt Only'],
        ['encryptSessionOnly', 'Encrypt Session Only'],
        ['encryptAll', 'Encrypt All']
    ], 'none');

    var proxySelect = cookieAddSelect(dialog, 'Proxy Server Cookies', [
        ['none', 'None'],
        ['sessionOnly', 'Session Only']
    ], 'none');

    var flagsSelect = cookieAddSelect(dialog, 'Flags to add in Cookies', [
        ['none', 'None'],
        ['secure', 'Secure'],
        ['httpOnly', 'HTTP Only'],
        ['all', 'All']
    ], 'none');

    dialog.appendChild(cookieEl('p', 'sql-dialog-help',
        'Wie in NetScaler selbst schließen sich die Optionen je Einstellung gegenseitig aus (z. B. Secure ODER '
        + 'HTTP Only ODER beide über „All“, nicht einzeln kombinierbar). „None“ entspricht der jeweiligen '
        + 'NetScaler-Voreinstellung, wenn diese Transformation nicht gewünscht ist.'));

    var errorLine = cookieEl('div', 'sql-dialog-error');
    dialog.appendChild(errorLine);

    var actions = cookieEl('div', 'sql-dialog-actions');
    var cancel = cookieEl('button', 'sql-dialog-cancel', 'Abbrechen');
    cancel.type = 'button';
    var submit = cookieEl('button', 'sql-dialog-submit', 'Umstellen');
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
        close();
        submitCookieConsistencyTransform(button, {
            profile: profile,
            cookie_encryption: encryptSelect.value,
            cookie_proxying: proxySelect.value,
            add_cookie_flags: flagsSelect.value
        });
    });

    document.body.appendChild(overlay);
    encryptSelect.focus();
}

function submitCookieConsistencyTransform(button, payload) {
    setActionButtonBusy(button, 'Wird umgestellt…');

    // Der periodische Refresh ersetzt die Log-Karten; ist der Button dann nicht
    // mehr im DOM, wird das Ergebnis als Hinweis eingeblendet statt zu verpuffen.
    function report(success, message) {
        if (document.body.contains(button)) {
            setActionButtonResult(button, success, message);
        } else {
            showCookieToast(message, !success);
        }
    }

    fetch('/analysis/cookie-consistency/transform', {
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
