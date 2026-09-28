/* Objekte-Seite: WAF-Profile per Drag & Drop auf einen VServer ziehen.
 * Legt dabei eine NEUE AppFW-Policy an (die auf das Profil zeigt) und
 * bindet sie an den VServer. Der Dialog wiederverwendet die sql-dialog-*
 * CSS-Klassen aus analysis.css für einen einheitlichen Look. */

function objEl(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}

function showObjectsToast(message, isError) {
    var toast = objEl('div', 'sql-toast' + (isError ? ' sql-toast-error' : ''), message);
    document.body.appendChild(toast);
    setTimeout(function () { toast.remove(); }, 12000);
}

/* Baut aus Regel-Typ + Wert den klassischen NetScaler-Policy-Ausdruck.
 * "Freier Ausdruck" liefert null - dann bleibt das Ausdrucksfeld unverändert
 * (der Nutzer hat dort direkt etwas eingegeben). */
function buildRuleExpression(type, value) {
    var escaped = (value || '').replace(/"/g, '\\"');
    if (type === 'hostname') return 'HTTP.REQ.HOSTNAME.CONTAINS("' + escaped + '")';
    if (type === 'url') return 'HTTP.REQ.URL.CONTAINS("' + escaped + '")';
    return null;
}

/* Höchste bereits vergebene Priorität an diesem VServer (aus dem bereits
 * gerenderten, ggf. eingeklappten Detail-Markup) + 10, sonst 100. */
function suggestPriority(vserverRow) {
    var max = 0;
    vserverRow.querySelectorAll('.vp-priority').forEach(function (el) {
        var n = parseInt(el.textContent, 10);
        if (!isNaN(n) && n > max) max = n;
    });
    return max > 0 ? max + 10 : 100;
}

function openBindDialog(profileName, vserverRow) {
    var vserverName = vserverRow.dataset.vserverName;
    var vserverType = vserverRow.dataset.vserverType;

    var overlay = objEl('div', 'sql-dialog-overlay');
    var dialog = objEl('div', 'sql-dialog');
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    overlay.appendChild(dialog);

    dialog.appendChild(objEl('h3', 'sql-dialog-title', 'Neue Policy anlegen und binden'));

    var context = objEl('div', 'sql-dialog-context');
    [['Profil', profileName], ['VServer', vserverName + ' (' + vserverType.toUpperCase() + ')']].forEach(function (pair) {
        var row = objEl('div', 'sql-dialog-context-row');
        row.appendChild(objEl('span', 'k', pair[0]));
        row.appendChild(objEl('span', 'v', pair[1]));
        context.appendChild(row);
    });
    dialog.appendChild(context);

    dialog.appendChild(objEl('p', 'sql-dialog-note',
        'Legt eine neue AppFW-Policy an, die auf dieses Profil zeigt, und bindet sie an diesen VServer. '
        + 'Bestehende Policies und Bindungen bleiben unverändert.'));

    dialog.appendChild(objEl('label', 'sql-dialog-note', 'Policy-Name:'));
    var nameInput = document.createElement('input');
    nameInput.type = 'text';
    nameInput.className = 'deny-pattern-input';
    nameInput.value = ('pol-' + profileName + '-' + vserverName).slice(0, 80).replace(/[^A-Za-z0-9_.:@=#\- ]/g, '_');
    nameInput.autocomplete = 'off';
    dialog.appendChild(nameInput);

    dialog.appendChild(objEl('label', 'sql-dialog-note', 'Regel-Typ:'));
    var typeSelect = document.createElement('select');
    typeSelect.className = 'cookie-transform-select';
    [['hostname', 'Hostname enthält'], ['url', 'URL-Pfad enthält'], ['raw', 'Freier Ausdruck']].forEach(function (pair) {
        var option = document.createElement('option');
        option.value = pair[0];
        option.textContent = pair[1];
        typeSelect.appendChild(option);
    });
    dialog.appendChild(typeSelect);

    var valueInput = document.createElement('input');
    valueInput.type = 'text';
    valueInput.className = 'deny-pattern-input';
    valueInput.placeholder = 'z. B. owa.example.com';
    dialog.appendChild(valueInput);

    dialog.appendChild(objEl('label', 'sql-dialog-note', 'Regel-Ausdruck (NetScaler-Expression):'));
    var ruleInput = document.createElement('textarea');
    ruleInput.className = 'deny-pattern-input';
    ruleInput.rows = 2;
    ruleInput.style.resize = 'vertical';
    ruleInput.style.fontFamily = 'var(--mono)';
    dialog.appendChild(ruleInput);

    // Das Ausdrucksfeld wird aus Typ+Wert generiert, solange der Nutzer es
    // nicht selbst angefasst hat - danach bleibt seine manuelle Eingabe
    // unangetastet (auch bei weiteren Änderungen an Typ/Wert).
    var ruleEditedManually = false;
    ruleInput.addEventListener('input', function () { ruleEditedManually = true; });
    function regenerateRule() {
        if (ruleEditedManually) return;
        var generated = buildRuleExpression(typeSelect.value, valueInput.value);
        if (generated !== null) ruleInput.value = generated;
    }
    typeSelect.addEventListener('change', function () {
        valueInput.hidden = typeSelect.value === 'raw';
        regenerateRule();
    });
    valueInput.addEventListener('input', regenerateRule);
    typeSelect.value = 'hostname';

    dialog.appendChild(objEl('label', 'sql-dialog-note', 'Priorität:'));
    var priorityInput = document.createElement('input');
    priorityInput.type = 'number';
    priorityInput.min = '1';
    priorityInput.className = 'deny-pattern-input';
    priorityInput.value = String(suggestPriority(vserverRow));
    dialog.appendChild(priorityInput);

    var errorLine = objEl('div', 'sql-dialog-error');
    dialog.appendChild(errorLine);

    var actions = objEl('div', 'sql-dialog-actions');
    var cancel = objEl('button', 'sql-dialog-cancel', 'Abbrechen');
    cancel.type = 'button';
    var submit = objEl('button', 'sql-dialog-submit', 'Anlegen & binden');
    submit.type = 'button';
    actions.appendChild(cancel);
    actions.appendChild(submit);
    dialog.appendChild(actions);

    function close() {
        document.removeEventListener('keydown', onKey);
        overlay.remove();
    }
    function onKey(event) { if (event.key === 'Escape') close(); }
    document.addEventListener('keydown', onKey);
    cancel.addEventListener('click', close);

    submit.addEventListener('click', function () {
        var policyName = nameInput.value.trim();
        var rule = ruleInput.value.trim();
        var priority = priorityInput.value.trim();
        if (!policyName) { errorLine.textContent = 'Bitte einen Policy-Namen angeben.'; return; }
        if (!rule) { errorLine.textContent = 'Bitte einen Regel-Ausdruck angeben.'; return; }
        if (!priority || Number(priority) <= 0) { errorLine.textContent = 'Bitte eine gültige Priorität angeben.'; return; }

        submit.disabled = true;
        cancel.disabled = true;
        errorLine.textContent = '';
        fetch('/objects/bind-profile', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                vserver_name: vserverName,
                vserver_type: vserverType,
                profile_name: profileName,
                policy_name: policyName,
                rule: rule,
                priority: priority
            })
        })
            .then(function (response) {
                return response.json().then(function (data) { return { status: response.status, data: data }; });
            })
            .then(function (result) {
                if (result.status === 401) {
                    close();
                    showObjectsToast('Sitzung abgelaufen – bitte neu anmelden.', true);
                    return;
                }
                if (result.data.success) {
                    close();
                    showObjectsToast(result.data.message, false);
                    refreshVserverRow(vserverName);
                } else {
                    submit.disabled = false;
                    cancel.disabled = false;
                    errorLine.textContent = result.data.message || 'Unbekannter Fehler.';
                }
            })
            .catch(function () {
                submit.disabled = false;
                cancel.disabled = false;
                errorLine.textContent = 'Netzwerkfehler – bitte erneut versuchen.';
            });
    });

    document.body.appendChild(overlay);
    valueInput.focus();
}

/* Lädt die Objekte-Seite im Hintergrund neu und ersetzt nur die Zeile des
 * betroffenen VServers, damit die neu gebundene Policy sichtbar wird - ohne
 * einen vollständigen Seitenneuladung und ohne den Zustand der übrigen,
 * ggf. aufgeklappten Zeilen zu verlieren. */
function refreshVserverRow(vserverName) {
    fetch('/objects', { headers: { 'X-Requested-With': 'fetch' } })
        .then(function (response) { return response.text(); })
        .then(function (html) {
            var doc = new DOMParser().parseFromString(html, 'text/html');
            var freshRow = doc.getElementById('vserver-' + vserverName);
            var currentRow = document.getElementById('vserver-' + vserverName);
            if (freshRow && currentRow) {
                freshRow.querySelector('.vserver-details').classList.add('open');
                currentRow.replaceWith(freshRow);
            }
        })
        .catch(function () { /* Zeile bleibt im alten Zustand - Meldung wurde bereits gezeigt */ });
}

/* ---------- "+ Add": neues Profil erstellen und konfigurieren ---------- */

function getSignatureObjectNames() {
    var el = document.getElementById('signature-objects-data');
    if (!el) return [];
    try { return JSON.parse(el.textContent) || []; } catch (e) { return []; }
}

/* ---------- Signatur auf Profil ziehen: zuweisen ---------- */

function openAssignSignatureDialog(signatureName, profileName) {
    var overlay = objEl('div', 'sql-dialog-overlay');
    var dialog = objEl('div', 'sql-dialog');
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    overlay.appendChild(dialog);

    dialog.appendChild(objEl('h3', 'sql-dialog-title', 'Signatur zuweisen'));

    var context = objEl('div', 'sql-dialog-context');
    [['Signatur', signatureName], ['Profil', profileName]].forEach(function (pair) {
        var row = objEl('div', 'sql-dialog-context-row');
        row.appendChild(objEl('span', 'k', pair[0]));
        row.appendChild(objEl('span', 'v', pair[1]));
        context.appendChild(row);
    });
    dialog.appendChild(context);

    dialog.appendChild(objEl('p', 'sql-dialog-note',
        'Weist dem Profil dieses Signatur-Objekt zu ("set appfw profile -signatures"). '
        + 'Gilt profilweit für alle Requests über dieses Profil. Eine zuvor zugewiesene '
        + 'Signatur wird dabei ersetzt, nicht ergänzt.'));

    var errorLine = objEl('div', 'sql-dialog-error');
    dialog.appendChild(errorLine);

    var actions = objEl('div', 'sql-dialog-actions');
    var cancel = objEl('button', 'sql-dialog-cancel', 'Abbrechen');
    cancel.type = 'button';
    var submit = objEl('button', 'sql-dialog-submit', 'Zuweisen');
    submit.type = 'button';
    actions.appendChild(cancel);
    actions.appendChild(submit);
    dialog.appendChild(actions);

    function close() {
        document.removeEventListener('keydown', onKey);
        overlay.remove();
    }
    function onKey(event) { if (event.key === 'Escape') close(); }
    document.addEventListener('keydown', onKey);
    cancel.addEventListener('click', close);

    submit.addEventListener('click', function () {
        submit.disabled = true;
        cancel.disabled = true;
        errorLine.textContent = '';
        fetch('/objects/assign-signature', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ profile_name: profileName, signature_name: signatureName })
        })
            .then(function (response) {
                return response.json().then(function (data) { return { status: response.status, data: data }; });
            })
            .then(function (result) {
                if (result.status === 401) {
                    close();
                    showObjectsToast('Sitzung abgelaufen – bitte neu anmelden.', true);
                    return;
                }
                if (result.data.success) {
                    close();
                    showObjectsToast(result.data.message, false);
                    refreshProfileCards();
                } else {
                    submit.disabled = false;
                    cancel.disabled = false;
                    errorLine.textContent = result.data.message || 'Unbekannter Fehler.';
                }
            })
            .catch(function () {
                submit.disabled = false;
                cancel.disabled = false;
                errorLine.textContent = 'Netzwerkfehler – bitte erneut versuchen.';
            });
    });

    document.body.appendChild(overlay);
}

/* ---------- Kategorie auf Profil ziehen: lokal vormerken ---------- */

/* ---------- Regel-Datenbank aus der Citrix-Signaturdatei aktualisieren ---------- */

function refreshSignatureRuleDatabase() {
    var statusEl = document.getElementById('rules-db-status');
    var originalText = statusEl.textContent;
    statusEl.textContent = 'Lädt Signaturdatei (kann einen Moment dauern)…';
    fetch('/objects/signature-rules/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
    })
        .then(function (response) {
            return response.json().then(function (data) { return { status: response.status, data: data }; });
        })
        .then(function (result) {
            if (result.status === 401) {
                statusEl.textContent = originalText;
                showObjectsToast('Sitzung abgelaufen – bitte neu anmelden.', true);
                return;
            }
            showObjectsToast(result.data.message, !result.data.success);
            if (result.data.success) {
                statusEl.textContent = result.data.message;
                refreshCategoryCards();
            } else {
                statusEl.textContent = originalText;
            }
        })
        .catch(function () {
            statusEl.textContent = originalText;
            showObjectsToast('Netzwerkfehler – bitte erneut versuchen.', true);
        });
}

/* ---------- Kategorie als echtes Signatur-Objekt in NetScaler erstellen ---------- */

function confirmBuildCategory(cardElement) {
    var categoryId = cardElement.dataset.categoryId;
    var categoryName = cardElement.dataset.categoryName;

    var overlay = objEl('div', 'sql-dialog-overlay');
    var dialog = objEl('div', 'sql-dialog');
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    overlay.appendChild(dialog);

    dialog.appendChild(objEl('h3', 'sql-dialog-title', 'Signatur-Objekt in NetScaler erstellen?'));
    dialog.appendChild(objEl('p', 'sql-dialog-note',
        'Erstellt ein neues appfwsignatures-Objekt namens „' + categoryName + '“ mit allen NetScaler-Regeln '
        + 'aktiviert, die zu den CVEs dieser Kategorie passen. CVEs ohne passende Regel in der geladenen '
        + 'Signaturdatei werden dabei übersprungen (siehe "Details anzeigen" für die genaue Trefferquote).'));
    dialog.appendChild(objEl('p', 'sql-dialog-warn',
        'Experimentell: Die NITRO-Anfrage für diesen Schritt ist nach bestem Wissen abgeleitet, aber nicht '
        + 'an einer echten Appliance verifiziert. Schlägt es fehl, hilft die genaue NetScaler-Fehlermeldung '
        + 'unten bei der Korrektur.'));

    var errorLine = objEl('div', 'sql-dialog-error');
    dialog.appendChild(errorLine);

    var actions = objEl('div', 'sql-dialog-actions');
    var cancel = objEl('button', 'sql-dialog-cancel', 'Abbrechen');
    cancel.type = 'button';
    var submit = objEl('button', 'sql-dialog-submit', 'Erstellen');
    submit.type = 'button';
    actions.appendChild(cancel);
    actions.appendChild(submit);
    dialog.appendChild(actions);

    function close() {
        document.removeEventListener('keydown', onKey);
        overlay.remove();
    }
    function onKey(event) { if (event.key === 'Escape') close(); }
    document.addEventListener('keydown', onKey);
    cancel.addEventListener('click', close);

    submit.addEventListener('click', function () {
        submit.disabled = true;
        cancel.disabled = true;
        errorLine.textContent = '';
        fetch('/objects/signature-categories/' + encodeURIComponent(categoryId) + '/build', { method: 'POST' })
            .then(function (response) {
                return response.json().then(function (data) { return { status: response.status, data: data }; });
            })
            .then(function (result) {
                if (result.status === 401) {
                    close();
                    showObjectsToast('Sitzung abgelaufen – bitte neu anmelden.', true);
                    return;
                }
                if (result.data.success) {
                    close();
                    showObjectsToast(result.data.message, false);
                    refreshSignatureCards();
                } else {
                    submit.disabled = false;
                    cancel.disabled = false;
                    errorLine.textContent = result.data.message || 'Unbekannter Fehler.';
                }
            })
            .catch(function () {
                submit.disabled = false;
                cancel.disabled = false;
                errorLine.textContent = 'Netzwerkfehler – bitte erneut versuchen.';
            });
    });

    document.body.appendChild(overlay);
}

/* ---------- Loeschen: Signatur-Kategorie (nur wenn nicht vorgemerkt) ---------- */

function confirmDeleteCategory(cardElement) {
    var categoryId = cardElement.dataset.categoryId;
    var categoryName = cardElement.dataset.categoryName;

    var overlay = objEl('div', 'sql-dialog-overlay');
    var dialog = objEl('div', 'sql-dialog');
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    overlay.appendChild(dialog);

    dialog.appendChild(objEl('h3', 'sql-dialog-title', 'Kategorie löschen?'));
    dialog.appendChild(objEl('p', 'sql-dialog-note',
        'Kategorie „' + categoryName + '“ und ihre gespeicherten CVEs werden unwiderruflich gelöscht. '
        + 'Nur möglich, solange sie keinem Profil vorgemerkt zugewiesen ist.'));

    var errorLine = objEl('div', 'sql-dialog-error');
    dialog.appendChild(errorLine);

    var actions = objEl('div', 'sql-dialog-actions');
    var cancel = objEl('button', 'sql-dialog-cancel', 'Abbrechen');
    cancel.type = 'button';
    var submit = objEl('button', 'sql-dialog-submit sql-dialog-submit-danger', 'Löschen');
    submit.type = 'button';
    actions.appendChild(cancel);
    actions.appendChild(submit);
    dialog.appendChild(actions);

    function close() {
        document.removeEventListener('keydown', onKey);
        overlay.remove();
    }
    function onKey(event) { if (event.key === 'Escape') close(); }
    document.addEventListener('keydown', onKey);
    cancel.addEventListener('click', close);

    submit.addEventListener('click', function () {
        submit.disabled = true;
        cancel.disabled = true;
        errorLine.textContent = '';
        fetch('/objects/signature-categories/' + encodeURIComponent(categoryId) + '/delete', { method: 'POST' })
            .then(function (response) {
                return response.json().then(function (data) { return { status: response.status, data: data }; });
            })
            .then(function (result) {
                if (result.status === 401) {
                    close();
                    showObjectsToast('Sitzung abgelaufen – bitte neu anmelden.', true);
                    return;
                }
                if (result.data.success) {
                    close();
                    showObjectsToast(result.data.message, false);
                    refreshCategoryCards();
                } else {
                    submit.disabled = false;
                    cancel.disabled = false;
                    errorLine.textContent = result.data.message || 'Unbekannter Fehler.';
                }
            })
            .catch(function () {
                submit.disabled = false;
                cancel.disabled = false;
                errorLine.textContent = 'Netzwerkfehler – bitte erneut versuchen.';
            });
    });

    document.body.appendChild(overlay);
}

/* ---------- Loeschen: echtes Signatur-Objekt (nur wenn keinem Profil zugewiesen) ---------- */

function confirmDeleteSignature(cardElement) {
    var signatureName = cardElement.dataset.signatureName;

    var overlay = objEl('div', 'sql-dialog-overlay');
    var dialog = objEl('div', 'sql-dialog');
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    overlay.appendChild(dialog);

    dialog.appendChild(objEl('h3', 'sql-dialog-title', 'Signatur-Objekt löschen?'));
    dialog.appendChild(objEl('p', 'sql-dialog-note',
        'Signatur-Objekt „' + signatureName + '“ wird UNWIDERRUFLICH vom NetScaler gelöscht. Nur '
        + 'möglich, solange kein Profil dieses Objekt aktuell zugewiesen hat.'));

    var errorLine = objEl('div', 'sql-dialog-error');
    dialog.appendChild(errorLine);

    var actions = objEl('div', 'sql-dialog-actions');
    var cancel = objEl('button', 'sql-dialog-cancel', 'Abbrechen');
    cancel.type = 'button';
    var submit = objEl('button', 'sql-dialog-submit sql-dialog-submit-danger', 'Löschen');
    submit.type = 'button';
    actions.appendChild(cancel);
    actions.appendChild(submit);
    dialog.appendChild(actions);

    function close() {
        document.removeEventListener('keydown', onKey);
        overlay.remove();
    }
    function onKey(event) { if (event.key === 'Escape') close(); }
    document.addEventListener('keydown', onKey);
    cancel.addEventListener('click', close);

    submit.addEventListener('click', function () {
        submit.disabled = true;
        cancel.disabled = true;
        errorLine.textContent = '';
        fetch('/objects/signatures/' + encodeURIComponent(signatureName) + '/delete', { method: 'POST' })
            .then(function (response) {
                return response.json().then(function (data) { return { status: response.status, data: data }; });
            })
            .then(function (result) {
                if (result.status === 401) {
                    close();
                    showObjectsToast('Sitzung abgelaufen – bitte neu anmelden.', true);
                    return;
                }
                if (result.data.success) {
                    close();
                    showObjectsToast(result.data.message, false);
                    refreshSignatureCards();
                } else {
                    submit.disabled = false;
                    cancel.disabled = false;
                    errorLine.textContent = result.data.message || 'Unbekannter Fehler.';
                }
            })
            .catch(function () {
                submit.disabled = false;
                cancel.disabled = false;
                errorLine.textContent = 'Netzwerkfehler – bitte erneut versuchen.';
            });
    });

    document.body.appendChild(overlay);
}

function refreshSignatureCards() {
    fetch('/objects', { headers: { 'X-Requested-With': 'fetch' } })
        .then(function (response) { return response.text(); })
        .then(function (html) {
            var doc = new DOMParser().parseFromString(html, 'text/html');
            var freshGrid = doc.getElementById('signature-card-grid');
            var currentGrid = document.getElementById('signature-card-grid');
            if (freshGrid && currentGrid) {
                currentGrid.replaceWith(freshGrid);
                attachSignatureCardDragHandlers(freshGrid);
            }
        })
        .catch(function () { /* Bereich bleibt im alten Zustand - Meldung wurde bereits gezeigt */ });
}

/* ---------- Details eines Signatur-Objekts (echte NetScaler-Metadaten) ---------- */

function formatSignatureSize(bytes) {
    if (bytes === null || bytes === undefined) return '';
    if (bytes >= 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return bytes + ' Bytes';
}

function openSignatureDetailsDialog(cardElement) {
    var details = {};
    try { details = JSON.parse(cardElement.dataset.details || '{}'); } catch (e) { details = {}; }

    var overlay = objEl('div', 'sql-dialog-overlay');
    var dialog = objEl('div', 'sql-dialog');
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    overlay.appendChild(dialog);

    dialog.appendChild(objEl('h3', 'sql-dialog-title', 'Signatur-Objekt „' + (details.name || '') + '“'));

    var rows = [
        ['Url', details.url],
        [details.date_label, details.date_value],
        ['Base Version', details.base_version],
        ['Size', formatSignatureSize(details.size)],
        ['AutoEnable New Signatures', details.autoenable],
        ['Comment', details.comment],
        ['Encrypted Version', details.encrypted_version],
    ];
    var context = objEl('div', 'sql-dialog-context');
    var anyRow = false;
    rows.forEach(function (pair) {
        var label = pair[0], value = pair[1];
        if (!label || value === undefined || value === null || value === '') return;
        anyRow = true;
        var row = objEl('div', 'sql-dialog-context-row');
        row.appendChild(objEl('span', 'k', label));
        row.appendChild(objEl('span', 'v', String(value)));
        context.appendChild(row);
    });
    if (anyRow) {
        dialog.appendChild(context);
    } else {
        dialog.appendChild(objEl('p', 'sql-dialog-note', 'Keine weiteren Metadaten aus der NetScaler-Antwort ablesbar.'));
    }

    dialog.appendChild(objEl('p', 'sql-dialog-help',
        'Diese Angaben stammen aus der Objekt-Übersicht des NetScaler ("show appfw signatures") - '
        + 'eine Liste der enthaltenen Regeln/CVEs liefert diese Ansicht nicht.'));

    var actions = objEl('div', 'sql-dialog-actions');
    var close_ = objEl('button', 'sql-dialog-cancel', 'Schließen');
    close_.type = 'button';
    actions.appendChild(close_);
    dialog.appendChild(actions);

    function close() {
        document.removeEventListener('keydown', onKey);
        overlay.remove();
    }
    function onKey(event) { if (event.key === 'Escape') close(); }
    document.addEventListener('keydown', onKey);
    close_.addEventListener('click', close);
    overlay.addEventListener('click', function (event) { if (event.target === overlay) close(); });

    document.body.appendChild(overlay);
}

/* ---------- Details einer Signatur-Kategorie: welche CVEs sind enthalten ---------- */

function openCategoryDetailsDialog(cardElement) {
    var categoryName = cardElement.dataset.categoryName;
    var cves = [];
    try { cves = JSON.parse(cardElement.dataset.cves || '[]'); } catch (e) { cves = []; }

    var overlay = objEl('div', 'sql-dialog-overlay');
    var dialog = objEl('div', 'sql-dialog category-details-dialog');
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    overlay.appendChild(dialog);

    dialog.appendChild(objEl('h3', 'sql-dialog-title', 'Kategorie „' + categoryName + '“: ' + cves.length + ' CVEs'));

    if (cves.length === 0) {
        dialog.appendChild(objEl('p', 'sql-dialog-note', 'Keine CVEs hinterlegt.'));
    } else {
        var list = objEl('div', 'category-cve-list');
        cves.forEach(function (cve) {
            var item = objEl('div', 'category-cve-item');

            var head = objEl('div', 'category-cve-head');
            var link = document.createElement('a');
            link.href = 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(cve.cve_id);
            link.target = '_blank';
            link.rel = 'noopener noreferrer';
            link.className = 'category-cve-id';
            link.textContent = cve.cve_id;
            head.appendChild(link);
            if (cve.matched_term) head.appendChild(objEl('span', 'category-cve-term', cve.matched_term));
            if (cve.published) head.appendChild(objEl('span', 'category-cve-date', cve.published.slice(0, 10)));
            if (cve.rule_ids && cve.rule_ids.length) {
                head.appendChild(objEl('span', 'category-cve-rule-match', 'NetScaler-Regel ' + cve.rule_ids.join(', ')));
            } else {
                head.appendChild(objEl('span', 'category-cve-rule-nomatch', 'keine passende Regel gefunden'));
            }
            item.appendChild(head);

            if (cve.description) item.appendChild(objEl('p', 'category-cve-desc', cve.description));
            list.appendChild(item);
        });
        dialog.appendChild(list);
    }

    var actions = objEl('div', 'sql-dialog-actions');
    var close_ = objEl('button', 'sql-dialog-cancel', 'Schließen');
    close_.type = 'button';
    actions.appendChild(close_);
    dialog.appendChild(actions);

    function close() {
        document.removeEventListener('keydown', onKey);
        overlay.remove();
    }
    function onKey(event) { if (event.key === 'Escape') close(); }
    document.addEventListener('keydown', onKey);
    close_.addEventListener('click', close);
    overlay.addEventListener('click', function (event) { if (event.target === overlay) close(); });

    document.body.appendChild(overlay);
}

function openAssignCategoryDialog(categoryId, categoryName, profileName) {
    var overlay = objEl('div', 'sql-dialog-overlay');
    var dialog = objEl('div', 'sql-dialog');
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    overlay.appendChild(dialog);

    dialog.appendChild(objEl('h3', 'sql-dialog-title', 'Signatur-Kategorie vormerken'));

    var context = objEl('div', 'sql-dialog-context');
    [['Kategorie', categoryName], ['Profil', profileName]].forEach(function (pair) {
        var row = objEl('div', 'sql-dialog-context-row');
        row.appendChild(objEl('span', 'k', pair[0]));
        row.appendChild(objEl('span', 'v', pair[1]));
        context.appendChild(row);
    });
    dialog.appendChild(context);

    dialog.appendChild(objEl('p', 'sql-dialog-note',
        'Merkt nur lokal vor, dass dieses Profil später diese Kategorie erhalten soll. Es wird noch '
        + 'NICHTS am NetScaler geändert - der Import als echtes Signatur-Objekt ist ein separater, '
        + 'noch nicht umgesetzter Schritt.'));

    var errorLine = objEl('div', 'sql-dialog-error');
    dialog.appendChild(errorLine);

    var actions = objEl('div', 'sql-dialog-actions');
    var cancel = objEl('button', 'sql-dialog-cancel', 'Abbrechen');
    cancel.type = 'button';
    var submit = objEl('button', 'sql-dialog-submit', 'Vormerken');
    submit.type = 'button';
    actions.appendChild(cancel);
    actions.appendChild(submit);
    dialog.appendChild(actions);

    function close() {
        document.removeEventListener('keydown', onKey);
        overlay.remove();
    }
    function onKey(event) { if (event.key === 'Escape') close(); }
    document.addEventListener('keydown', onKey);
    cancel.addEventListener('click', close);

    submit.addEventListener('click', function () {
        submit.disabled = true;
        cancel.disabled = true;
        errorLine.textContent = '';
        fetch('/objects/signature-categories/' + encodeURIComponent(categoryId) + '/assign', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ profile_name: profileName })
        })
            .then(function (response) {
                return response.json().then(function (data) { return { status: response.status, data: data }; });
            })
            .then(function (result) {
                if (result.status === 401) {
                    close();
                    showObjectsToast('Sitzung abgelaufen – bitte neu anmelden.', true);
                    return;
                }
                if (result.data.success) {
                    close();
                    showObjectsToast(result.data.message, false);
                    refreshProfileCards();
                } else {
                    submit.disabled = false;
                    cancel.disabled = false;
                    errorLine.textContent = result.data.message || 'Unbekannter Fehler.';
                }
            })
            .catch(function () {
                submit.disabled = false;
                cancel.disabled = false;
                errorLine.textContent = 'Netzwerkfehler – bitte erneut versuchen.';
            });
    });

    document.body.appendChild(overlay);
}

/* ---------- "+ Add" bei Signatur-Kategorien ---------- */

function getCategoryPresetNames() {
    var el = document.getElementById('category-presets-data');
    if (!el) return [];
    try { return JSON.parse(el.textContent) || []; } catch (e) { return []; }
}

function openCreateCategoryDialog() {
    var overlay = objEl('div', 'sql-dialog-overlay');
    var dialog = objEl('div', 'sql-dialog');
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    overlay.appendChild(dialog);

    dialog.appendChild(objEl('h3', 'sql-dialog-title', 'Signatur-Kategorie anlegen'));
    dialog.appendChild(objEl('p', 'sql-dialog-note',
        'Sucht für jeden Begriff passende CVEs in der NVD (National Vulnerability Database) und legt '
        + 'daraus eine Kategorie an. Rein lokal - noch keine Verbindung zu einem echten '
        + 'NetScaler-Signatur-Objekt.'));

    dialog.appendChild(objEl('label', 'sql-dialog-note', 'Vordefiniert:'));
    var presetSelect = document.createElement('select');
    presetSelect.className = 'cookie-transform-select';
    var customOption = document.createElement('option');
    customOption.value = ''; customOption.textContent = '— eigene Kategorie —';
    presetSelect.appendChild(customOption);
    getCategoryPresetNames().forEach(function (name) {
        var option = document.createElement('option');
        option.value = name; option.textContent = name;
        presetSelect.appendChild(option);
    });
    dialog.appendChild(presetSelect);

    dialog.appendChild(objEl('label', 'sql-dialog-note', 'Name (bei eigener Kategorie):'));
    var nameInput = document.createElement('input');
    nameInput.type = 'text';
    nameInput.className = 'deny-pattern-input';
    nameInput.autocomplete = 'off';
    dialog.appendChild(nameInput);

    dialog.appendChild(objEl('label', 'sql-dialog-note', 'Suchbegriffe (kommagetrennt, bei eigener Kategorie):'));
    var termsInput = document.createElement('input');
    termsInput.type = 'text';
    termsInput.className = 'deny-pattern-input';
    termsInput.placeholder = 'z. B. Drupal, Drupal Core';
    dialog.appendChild(termsInput);

    function updateCustomFieldsEnabled() {
        var isPreset = presetSelect.value !== '';
        nameInput.disabled = isPreset;
        termsInput.disabled = isPreset;
    }
    presetSelect.addEventListener('change', updateCustomFieldsEnabled);
    updateCustomFieldsEnabled();

    var errorLine = objEl('div', 'sql-dialog-error');
    dialog.appendChild(errorLine);

    var actions = objEl('div', 'sql-dialog-actions');
    var cancel = objEl('button', 'sql-dialog-cancel', 'Abbrechen');
    cancel.type = 'button';
    var submit = objEl('button', 'sql-dialog-submit', 'Anlegen');
    submit.type = 'button';
    actions.appendChild(cancel);
    actions.appendChild(submit);
    dialog.appendChild(actions);

    function close() {
        document.removeEventListener('keydown', onKey);
        overlay.remove();
    }
    function onKey(event) { if (event.key === 'Escape') close(); }
    document.addEventListener('keydown', onKey);
    cancel.addEventListener('click', close);

    submit.addEventListener('click', function () {
        var payload = presetSelect.value
            ? { preset: presetSelect.value }
            : { name: nameInput.value.trim(), terms: termsInput.value.trim() };
        if (!presetSelect.value && (!payload.name || !payload.terms)) {
            errorLine.textContent = 'Bitte Name und mindestens einen Suchbegriff angeben.';
            return;
        }

        submit.disabled = true;
        cancel.disabled = true;
        errorLine.textContent = 'Suche läuft (NVD-Abfrage kann einen Moment dauern)…';
        fetch('/objects/signature-categories/create', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        })
            .then(function (response) {
                return response.json().then(function (data) { return { status: response.status, data: data }; });
            })
            .then(function (result) {
                if (result.status === 401) {
                    close();
                    showObjectsToast('Sitzung abgelaufen – bitte neu anmelden.', true);
                    return;
                }
                if (result.data.success) {
                    close();
                    showObjectsToast(result.data.message, false);
                    refreshCategoryCards();
                } else {
                    submit.disabled = false;
                    cancel.disabled = false;
                    errorLine.textContent = result.data.message || 'Unbekannter Fehler.';
                }
            })
            .catch(function () {
                submit.disabled = false;
                cancel.disabled = false;
                errorLine.textContent = 'Netzwerkfehler – bitte erneut versuchen.';
            });
    });

    document.body.appendChild(overlay);
    presetSelect.focus();
}

function refreshCategoryCards() {
    fetch('/objects', { headers: { 'X-Requested-With': 'fetch' } })
        .then(function (response) { return response.text(); })
        .then(function (html) {
            var doc = new DOMParser().parseFromString(html, 'text/html');
            var freshGrid = doc.getElementById('category-card-grid');
            var currentGrid = document.getElementById('category-card-grid');
            if (freshGrid && currentGrid) {
                currentGrid.replaceWith(freshGrid);
                attachCategoryCardDragHandlers(freshGrid);
            }
        })
        .catch(function () { /* Bereich bleibt im alten Zustand - Meldung wurde bereits gezeigt */ });
}

function openCreateProfileDialog() {
    var overlay = objEl('div', 'sql-dialog-overlay');
    var dialog = objEl('div', 'sql-dialog');
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    overlay.appendChild(dialog);

    dialog.appendChild(objEl('h3', 'sql-dialog-title', 'Neues Profil erstellen'));

    dialog.appendChild(objEl('label', 'sql-dialog-note', 'Name:'));
    var nameInput = document.createElement('input');
    nameInput.type = 'text';
    nameInput.className = 'deny-pattern-input';
    nameInput.autocomplete = 'off';
    dialog.appendChild(nameInput);

    var row = objEl('div', 'create-profile-row');

    var defaultsWrap = objEl('div');
    defaultsWrap.appendChild(objEl('label', 'sql-dialog-note', 'Defaults:'));
    var defaultsSelect = document.createElement('select');
    defaultsSelect.className = 'cookie-transform-select';
    [['basic', 'Basic'], ['advanced', 'Advanced'], ['core', 'Core'], ['cve', 'CVE']].forEach(function (pair) {
        var option = document.createElement('option');
        option.value = pair[0]; option.textContent = pair[1];
        defaultsSelect.appendChild(option);
    });
    defaultsWrap.appendChild(defaultsSelect);
    row.appendChild(defaultsWrap);

    var typeWrap = objEl('div');
    typeWrap.appendChild(objEl('label', 'sql-dialog-note', 'Typ (optional):'));
    var typeSelect = document.createElement('select');
    typeSelect.className = 'cookie-transform-select';
    [['', '— nicht setzen —'], ['HTML', 'HTML'], ['XML', 'XML'], ['HTML XML', 'HTML + XML']].forEach(function (pair) {
        var option = document.createElement('option');
        option.value = pair[0]; option.textContent = pair[1];
        typeSelect.appendChild(option);
    });
    typeWrap.appendChild(typeSelect);
    row.appendChild(typeWrap);
    dialog.appendChild(row);

    dialog.appendChild(objEl('label', 'sql-dialog-note', 'Kommentar (optional):'));
    var commentInput = document.createElement('input');
    commentInput.type = 'text';
    commentInput.className = 'deny-pattern-input';
    dialog.appendChild(commentInput);

    dialog.appendChild(objEl('label', 'sql-dialog-note', 'Signatur (optional):'));
    var sigSelect = document.createElement('select');
    sigSelect.className = 'cookie-transform-select';
    var noneOption = document.createElement('option');
    noneOption.value = ''; noneOption.textContent = '— keine —';
    sigSelect.appendChild(noneOption);
    var signatureNames = getSignatureObjectNames();
    signatureNames.forEach(function (name) {
        var option = document.createElement('option');
        option.value = name; option.textContent = name;
        sigSelect.appendChild(option);
    });
    dialog.appendChild(sigSelect);
    if (signatureNames.length === 0) {
        dialog.appendChild(objEl('p', 'sql-dialog-help', 'Keine Signatur-Objekte auf dem NetScaler gefunden.'));
    }

    dialog.appendChild(objEl('p', 'sql-dialog-help',
        'Legt ein neues, eigenes Profil an. Security-Check-Aktionen (Learning/Block/Log/Stat) werden '
        + 'danach wie gewohnt auf der Dashboard-Seite konfiguriert.'));

    var errorLine = objEl('div', 'sql-dialog-error');
    dialog.appendChild(errorLine);

    var actions = objEl('div', 'sql-dialog-actions');
    var cancel = objEl('button', 'sql-dialog-cancel', 'Abbrechen');
    cancel.type = 'button';
    var submit = objEl('button', 'sql-dialog-submit', 'Erstellen');
    submit.type = 'button';
    actions.appendChild(cancel);
    actions.appendChild(submit);
    dialog.appendChild(actions);

    function close() {
        document.removeEventListener('keydown', onKey);
        overlay.remove();
    }
    function onKey(event) { if (event.key === 'Escape') close(); }
    document.addEventListener('keydown', onKey);
    cancel.addEventListener('click', close);

    submit.addEventListener('click', function () {
        var name = nameInput.value.trim();
        if (!name) { errorLine.textContent = 'Bitte einen Profilnamen angeben.'; return; }

        submit.disabled = true;
        cancel.disabled = true;
        errorLine.textContent = '';
        fetch('/objects/create-profile', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name: name,
                defaults: defaultsSelect.value,
                type: typeSelect.value,
                comment: commentInput.value.trim(),
                signature: sigSelect.value
            })
        })
            .then(function (response) {
                return response.json().then(function (data) { return { status: response.status, data: data }; });
            })
            .then(function (result) {
                if (result.status === 401) {
                    close();
                    showObjectsToast('Sitzung abgelaufen – bitte neu anmelden.', true);
                    return;
                }
                if (result.data.success) {
                    close();
                    showObjectsToast(result.data.message, false);
                    refreshProfileCards();
                } else {
                    submit.disabled = false;
                    cancel.disabled = false;
                    errorLine.textContent = result.data.message || 'Unbekannter Fehler.';
                }
            })
            .catch(function () {
                submit.disabled = false;
                cancel.disabled = false;
                errorLine.textContent = 'Netzwerkfehler – bitte erneut versuchen.';
            });
    });

    document.body.appendChild(overlay);
    nameInput.focus();
}

/* Laedt die Objekte-Seite im Hintergrund neu und ersetzt den kompletten
 * Profil-Karten-Bereich (neue Karte + aktualisierte Drag-Handler). */
function refreshProfileCards() {
    fetch('/objects', { headers: { 'X-Requested-With': 'fetch' } })
        .then(function (response) { return response.text(); })
        .then(function (html) {
            var doc = new DOMParser().parseFromString(html, 'text/html');
            var freshGrid = doc.querySelector('#content-waf-profiles .profile-card-grid');
            var currentGrid = document.querySelector('#content-waf-profiles .profile-card-grid');
            var freshData = doc.getElementById('signature-objects-data');
            var currentData = document.getElementById('signature-objects-data');
            if (freshGrid && currentGrid) {
                currentGrid.replaceWith(freshGrid);
                if (freshData && currentData) currentData.textContent = freshData.textContent;
                attachProfileCardDragHandlers(freshGrid);
                attachProfileCardDropHandlers(freshGrid);
            }
        })
        .catch(function () { /* Bereich bleibt im alten Zustand - Meldung wurde bereits gezeigt */ });
}

function attachProfileCardDragHandlers(root) {
    (root || document).querySelectorAll('.profile-card[draggable="true"]').forEach(function (card) {
        card.addEventListener('dragstart', function (event) {
            event.dataTransfer.setData('text/plain', card.dataset.profileName);
            event.dataTransfer.setData('application/x-object-kind', 'profile');
            event.dataTransfer.effectAllowed = 'copy';
            card.classList.add('dragging');
        });
        card.addEventListener('dragend', function () { card.classList.remove('dragging'); });
    });
}

function attachSignatureCardDragHandlers(root) {
    (root || document).querySelectorAll('.signature-card[draggable="true"]').forEach(function (card) {
        card.addEventListener('dragstart', function (event) {
            event.dataTransfer.setData('text/plain', card.dataset.signatureName);
            event.dataTransfer.setData('application/x-object-kind', 'signature');
            event.dataTransfer.effectAllowed = 'copy';
            card.classList.add('dragging');
        });
        card.addEventListener('dragend', function () { card.classList.remove('dragging'); });
    });
}

function attachCategoryCardDragHandlers(root) {
    (root || document).querySelectorAll('.category-card[draggable="true"]').forEach(function (card) {
        card.addEventListener('dragstart', function (event) {
            event.dataTransfer.setData('text/plain', card.dataset.categoryId);
            event.dataTransfer.setData('application/x-object-kind', 'category');
            event.dataTransfer.setData('application/x-category-name', card.dataset.categoryName);
            event.dataTransfer.effectAllowed = 'copy';
            card.classList.add('dragging');
        });
        card.addEventListener('dragend', function () { card.classList.remove('dragging'); });
    });
}

/* Profil-Karten sind Drop-Ziel fuer Signatur-Karten (Signatur -> Profil
 * zuweisen). Wird separat von den VServer-Drop-Handlern behandelt, die nur
 * Profile (nicht Signaturen) als Drop entgegennehmen. */
function attachProfileCardDropHandlers(root) {
    (root || document).querySelectorAll('.profile-card[draggable="true"]').forEach(function (card) {
        card.addEventListener('dragover', function (event) { event.preventDefault(); });
        card.addEventListener('dragenter', function (event) {
            event.preventDefault();
            card.classList.add('drop-target');
        });
        card.addEventListener('dragleave', function (event) {
            // dragleave feuert auch beim Wechsel auf ein Kind-Element (Text,
            // Icon) INNERHALB der Karte, nicht nur beim tatsächlichen
            // Verlassen - deshalb nur entfernen, wenn die Maus die Karte
            // wirklich komplett verlassen hat (relatedTarget liegt dann
            // ausserhalb). Ohne diese Prüfung flackert die Hervorhebung und
            // wirkt, als gelte sie nur nahe am Rand.
            if (!card.contains(event.relatedTarget)) {
                card.classList.remove('drop-target');
            }
        });
        card.addEventListener('drop', function (event) {
            event.preventDefault();
            card.classList.remove('drop-target');
            var kind = event.dataTransfer.getData('application/x-object-kind');
            if (kind === 'signature') {
                var signatureName = event.dataTransfer.getData('text/plain');
                if (!signatureName) return;
                openAssignSignatureDialog(signatureName, card.dataset.profileName);
            } else if (kind === 'category') {
                var categoryId = event.dataTransfer.getData('text/plain');
                var categoryName = event.dataTransfer.getData('application/x-category-name');
                if (!categoryId) return;
                openAssignCategoryDialog(categoryId, categoryName, card.dataset.profileName);
            }
            // andere Kinds (z.B. 'profile') werden hier ignoriert
        });
    });
}

document.addEventListener('DOMContentLoaded', function () {
    attachProfileCardDragHandlers();
    attachSignatureCardDragHandlers();
    attachCategoryCardDragHandlers();
    attachProfileCardDropHandlers();

    document.querySelectorAll('.vserver-row').forEach(function (row) {
        row.addEventListener('dragover', function (event) {
            event.preventDefault();
            event.dataTransfer.dropEffect = 'copy';
        });
        row.addEventListener('dragenter', function (event) {
            event.preventDefault();
            row.classList.add('drop-target');
        });
        row.addEventListener('dragleave', function (event) {
            // Siehe Kommentar bei attachProfileCardDropHandlers(): nur bei
            // echtem Verlassen der Zeile entfernen, nicht beim Wechsel
            // zwischen Kind-Elementen (VServer-Name, Chips, Badges).
            if (!row.contains(event.relatedTarget)) {
                row.classList.remove('drop-target');
            }
        });
        row.addEventListener('drop', function (event) {
            event.preventDefault();
            row.classList.remove('drop-target');
            var kind = event.dataTransfer.getData('application/x-object-kind');
            if (kind && kind !== 'profile') return;   // Signaturen gehoeren auf ein Profil, nicht auf einen VServer
            var profileName = event.dataTransfer.getData('text/plain');
            if (!profileName) return;
            openBindDialog(profileName, row);
        });
    });
});
