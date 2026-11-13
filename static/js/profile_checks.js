/* Editierbare Security-Check-Aktionen (Learning/Block/Stat/Log) je Profil
 * auf der Dashboard-Seite. Eine Zeile gilt als "geändert" (dirty), sobald
 * mindestens eine der vier Checkboxen von ihrem Ausgangszustand abweicht
 * (checkbox.checked vs. checkbox.defaultChecked - defaultChecked spiegelt
 * das vom Server gerenderte "checked"-HTML-Attribut wider und bleibt beim
 * Klicken unverändert, ist also der ideale Vergleichswert ohne eigene
 * data-Attribute). Erst dann erscheinen Speichern/Verwerfen. */

function checkRowIsDirty(row) {
    var boxes = row.querySelectorAll('.check-action-box');
    for (var i = 0; i < boxes.length; i++) {
        if (boxes[i].checked !== boxes[i].defaultChecked) return true;
    }
    return false;
}

function updateCheckRowState(row) {
    var actionRow = row.querySelector('.check-action-row');
    if (!actionRow) return;
    actionRow.hidden = !checkRowIsDirty(row);
}

function cancelCheckAction(button) {
    var row = button.closest('.check-row');
    row.querySelectorAll('.check-action-box').forEach(function (box) {
        box.checked = box.defaultChecked;
    });
    row.querySelector('.check-action-message').textContent = '';
    updateCheckRowState(row);
}

function saveCheckAction(button) {
    var row = button.closest('.check-row');
    var profile = row.dataset.profile;
    var checkKey = row.dataset.checkKey;
    var boxes = row.querySelectorAll('.check-action-box');
    var tokens = [];
    boxes.forEach(function (box) {
        if (box.checked) tokens.push(box.dataset.token);
    });

    var saveButton = row.querySelector('.check-action-save');
    var cancelButton = row.querySelector('.check-action-cancel');
    var messageEl = row.querySelector('.check-action-message');
    saveButton.disabled = true;
    cancelButton.disabled = true;
    boxes.forEach(function (box) { box.disabled = true; });
    messageEl.className = 'check-action-message';
    messageEl.textContent = 'Wird gespeichert…';

    fetch('/profile/' + encodeURIComponent(profile) + '/check/' + encodeURIComponent(checkKey) + '/action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tokens: tokens })
    })
        .then(function (response) {
            return response.json().then(function (data) { return { status: response.status, data: data }; });
        })
        .then(function (result) {
            boxes.forEach(function (box) { box.disabled = false; });
            saveButton.disabled = false;
            cancelButton.disabled = false;

            if (result.status === 401) {
                messageEl.classList.add('check-action-error');
                messageEl.textContent = 'Sitzung abgelaufen – bitte neu anmelden.';
                return;
            }
            var success = !!result.data.success;
            messageEl.classList.toggle('check-action-error', !success);
            messageEl.textContent = result.data.message || 'Unbekannter Fehler.';
            if (success) {
                // Neuer Ausgangszustand: aktuelle Auswahl wird zur neuen "Baseline",
                // dadurch verschwinden Speichern/Verwerfen wieder.
                boxes.forEach(function (box) { box.defaultChecked = box.checked; });
                updateCheckRowState(row);
                var nameEl = row.querySelector('.check-name');
                if (nameEl) nameEl.classList.toggle('inactive', tokens.length === 0);
            }
        })
        .catch(function () {
            boxes.forEach(function (box) { box.disabled = false; });
            saveButton.disabled = false;
            cancelButton.disabled = false;
            messageEl.classList.add('check-action-error');
            messageEl.textContent = 'Netzwerkfehler – bitte erneut versuchen.';
        });
}

document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('.check-row').forEach(function (row) {
        row.querySelectorAll('.check-action-box').forEach(function (box) {
            box.addEventListener('change', function () { updateCheckRowState(row); });
        });
    });
    document.querySelectorAll('.check-details').forEach(function (details) {
        details.querySelectorAll('.detail-field-input').forEach(function (input) {
            input.addEventListener('change', function () { updateCheckDetailsState(details); });
            if (input.tagName === 'INPUT') {
                input.addEventListener('input', function () { updateCheckDetailsState(details); });
            }
        });
    });
});

/* Editierbare Check-Detail-Felder (z.B. Cookie-Consistency-Transform-Werte,
 * Field-Format-Grenzwerte) - dieselbe Speichern/Verwerfen-Logik wie bei den
 * vier Aktions-Kaestchen oben, aber als eigener Abschnitt innerhalb der
 * aufgeklappten Details, da es fachlich ein anderer Schreibvorgang ist
 * (Detail-Felder statt Learning/Block/Stat/Log). "Dirty" wird per
 * data-original (vom Server gerenderter Ausgangswert) statt defaultChecked
 * erkannt, da Text-/Select-Felder kein Aequivalent dazu haben. */

// Checkbox-Gruppen (mehrere <input type="checkbox"> mit demselben data-field,
// z.B. die Kreditkarten-Typen) tragen den Ausgangswert nicht am einzelnen
// Kaestchen (dessen .value ist immer der feste Options-Token, z.B. "visa"),
// sondern als JSON-Array am umschliessenden .detail-field-checkbox-list -
// deshalb bei Checkboxen ueber diesen Container statt ueber .value/.dataset
// am Input selbst gehen.
function getCheckboxListOriginal(details, fieldName) {
    var container = details.querySelector('.detail-field-checkbox-list[data-field="' + fieldName + '"]');
    if (!container) return [];
    try { return JSON.parse(container.dataset.original) || []; } catch (e) { return []; }
}

function getCheckboxListCurrent(details, fieldName) {
    var boxes = details.querySelectorAll('.detail-field-input[type="checkbox"][data-field="' + fieldName + '"]:checked');
    return Array.prototype.map.call(boxes, function (b) { return b.value; });
}

function sameStringSet(a, b) {
    if (a.length !== b.length) return false;
    var sortedA = a.slice().sort(), sortedB = b.slice().sort();
    for (var i = 0; i < sortedA.length; i++) { if (sortedA[i] !== sortedB[i]) return false; }
    return true;
}

function checkDetailsIsDirty(details) {
    var seenCheckboxFields = {};
    var inputs = details.querySelectorAll('.detail-field-input');
    for (var i = 0; i < inputs.length; i++) {
        var input = inputs[i];
        if (input.type === 'checkbox') {
            var fieldName = input.dataset.field;
            if (seenCheckboxFields[fieldName]) continue;  // Gruppe nur einmal pruefen
            seenCheckboxFields[fieldName] = true;
            if (!sameStringSet(getCheckboxListCurrent(details, fieldName), getCheckboxListOriginal(details, fieldName))) return true;
        } else if (input.value !== input.dataset.original) {
            return true;
        }
    }
    return false;
}

function updateCheckDetailsState(details) {
    var actionRow = details.querySelector('.check-detail-action-row');
    if (!actionRow) return;
    actionRow.hidden = !checkDetailsIsDirty(details);
}

function cancelCheckDetails(button) {
    var details = button.closest('.check-details');
    var handledCheckboxFields = {};
    details.querySelectorAll('.detail-field-input').forEach(function (input) {
        if (input.type === 'checkbox') {
            var fieldName = input.dataset.field;
            if (!handledCheckboxFields[fieldName]) {
                handledCheckboxFields[fieldName] = getCheckboxListOriginal(details, fieldName);
            }
            input.checked = handledCheckboxFields[fieldName].indexOf(input.value) !== -1;
        } else {
            input.value = input.dataset.original;
        }
    });
    details.querySelector('.check-action-message').textContent = '';
    updateCheckDetailsState(details);
}

function saveCheckDetails(button) {
    var details = button.closest('.check-details');
    var profile = details.dataset.profile;
    var checkKey = details.dataset.checkKey;
    var inputs = details.querySelectorAll('.detail-field-input');
    var fields = {};
    var handledCheckboxFields = {};
    inputs.forEach(function (input) {
        if (input.type === 'checkbox') {
            var fieldName = input.dataset.field;
            if (!handledCheckboxFields[fieldName]) {
                fields[fieldName] = getCheckboxListCurrent(details, fieldName);
                handledCheckboxFields[fieldName] = true;
            }
        } else {
            fields[input.dataset.field] = input.value;
        }
    });

    var saveButton = details.querySelector('.check-action-save');
    var cancelButton = details.querySelector('.check-action-cancel');
    var messageEl = details.querySelector('.check-action-message');
    saveButton.disabled = true;
    cancelButton.disabled = true;
    inputs.forEach(function (input) { input.disabled = true; });
    messageEl.className = 'check-action-message';
    messageEl.textContent = 'Wird gespeichert…';

    fetch('/profile/' + encodeURIComponent(profile) + '/check/' + encodeURIComponent(checkKey) + '/details', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: fields })
    })
        .then(function (response) {
            return response.json().then(function (data) { return { status: response.status, data: data }; });
        })
        .then(function (result) {
            inputs.forEach(function (input) { input.disabled = false; });
            saveButton.disabled = false;
            cancelButton.disabled = false;

            if (result.status === 401) {
                messageEl.classList.add('check-action-error');
                messageEl.textContent = 'Sitzung abgelaufen – bitte neu anmelden.';
                return;
            }
            var success = !!result.data.success;
            messageEl.classList.toggle('check-action-error', !success);
            messageEl.textContent = result.data.message || 'Unbekannter Fehler.';
            if (success) {
                var savedCheckboxFields = {};
                inputs.forEach(function (input) {
                    if (input.type === 'checkbox') {
                        var fieldName = input.dataset.field;
                        if (!savedCheckboxFields[fieldName]) {
                            var container = details.querySelector('.detail-field-checkbox-list[data-field="' + fieldName + '"]');
                            if (container) container.dataset.original = JSON.stringify(getCheckboxListCurrent(details, fieldName));
                            savedCheckboxFields[fieldName] = true;
                        }
                    } else {
                        input.dataset.original = input.value;
                    }
                });
                updateCheckDetailsState(details);
            }
        })
        .catch(function () {
            inputs.forEach(function (input) { input.disabled = false; });
            saveButton.disabled = false;
            cancelButton.disabled = false;
            messageEl.classList.add('check-action-error');
            messageEl.textContent = 'Netzwerkfehler – bitte erneut versuchen.';
        });
}
