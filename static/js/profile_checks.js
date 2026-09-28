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
});
