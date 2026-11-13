function setActionButtonBusy(button, text) {
    button.disabled = true;
    if (!button.dataset.originalText) {
        button.dataset.originalText = button.textContent.trim();
    }
    button.textContent = text;
}

function setActionButtonResult(button, success, message) {
    button.disabled = success;
    button.textContent = success ? '✓ Übernommen' : (button.dataset.originalText || 'Erneut versuchen');
    button.classList.toggle('bo-success', success);
    button.classList.toggle('bo-error', !success);

    var row = button.closest('.bo-action-row');
    if (!row) return;
    var statusEl = row.querySelector('.bo-status-message');
    if (!statusEl) {
        statusEl = document.createElement('div');
        statusEl.className = 'bo-status-message';
        row.appendChild(statusEl);
    }
    statusEl.textContent = message;
    statusEl.classList.toggle('bo-status-error', !success);
}

function postAnalysisWriteAction(url, payload, button) {
    fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    })
        .then(function (response) {
            return response.json().then(function (data) {
                return { status: response.status, data: data };
            });
        })
        .then(function (result) {
            if (result.status === 401) {
                setActionButtonResult(button, false, 'Sitzung abgelaufen – bitte neu anmelden.');
                return;
            }
            setActionButtonResult(button, !!result.data.success, result.data.message || 'Unbekannter Fehler.');
        })
        .catch(function () {
            setActionButtonResult(button, false, 'Netzwerkfehler – bitte erneut versuchen.');
        });
}
