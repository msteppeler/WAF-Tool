function handleBufferOverflowRelax(button) {
    var profile = button.dataset.profile;
    var field = button.dataset.field;
    var fieldLabel = button.dataset.fieldLabel;
    var value = button.dataset.value;
    var currentMax = button.dataset.currentMax;

    var confirmText = fieldLabel + ' im Profil "' + profile + '" ';
    confirmText += currentMax
        ? ('von ' + currentMax + ' auf ' + value + ' erhöhen?')
        : ('auf ' + value + ' setzen?');

    if (!window.confirm(confirmText)) return;

    setActionButtonBusy(button, 'Wird gespeichert…');
    postAnalysisWriteAction('/analysis/buffer-overflow/relax', {
        profile: profile,
        field: field,
        value: value
    }, button);
}

function handleBufferOverflowActivate(button) {
    var profile = button.dataset.profile;
    var confirmText = 'Block-Aktion für Buffer Overflow im Profil "' + profile + '" aktivieren? '
        + 'Bestehende Aktionen (z. B. Log/Stats) bleiben erhalten.';

    if (!window.confirm(confirmText)) return;

    setActionButtonBusy(button, 'Wird aktiviert…');
    postAnalysisWriteAction('/analysis/buffer-overflow/activate', {
        profile: profile
    }, button);
}
