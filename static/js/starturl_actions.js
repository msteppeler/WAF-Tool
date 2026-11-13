function handleStartUrlRelax(button) {
    var profile = button.dataset.profile;
    var pattern = button.dataset.pattern;

    var confirmText = 'Folgende Start-URL-Regel zum Profil "' + profile + '" hinzufügen?\n\n' + pattern;
    if (!window.confirm(confirmText)) return;

    setActionButtonBusy(button, 'Wird gespeichert…');
    postAnalysisWriteAction('/analysis/starturl/relax', {
        profile: profile,
        pattern: pattern
    }, button);
}
