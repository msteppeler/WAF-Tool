const defaultStates = {
    'policies': 'open',
    'default-profiles': 'closed',
    'custom-profiles': 'open',
    'vservers': 'open',
    'waf-profiles': 'open',
    'signatures': 'open',
    'signature-categories': 'open'
};

function toggleSection(sectionId) {
    const content = document.getElementById('content-' + sectionId);
    const toggle = document.getElementById('toggle-' + sectionId);
    if (!content || !toggle) return;
    const isOpen = content.classList.contains('open');
    if (isOpen) {
        content.classList.remove('open');
        toggle.classList.add('closed');
        localStorage.setItem('section-' + sectionId, 'closed');
    } else {
        content.classList.add('open');
        toggle.classList.remove('closed');
        localStorage.setItem('section-' + sectionId, 'open');
    }
}

function toggleDetails(id) {
    const details = document.getElementById('details-' + id);
    if (!details) return;
    details.classList.toggle('open');
    const arrow = document.getElementById('arrow-' + id);
    if (arrow) arrow.classList.toggle('closed', !details.classList.contains('open'));
}

function jumpToProfile(profileName) {
    const row = document.getElementById('profile-' + profileName);
    if (!row) return;

    const section = row.closest('.section-content');
    if (section && !section.classList.contains('open')) {
        toggleSection(section.id.replace('content-', ''));
    }

    const details = document.getElementById('details-profile-' + profileName);
    if (details) details.classList.add('open');

    setTimeout(function() {
        row.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }, 150);

    row.classList.add('highlight');
    setTimeout(function() { row.classList.remove('highlight'); }, 1600);
}

document.addEventListener('DOMContentLoaded', function() {
    const sections = ['policies', 'default-profiles', 'custom-profiles', 'vservers', 'waf-profiles', 'signatures', 'signature-categories'];
    sections.forEach(function(id) {
        const content = document.getElementById('content-' + id);
        const toggle = document.getElementById('toggle-' + id);
        if (!content || !toggle) return;
        let state = localStorage.getItem('section-' + id);
        if (state === null) {
            state = defaultStates[id] || 'open';
        }
        if (state === 'open') {
            content.classList.add('open');
            toggle.classList.remove('closed');
        } else {
            content.classList.remove('open');
            toggle.classList.add('closed');
        }
    });

    // Sprung von einer anderen Seite (z.B. Analysis) direkt zu einem Profil,
    // per ?jump_profile=<name> in der URL.
    const params = new URLSearchParams(window.location.search);
    const jumpProfile = params.get('jump_profile');
    if (jumpProfile) {
        jumpToProfile(jumpProfile);
        params.delete('jump_profile');
        const newSearch = params.toString();
        const newUrl = window.location.pathname + (newSearch ? '?' + newSearch : '') + window.location.hash;
        window.history.replaceState({}, '', newUrl);
    }
});
