(function () {
    var POLL_STORAGE_KEY = 'analysis-poll-interval';
    var ACTION_FILTER_STORAGE_KEY = 'analysis-filter-action';
    var pollTimer = null;

    // Von analysis.html eingebettete, in der aktuellen Sprache uebersetzte
    // Texte fuer die zur Laufzeit erzeugten Statusmeldungen (kann nicht rein
    // serverseitig im Template stehen, da diese Texte erst bei Ereignissen
    // wie einem fehlgeschlagenen Fetch entstehen).
    var I18N = (function () {
        var el = document.getElementById('logging-i18n-data');
        if (!el) return {};
        try { return JSON.parse(el.textContent) || {}; } catch (e) { return {}; }
    })();

    // 24-Stunden-Format fuer alle Sprachen (auch Englisch) - fuer ein
    // technisches Monitoring-Tool durchgaengiger als ein AM/PM-Wechsel nur
    // bei Englisch. document.documentElement.lang kommt aus base.html
    // (<html lang="...">), passend zur serverseitig erkannten Sprache.
    var TIME_LOCALES = { de: 'de-DE', it: 'it-IT', fr: 'fr-FR', en: 'en-GB' };
    var timeLocale = TIME_LOCALES[document.documentElement.lang] || 'en-GB';

    function formatTime(date) {
        return date.toLocaleTimeString(timeLocale, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }

    function setStatus(text, isStale) {
        var el = document.getElementById('refresh-status');
        if (!el) return;
        el.textContent = text;
        el.classList.toggle('stale', !!isStale);
    }

    function applyFilters() {
        var searchInput = document.getElementById('filter-search');
        var actionSelect = document.getElementById('filter-action');
        var emptyMessage = document.getElementById('filter-empty-message');
        var clearButton = document.getElementById('filter-search-clear');
        if (!searchInput || !actionSelect) return;

        // X-Button nur anzeigen, solange im Suchfeld etwas steht. Da
        // applyFilters() bei jeder Eingabe, nach jedem Poll und bei
        // filterByValue() läuft, bleibt der Button in allen Fällen synchron.
        if (clearButton) clearButton.hidden = searchInput.value === '';

        var search = searchInput.value.trim().toLowerCase();
        var actionFilter = actionSelect.value;

        var entries = document.querySelectorAll('#log-container .log-entry');
        var visibleCount = 0;

        entries.forEach(function (entry) {
            var action = entry.getAttribute('data-action') || '';
            var searchable = entry.getAttribute('data-search') || '';

            var matchesAction = actionFilter === 'all'
                || (actionFilter === 'blocked' && action === 'blocked')
                || (actionFilter === 'not_blocked' && action !== 'blocked');
            var matchesSearch = !search || searchable.indexOf(search) !== -1;

            var visible = matchesAction && matchesSearch;
            entry.style.display = visible ? '' : 'none';
            if (visible) visibleCount++;
        });

        if (emptyMessage) {
            emptyMessage.style.display = (entries.length > 0 && visibleCount === 0) ? '' : 'none';
        }
    }

    function filterByValue(value) {
        var searchInput = document.getElementById('filter-search');
        if (!searchInput) return;
        searchInput.value = value;
        applyFilters();
        searchInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
        searchInput.focus();
    }
    // Wird per inline onclick aus dynamisch eingefügtem Log-Karten-HTML
    // aufgerufen (siehe _log_entry.html) - muss daher global erreichbar sein.
    window.filterByValue = filterByValue;

    function refreshLog() {
        setStatus(I18N.updating || 'aktualisiere…');
        return fetch('/analysis/data', { headers: { 'X-Requested-With': 'fetch' } })
            .then(function (response) {
                if (response.status === 401) {
                    setStatus(I18N.session_expired || 'Sitzung abgelaufen – bitte neu anmelden', true);
                    stopPolling();
                    return null;
                }
                return response.text();
            })
            .then(function (html) {
                if (html === null) return;
                var container = document.getElementById('log-container');
                if (container) container.innerHTML = html;
                applyFilters();
                setStatus((I18N.last_updated_prefix || 'zuletzt aktualisiert um ') + formatTime(new Date()));
            })
            .catch(function () {
                setStatus(I18N.update_failed || 'Aktualisierung fehlgeschlagen – Verbindung prüfen', true);
            });
    }

    function clearList() {
        var container = document.getElementById('log-container');
        var emptyMessage = document.getElementById('filter-empty-message');
        if (!container) return;
        container.innerHTML = '<div class="log-cleared">' + (I18N.list_cleared_prefix || 'Liste geleert um ') + formatTime(new Date())
            + (I18N.list_cleared_suffix || ' – wird bei der nächsten Aktualisierung (Polling oder „Fetch now“) neu befüllt.') + '</div>';
        if (emptyMessage) emptyMessage.style.display = 'none';
    }

    function stopPolling() {
        if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
        }
    }

    function startPolling(seconds) {
        stopPolling();
        pollTimer = setInterval(refreshLog, seconds * 1000);
    }

    document.addEventListener('DOMContentLoaded', function () {
        var pollSelect = document.getElementById('poll-interval');
        var searchInput = document.getElementById('filter-search');
        var actionSelect = document.getElementById('filter-action');
        if (!pollSelect) return;

        var savedInterval = localStorage.getItem(POLL_STORAGE_KEY);
        if (savedInterval && pollSelect.querySelector('option[value="' + savedInterval + '"]')) {
            pollSelect.value = savedInterval;
        }

        var savedAction = localStorage.getItem(ACTION_FILTER_STORAGE_KEY);
        if (actionSelect && savedAction && actionSelect.querySelector('option[value="' + savedAction + '"]')) {
            actionSelect.value = savedAction;
        }

        // Filter auf die bereits serverseitig gerenderten Einträge anwenden
        applyFilters();

        setStatus((I18N.last_updated_prefix || 'zuletzt aktualisiert um ') + formatTime(new Date()));
        startPolling(parseInt(pollSelect.value, 10));

        pollSelect.addEventListener('change', function () {
            localStorage.setItem(POLL_STORAGE_KEY, pollSelect.value);
            startPolling(parseInt(pollSelect.value, 10));
            refreshLog();
        });

        if (searchInput) {
            searchInput.addEventListener('input', applyFilters);
        }

        var clearButton = document.getElementById('filter-search-clear');
        if (clearButton && searchInput) {
            clearButton.addEventListener('click', function () {
                searchInput.value = '';
                applyFilters();
                searchInput.focus();
            });
        }
        if (actionSelect) {
            actionSelect.addEventListener('change', function () {
                localStorage.setItem(ACTION_FILTER_STORAGE_KEY, actionSelect.value);
                applyFilters();
            });
        }

        var fetchNowButton = document.getElementById('fetch-now-btn');
        if (fetchNowButton) {
            fetchNowButton.addEventListener('click', function () {
                fetchNowButton.disabled = true;
                // Manuellen Fetch immer mit einem frischen Poll-Intervall verbinden,
                // damit direkt danach kein zweiter (automatischer) Fetch folgt.
                startPolling(parseInt(pollSelect.value, 10));
                refreshLog().finally(function () {
                    fetchNowButton.disabled = false;
                });
            });
        }

        var clearListButton = document.getElementById('clear-list-btn');
        if (clearListButton) {
            clearListButton.addEventListener('click', clearList);
        }
    });
})();

