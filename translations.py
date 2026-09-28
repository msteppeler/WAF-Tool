"""
Leichtgewichtige Mehrsprachigkeit ohne zusätzliche Paketabhängigkeit (z.B.
Flask-Babel) - das Projekt hat keine requirements.txt/Paketverwaltung, über
die eine neue Abhängigkeit zuverlässig ins Docker-Image gelangen würde,
deshalb bewusst nur Python-Standardbibliothek.

Aktueller Umfang (siehe README): Sidebar, Login-Seite und Dashboard-Seite
sind vollständig übersetzt. Die dynamischen Erfolgs-/Fehlermeldungen der
einzelnen Routen (app.py) sowie die Analysis- und Objekte-Seiten sind NOCH
NICHT übersetzt - das ist eine bewusste erste Ausbaustufe, keine Auslassung
aus Versehen (bei der Textmenge im gesamten Tool wäre alles auf einmal zu
fehleranfällig gewesen).
"""

SUPPORTED_LOCALES = ['de', 'it', 'fr', 'en']
DEFAULT_LOCALE = 'en'

TRANSLATIONS = {
    'de': {
        'configuration.title_tag': 'Konfiguration – WAF Monitor',
        'time.minute_1': '1 Minute',
        'time.minutes_3': '3 Minuten',
        'time.minutes_5': '5 Minuten',
        'logging.title_tag': 'Protokollierung – WAF Monitor',
        'logging.entries_from': 'WAF-Einträge aus',
        'logging.search_placeholder': 'Suche, z. B. Transaktions-ID',
        'logging.clear_filter_title': 'Filter löschen',
        'logging.action_label': 'Aktion',
        'logging.poll_interval_label': 'Aktualisieren alle',
        'logging.fetch_now': 'Jetzt abrufen',
        'logging.fetch_now_title': 'Sofort neu vom NetScaler abrufen',
        'logging.clear_list': 'Liste leeren',
        'logging.clear_list_title': 'Nur die Anzeige leeren, nicht das ns.log',
        'logging.no_filter_matches': 'Keine Einträge entsprechen den Filterkriterien.',
        'logging.no_entries': 'Keine WAF-Einträge in {filename} gefunden.',
        'logging.detail_message': 'Meldung',
        'logging.detail_request_url': 'Request-URL',
        'logging.detail_severity': 'Schweregrad',
        'logging.js_updating': 'aktualisiere…',
        'logging.js_session_expired': 'Sitzung abgelaufen – bitte neu anmelden',
        'logging.js_last_updated_prefix': 'zuletzt aktualisiert um ',
        'logging.js_update_failed': 'Aktualisierung fehlgeschlagen – Verbindung prüfen',
        'logging.js_list_cleared_prefix': 'Liste geleert um ',
        'logging.js_list_cleared_suffix': ' – wird bei der nächsten Aktualisierung (Polling oder „Fetch now“) neu befüllt.',
        'sidebar.tagline': 'appfw · policy console',
        'sidebar.navigation': 'Navigation',
        'sidebar.dashboard': 'Dashboard',
        'sidebar.policies': 'Policies',
        'sidebar.default_profiles': 'Default-Profile',
        'sidebar.custom_profiles': 'Custom-Profile',
        'sidebar.configuration': 'Konfiguration',
        'sidebar.logging': 'Protokollierung',
        'sidebar.logged_in_as': 'Angemeldet als',
        'sidebar.logout': 'Abmelden',

        'login.title_tag': 'Anmeldung – WAF Monitor',
        'login.heading': 'Anmelden',
        'login.hint': 'Zugangsdaten des NetScaler-Geräts eingeben.',
        'login.field_nsip': 'NetScaler-IP',
        'login.field_nsip_placeholder': 'z. B. 10.20.30.40',
        'login.field_username': 'Benutzername',
        'login.field_password': 'Passwort',
        'login.submit': 'Anmelden',
        'login.footnote': 'NITRO API · Verbindung per HTTPS empfohlen',

        'dashboard.title': 'Übersicht',
        'dashboard.section_policies': 'WAF Policies',
        'dashboard.no_policies': 'Keine WAF Policies gefunden oder API-Fehler.',
        'dashboard.section_default_profiles': 'Default-Profile (Built-in)',
        'dashboard.no_default_profiles': 'Keine Default-Profile vorhanden.',
        'dashboard.section_custom_profiles': 'Custom-Profile (Eigene)',
        'dashboard.no_custom_profiles': 'Keine Custom-Profile vorhanden.',
        'dashboard.kpi_policies': 'WAF Policies',
        'dashboard.kpi_default_profiles': 'Default-Profile',
        'dashboard.kpi_custom_profiles': 'Custom-Profile',

        'policy.hits': 'Hits',
        'policy.not_bound': 'nicht gebunden',
        'policy.detail_profile': 'Profil',
        'policy.detail_hits': 'Hits',
        'policy.detail_vserver': 'vServer',
        'policy.no_binding': 'Keine Bindung gefunden',
        'policy.detail_comment': 'Kommentar',
        'policy.detail_rule': 'Regel',

        'profile.no_config': 'Keine weiteren Konfigurationsdaten vorhanden.',
        'profile.security_checks': 'Security Checks',
        'profile.general_settings': 'General Profile Settings',
        'check.save': 'Speichern',
        'check.discard': 'Verwerfen',

        'footer.nitro_api': 'NITRO API',
    },
    'it': {
        'configuration.title_tag': 'Configurazione – WAF Monitor',
        'time.minute_1': '1 minuto',
        'time.minutes_3': '3 minuti',
        'time.minutes_5': '5 minuti',
        'logging.title_tag': 'Registrazione – WAF Monitor',
        'logging.entries_from': 'Voci WAF da',
        'logging.search_placeholder': 'Cerca, es. ID transazione',
        'logging.clear_filter_title': 'Cancella filtro',
        'logging.action_label': 'Azione',
        'logging.poll_interval_label': 'Aggiorna ogni',
        'logging.fetch_now': 'Recupera ora',
        'logging.fetch_now_title': 'Recupera subito i dati dal NetScaler',
        'logging.clear_list': 'Svuota elenco',
        'logging.clear_list_title': 'Svuota solo la visualizzazione, non il ns.log',
        'logging.no_filter_matches': 'Nessuna voce corrisponde ai criteri di filtro.',
        'logging.no_entries': 'Nessuna voce WAF trovata in {filename}.',
        'logging.detail_message': 'Messaggio',
        'logging.detail_request_url': 'Request-URL',
        'logging.detail_severity': 'Gravità',
        'logging.js_updating': 'aggiornamento in corso…',
        'logging.js_session_expired': 'Sessione scaduta – effettua di nuovo l’accesso',
        'logging.js_last_updated_prefix': 'ultimo aggiornamento alle ',
        'logging.js_update_failed': 'Aggiornamento non riuscito – controlla la connessione',
        'logging.js_list_cleared_prefix': 'Elenco svuotato alle ',
        'logging.js_list_cleared_suffix': ' – verrà ripopolato al prossimo aggiornamento (polling o „Fetch now“).',
        'sidebar.tagline': 'appfw · console policy',
        'sidebar.navigation': 'Navigazione',
        'sidebar.dashboard': 'Dashboard',
        'sidebar.policies': 'Policy',
        'sidebar.default_profiles': 'Profili predefiniti',
        'sidebar.custom_profiles': 'Profili personalizzati',
        'sidebar.configuration': 'Configurazione',
        'sidebar.logging': 'Registrazione',
        'sidebar.logged_in_as': 'Connesso come',
        'sidebar.logout': 'Disconnetti',

        'login.title_tag': 'Accesso – WAF Monitor',
        'login.heading': 'Accedi',
        'login.hint': 'Inserisci le credenziali del dispositivo NetScaler.',
        'login.field_nsip': 'IP NetScaler',
        'login.field_nsip_placeholder': 'es. 10.20.30.40',
        'login.field_username': 'Nome utente',
        'login.field_password': 'Password',
        'login.submit': 'Accedi',
        'login.footnote': 'NITRO API · Si consiglia una connessione HTTPS',

        'dashboard.title': 'Panoramica',
        'dashboard.section_policies': 'WAF Policy',
        'dashboard.no_policies': 'Nessuna policy WAF trovata o errore API.',
        'dashboard.section_default_profiles': 'Profili predefiniti (integrati)',
        'dashboard.no_default_profiles': 'Nessun profilo predefinito disponibile.',
        'dashboard.section_custom_profiles': 'Profili personalizzati (propri)',
        'dashboard.no_custom_profiles': 'Nessun profilo personalizzato disponibile.',
        'dashboard.kpi_policies': 'WAF Policy',
        'dashboard.kpi_default_profiles': 'Profili predefiniti',
        'dashboard.kpi_custom_profiles': 'Profili personalizzati',

        'policy.hits': 'Hit',
        'policy.not_bound': 'non associato',
        'policy.detail_profile': 'Profilo',
        'policy.detail_hits': 'Hit',
        'policy.detail_vserver': 'vServer',
        'policy.no_binding': 'Nessuna associazione trovata',
        'policy.detail_comment': 'Commento',
        'policy.detail_rule': 'Regola',

        'profile.no_config': 'Nessun altro dato di configurazione disponibile.',
        'profile.security_checks': 'Security Checks',
        'profile.general_settings': 'General Profile Settings',
        'check.save': 'Salva',
        'check.discard': 'Annulla',

        'footer.nitro_api': 'NITRO API',
    },
    'fr': {
        'configuration.title_tag': 'Configuration – WAF Monitor',
        'time.minute_1': '1 minute',
        'time.minutes_3': '3 minutes',
        'time.minutes_5': '5 minutes',
        'logging.title_tag': 'Journalisation – WAF Monitor',
        'logging.entries_from': 'Entrées WAF depuis',
        'logging.search_placeholder': 'Rechercher, p. ex. ID de transaction',
        'logging.clear_filter_title': 'Effacer le filtre',
        'logging.action_label': 'Action',
        'logging.poll_interval_label': 'Actualiser toutes les',
        'logging.fetch_now': 'Récupérer maintenant',
        'logging.fetch_now_title': 'Récupérer immédiatement depuis le NetScaler',
        'logging.clear_list': 'Vider la liste',
        'logging.clear_list_title': "Vide uniquement l'affichage, pas le ns.log",
        'logging.no_filter_matches': 'Aucune entrée ne correspond aux critères de filtre.',
        'logging.no_entries': 'Aucune entrée WAF trouvée dans {filename}.',
        'logging.detail_message': 'Message',
        'logging.detail_request_url': 'Request-URL',
        'logging.detail_severity': 'Gravité',
        'logging.js_updating': 'actualisation en cours…',
        'logging.js_session_expired': 'Session expirée – veuillez vous reconnecter',
        'logging.js_last_updated_prefix': 'dernière actualisation à ',
        'logging.js_update_failed': 'Échec de l’actualisation – vérifiez la connexion',
        'logging.js_list_cleared_prefix': 'Liste vidée à ',
        'logging.js_list_cleared_suffix': ' – sera à nouveau remplie lors de la prochaine actualisation (polling ou « Fetch now »).',
        'sidebar.tagline': 'appfw · console policy',
        'sidebar.navigation': 'Navigation',
        'sidebar.dashboard': 'Dashboard',
        'sidebar.policies': 'Policies',
        'sidebar.default_profiles': 'Profils par défaut',
        'sidebar.custom_profiles': 'Profils personnalisés',
        'sidebar.configuration': 'Configuration',
        'sidebar.logging': 'Journalisation',
        'sidebar.logged_in_as': 'Connecté en tant que',
        'sidebar.logout': 'Déconnexion',

        'login.title_tag': 'Connexion – WAF Monitor',
        'login.heading': 'Connexion',
        'login.hint': "Saisissez les identifiants de l'appliance NetScaler.",
        'login.field_nsip': 'IP NetScaler',
        'login.field_nsip_placeholder': 'p. ex. 10.20.30.40',
        'login.field_username': "Nom d'utilisateur",
        'login.field_password': 'Mot de passe',
        'login.submit': 'Se connecter',
        'login.footnote': 'API NITRO · Connexion HTTPS recommandée',

        'dashboard.title': 'Aperçu',
        'dashboard.section_policies': 'WAF Policies',
        'dashboard.no_policies': 'Aucune policy WAF trouvée ou erreur API.',
        'dashboard.section_default_profiles': 'Profils par défaut (intégrés)',
        'dashboard.no_default_profiles': 'Aucun profil par défaut disponible.',
        'dashboard.section_custom_profiles': 'Profils personnalisés (propres)',
        'dashboard.no_custom_profiles': 'Aucun profil personnalisé disponible.',
        'dashboard.kpi_policies': 'WAF Policies',
        'dashboard.kpi_default_profiles': 'Profils par défaut',
        'dashboard.kpi_custom_profiles': 'Profils personnalisés',

        'policy.hits': 'Hits',
        'policy.not_bound': 'non liée',
        'policy.detail_profile': 'Profil',
        'policy.detail_hits': 'Hits',
        'policy.detail_vserver': 'vServer',
        'policy.no_binding': 'Aucune liaison trouvée',
        'policy.detail_comment': 'Commentaire',
        'policy.detail_rule': 'Règle',

        'profile.no_config': 'Aucune autre donnée de configuration disponible.',
        'profile.security_checks': 'Security Checks',
        'profile.general_settings': 'General Profile Settings',
        'check.save': 'Enregistrer',
        'check.discard': 'Annuler',

        'footer.nitro_api': 'NITRO API',
    },
    'en': {
        'configuration.title_tag': 'Configuration – WAF Monitor',
        'time.minute_1': '1 minute',
        'time.minutes_3': '3 minutes',
        'time.minutes_5': '5 minutes',
        'logging.title_tag': 'Logging – WAF Monitor',
        'logging.entries_from': 'WAF entries from',
        'logging.search_placeholder': 'Search, e.g. transaction ID',
        'logging.clear_filter_title': 'Clear filter',
        'logging.action_label': 'Action',
        'logging.poll_interval_label': 'Refresh every',
        'logging.fetch_now': 'Fetch now',
        'logging.fetch_now_title': 'Fetch immediately from the NetScaler',
        'logging.clear_list': 'Clear list',
        'logging.clear_list_title': 'Clears only the display, not the ns.log',
        'logging.no_filter_matches': 'No entries match the filter criteria.',
        'logging.no_entries': 'No WAF entries found in {filename}.',
        'logging.detail_message': 'Message',
        'logging.detail_request_url': 'Request-URL',
        'logging.detail_severity': 'Severity',
        'logging.js_updating': 'refreshing…',
        'logging.js_session_expired': 'Session expired – please log in again',
        'logging.js_last_updated_prefix': 'last updated at ',
        'logging.js_update_failed': 'Refresh failed – check the connection',
        'logging.js_list_cleared_prefix': 'List cleared at ',
        'logging.js_list_cleared_suffix': ' – will be refilled on the next update (polling or "Fetch now").',
        'sidebar.tagline': 'appfw · policy console',
        'sidebar.navigation': 'Navigation',
        'sidebar.dashboard': 'Dashboard',
        'sidebar.policies': 'Policies',
        'sidebar.default_profiles': 'Default Profiles',
        'sidebar.custom_profiles': 'Custom Profiles',
        'sidebar.configuration': 'Configuration',
        'sidebar.logging': 'Logging',
        'sidebar.logged_in_as': 'Logged in as',
        'sidebar.logout': 'Log out',

        'login.title_tag': 'Login – WAF Monitor',
        'login.heading': 'Log in',
        'login.hint': 'Enter the NetScaler device credentials.',
        'login.field_nsip': 'NetScaler IP',
        'login.field_nsip_placeholder': 'e.g. 10.20.30.40',
        'login.field_username': 'Username',
        'login.field_password': 'Password',
        'login.submit': 'Log in',
        'login.footnote': 'NITRO API · HTTPS connection recommended',

        'dashboard.title': 'Overview',
        'dashboard.section_policies': 'WAF Policies',
        'dashboard.no_policies': 'No WAF policies found or API error.',
        'dashboard.section_default_profiles': 'Default Profiles (Built-in)',
        'dashboard.no_default_profiles': 'No default profiles available.',
        'dashboard.section_custom_profiles': 'Custom Profiles (Own)',
        'dashboard.no_custom_profiles': 'No custom profiles available.',
        'dashboard.kpi_policies': 'WAF Policies',
        'dashboard.kpi_default_profiles': 'Default Profiles',
        'dashboard.kpi_custom_profiles': 'Custom Profiles',

        'policy.hits': 'Hits',
        'policy.not_bound': 'not bound',
        'policy.detail_profile': 'Profile',
        'policy.detail_hits': 'Hits',
        'policy.detail_vserver': 'vServer',
        'policy.no_binding': 'No binding found',
        'policy.detail_comment': 'Comment',
        'policy.detail_rule': 'Rule',

        'profile.no_config': 'No further configuration data available.',
        'profile.security_checks': 'Security Checks',
        'profile.general_settings': 'General Profile Settings',
        'check.save': 'Save',
        'check.discard': 'Discard',

        'footer.nitro_api': 'NITRO API',
    },
}


def detect_locale(accept_language_header):
    """
    Wählt die beste unterstützte Sprache (de/it/fr/en) aus dem
    "Accept-Language"-Header des Browsers. Fällt auf Englisch zurück, wenn
    keine der im Header genannten Sprachen unterstützt wird (so vom Nutzer
    gewünscht) oder der Header fehlt/leer ist.
    """
    if not accept_language_header:
        return DEFAULT_LOCALE
    # Header-Format: "de-DE,de;q=0.9,en;q=0.8" - nach Priorität (q) sortiert,
    # dann jeweils nur den Sprachanteil vor einem eventuellen "-" betrachten.
    entries = []
    for part in accept_language_header.split(','):
        part = part.strip()
        if not part:
            continue
        if ';q=' in part:
            lang, q = part.split(';q=', 1)
            try:
                quality = float(q)
            except ValueError:
                quality = 1.0
        else:
            lang, quality = part, 1.0
        entries.append((lang.strip().split('-')[0].lower(), quality))
    entries.sort(key=lambda pair: pair[1], reverse=True)
    for lang, _ in entries:
        if lang in SUPPORTED_LOCALES:
            return lang
    return DEFAULT_LOCALE


def translate(locale, key, **kwargs):
    """Gibt die Übersetzung von 'key' in 'locale' zurück, fällt auf Englisch
    und dann auf den Key selbst zurück, falls nicht vorhanden (damit ein
    fehlender Schlüssel sichtbar auffällt statt eine Exception zu werfen).
    Übergebene kwargs werden per str.format() in Platzhalter eingesetzt
    (z.B. 'log.no_entries': 'Keine Einträge in {filename} gefunden.')."""
    table = TRANSLATIONS.get(locale, TRANSLATIONS[DEFAULT_LOCALE])
    text = table.get(key, TRANSLATIONS[DEFAULT_LOCALE].get(key, key))
    if kwargs:
        try:
            return text.format(**kwargs)
        except (KeyError, IndexError):
            return text
    return text
