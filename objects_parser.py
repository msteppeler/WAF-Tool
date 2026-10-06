"""
Aufbereitung der Infrastruktur-Objekte (VServer, Services, AppFW-Policy-
Bindings) für die "Objekte"-Seite - die Grundlage für die spätere,
objektbezogene Regel-Erstellung.

Bewusst getrennt von profile_parser.py: dort geht es um die Struktur EINES
appfwprofile-Objekts, hier um die Beziehungen ZWISCHEN VServern, Services
und Policies.
"""


def _backend_summary(service):
    """Kurzbeschreibung eines Service/ServiceGroup-Backends für die Anzeige."""
    parts = []
    if service.get('servicetype'):
        parts.append(service['servicetype'])
    if service.get('ip'):
        port = service.get('port')
        parts.append(f"{service['ip']}:{port}" if port else service['ip'])
    return ' · '.join(parts)


def structure_vserver(vserver, vserver_type, backends, policy_bindings, policies_by_name, profiles_by_name):
    """
    Baut ein einzelnes, angereichertes VServer-Objekt:
      name, type ('lb'/'cs'), ip, port, servicetype, state
      backends: [{name, kind ('service'/'servicegroup'), summary}]
      policies: [{name, priority, rule, profile, profile_exists}] - nach
                Priorität sortiert (aufsteigend = zuerst ausgewertet)
    policies_by_name / profiles_by_name: Lookup-Dicts (name -> Objekt) aus
    get_waf_policies()/get_waf_profiles(), um Regel-Ausdruck und Profil-Link
    ohne weitere NITRO-Aufrufe aufzulösen.
    """
    policies = []
    for binding in policy_bindings:
        policy_name = binding.get('policyname') or binding.get('name')
        if not policy_name:
            continue
        policy = policies_by_name.get(policy_name, {})
        profile_name = policy.get('profilename')
        policies.append({
            'name': policy_name,
            'priority': binding.get('priority'),
            'rule': policy.get('rule'),
            'profile': profile_name,
            'profile_exists': bool(profile_name and profile_name in profiles_by_name),
        })
    # Fehlende oder nicht-numerische Priorität ans Ende sortieren; die
    # Prioritätswerte kommen von NITRO als String und müssen für eine
    # korrekte (nicht lexikografische) Sortierung erst in int gewandelt
    # werden ("100" muss nach "20" kommen, nicht davor).
    def _priority_sort_key(p):
        try:
            return (0, int(p['priority']))
        except (TypeError, ValueError):
            return (1, 0)
    policies.sort(key=_priority_sort_key)

    return {
        'name': vserver.get('name'),
        'type': vserver_type,
        'ip': vserver.get('ipv46') or vserver.get('ip'),
        'port': vserver.get('port'),
        'servicetype': vserver.get('servicetype'),
        'state': vserver.get('curstate') or vserver.get('state'),
        'backends': backends,
        'policies': policies,
        'policy_count': len(policies),
    }
