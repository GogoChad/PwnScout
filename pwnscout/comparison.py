"""Compare two *already generated* static ELF analysis snapshots.

Differences describe indicators, not which binary is intrinsically secure.
"""

PROTECTION_ORDER = ('NX', 'PIE', 'RELRO', 'Stack Canary', 'FORTIFY')


def compare_reports(left, right):
    a = left['metadata']
    b = right['metadata']
    protections = []
    for name in PROTECTION_ORDER:
        before = str(left['protections'].get(name, 'Unknown'))
        after = str(right['protections'].get(name, 'Unknown'))
        protections.append({'name': name, 'left': before, 'right': after, 'changed': before != after})
    left_imports = set(left['symbols']['imports'])
    right_imports = set(right['symbols']['imports'])
    left_risky = {x['function'] for x in left['vulnerabilities']}
    right_risky = {x['function'] for x in right['vulnerabilities']}
    left_deps = set(left.get('details', {}).get('dependencies', []))
    right_deps = set(right.get('details', {}).get('dependencies', []))
    warnings = []
    if a.get('architecture') != b.get('architecture'):
        warnings.append('Different architectures: mitigation indicators may not be directly comparable.')
    if a.get('type') != b.get('type'):
        warnings.append('Different ELF types: interpret PIE and relocation differences with care.')
    if a.get('sha256') and a.get('sha256') == b.get('sha256'):
        warnings.append('Identical SHA-256 digests: both inputs have the same file content.')
    return {
        'warnings': warnings,
        'left': {'name': a['name'], 'path': a['file'], 'sha256': a.get('sha256', ''),
                 'architecture': a['architecture'], 'type': a['type'], 'size_bytes': a.get('size_bytes')},
        'right': {'name': b['name'], 'path': b['file'], 'sha256': b.get('sha256', ''),
                  'architecture': b['architecture'], 'type': b['type'], 'size_bytes': b.get('size_bytes')},
        'protections': protections,
        'changed_protections': sum(p['changed'] for p in protections),
        'imports': {'only_left': sorted(left_imports - right_imports), 'only_right': sorted(right_imports - left_imports)},
        'risky_imports': {'only_left': sorted(left_risky - right_risky), 'only_right': sorted(right_risky - left_risky)},
        'dependencies': {'only_left': sorted(left_deps - right_deps), 'only_right': sorted(right_deps - left_deps)},
        'note': 'Structural and heuristic differences only; not a vulnerability or exploitability verdict.',
    }
