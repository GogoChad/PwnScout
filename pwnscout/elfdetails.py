"""Additional static ELF facts. No execution of the inspected file."""


def inspect_elf_details(elf):
    sections = []
    for s in elf.iter_sections():
        flags = int(s['sh_flags'])
        sections.append({
            'name': s.name or '(unnamed)', 'type': str(s['sh_type']),
            'address': hex(int(s['sh_addr'])), 'offset': hex(int(s['sh_offset'])),
            'size': int(s['sh_size']),
            'flags': ''.join(c for bit, c in ((2, 'A'), (1, 'W'), (4, 'X')) if flags & bit) or '-',
        })
    segments = []
    for p in elf.iter_segments():
        flags = int(p['p_flags'])
        segments.append({
            'type': str(p['p_type']), 'vaddr': hex(int(p['p_vaddr'])),
            'filesz': int(p['p_filesz']), 'memsz': int(p['p_memsz']),
            'permissions': ''.join(c for bit, c in ((4, 'R'), (2, 'W'), (1, 'X')) if flags & bit) or '-',
        })
    dependencies, rpath, runpath = [], [], []
    from elftools.elf.dynamic import DynamicSection
    for section in elf.iter_sections():
        if not isinstance(section, DynamicSection):
            continue
        for tag in section.iter_tags():
            kind = str(tag.entry.d_tag)
            if kind == 'DT_NEEDED':
                dependencies.append(tag.needed)
            elif kind == 'DT_RPATH':
                rpath.append(tag.rpath)
            elif kind == 'DT_RUNPATH':
                runpath.append(tag.runpath)
    return {
        'sections': sections,
        'segments': segments,
        'dependencies': list(dict.fromkeys(dependencies)),
        'rpath': list(dict.fromkeys(rpath)),
        'runpath': list(dict.fromkeys(runpath)),
    }


def inspect_security_details(elf, details, protections):
    issues = []
    def add(code, severity, finding, explanation):
        issues.append({'code': code, 'severity': severity, 'finding': finding, 'explanation': explanation})
    if protections['NX'] == 'Disabled':
        add('NX_OFF', 'High', 'Executable stack', 'PT_GNU_STACK permits execution.')
    elif protections['NX'] == 'Unknown':
        add('NX_UNKNOWN', 'Info', 'NX could not be established', 'PT_GNU_STACK not available.')
    if protections['PIE'] == 'Disabled':
        add('PIE_OFF', 'Medium', 'PIE disabled', 'Executable is not position independent.')
    if protections['RELRO'] == 'No RELRO':
        add('RELRO_OFF', 'Medium', 'RELRO missing', 'No PT_GNU_RELRO segment.')
    elif protections['RELRO'] == 'Partial':
        add('RELRO_PARTIAL', 'Low', 'Partial RELRO', 'Lazy binding may remain available.')
    if protections['Stack Canary'] != 'Enabled':
        add('CANARY_UNKNOWN', 'Info', 'No stack canary detected', 'Symbol heuristic only; absence does not establish exploitability.')
    if details['rpath']:
        add('RPATH', 'Medium', 'RPATH embedded', ', '.join(details['rpath']))
    if details['runpath']:
        add('RUNPATH', 'Info', 'RUNPATH embedded', ', '.join(details['runpath']))
    for p in details['segments']:
        if p['type'] == 'PT_LOAD' and 'W' in p['permissions'] and 'X' in p['permissions']:
            add('WX_SEGMENT', 'High', 'Writable executable load segment', f"{p['vaddr']} has {p['permissions']} permissions")
    return issues
