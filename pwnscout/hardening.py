"""Explain observable ELF mitigations and suggest *conditional* compiler hardening.

The recommendations are not guarantees: build systems, code paths, toolchains and
runtime support determine the actual hardening applied to a binary.
"""

PROTECTION_GUIDE = {
    'NX': {
        'what': 'A non-executable stack discourages execution of injected code from stack memory.',
        'limits': 'NX does not prevent code-reuse attacks or memory corruption.',
        'verify': 'readelf -lW <binary>  # inspect GNU_STACK flags',
        'flags': '-Wl,-z,noexecstack',
        'advice': 'Ensure the stack is not marked executable; investigate assembly objects that require an executable stack.',
    },
    'PIE': {
        'what': 'Position-independent executables can be relocated in memory, supporting ASLR.',
        'limits': 'ASLR also depends on the operating system; an ET_DYN shared library is not automatically a PIE executable.',
        'verify': 'readelf -h <binary> && readelf -lW <binary>  # type and INTERP',
        'flags': '-fPIE -pie',
        'advice': 'For executable programs, build and link as PIE where supported.',
    },
    'RELRO': {
        'what': 'RELRO makes selected relocation-related memory regions read-only after dynamic linking.',
        'limits': 'Full RELRO depends on dynamic linking and eager binding; it does not remove all writable pointers.',
        'verify': 'readelf -lW <binary> && readelf -dW <binary>  # GNU_RELRO and BIND_NOW',
        'flags': '-Wl,-z,relro,-z,now',
        'advice': 'Enable RELRO and immediate binding where compatible with startup and linking requirements.',
    },
    'Stack Canary': {
        'what': 'Compiler-inserted checks can detect certain stack buffer overwrites before returning.',
        'limits': 'Not every function is instrumented; import-symbol detection can miss static binaries or other implementations.',
        'verify': 'readelf -Ws <binary> | grep __stack_chk_fail  # heuristic only',
        'flags': '-fstack-protector-strong',
        'advice': 'Enable stack protector instrumentation; check representative vulnerable functions in disassembly.',
    },
    'FORTIFY': {
        'what': 'Some libc calls receive additional compile-time or runtime checks when their object sizes are known.',
        'limits': 'Requires appropriate optimization, headers and libc support; absence of _chk imports does not prove it is disabled.',
        'verify': 'readelf -Ws <binary> | grep _chk  # heuristic only',
        'flags': '-O2 -D_FORTIFY_SOURCE=2',
        'advice': 'Enable supported optimization and fortification; review build warnings and target libc.',
    },
}


def explain_protections(protections):
    """Return transparent educational notes, with status-derived recommendations."""
    result = []
    for name, info in PROTECTION_GUIDE.items():
        status = str(protections.get(name, 'Unknown'))
        if name == 'RELRO':
            needs_attention = status in ('Partial', 'No RELRO')
        elif name in ('Stack Canary', 'FORTIFY'):
            needs_attention = status == 'Not detected'
        else:
            needs_attention = status == 'Disabled'
        result.append({
            'name': name, 'status': status, 'what': info['what'],
            'limits': info['limits'], 'verify': info['verify'],
            'flags': info['flags'], 'advice': info['advice'],
            'recommendation': ('Review build configuration' if needs_attention else
                               'Inspect manually' if status == 'Unknown' else 'No change inferred from this indicator'),
            'needs_attention': needs_attention,
        })
    return result


def build_hardening_suggestion(guidance):
    """Educational compiler/linker flags; not an automatically runnable build command."""
    return [entry['flags'] for entry in guidance if entry['needs_attention']]
