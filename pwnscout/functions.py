"""Symbol-based function discovery and bounded function disassembly."""
from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_ARM64
from capstone import CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_BIG_ENDIAN


def _decoder(elf):
    machine = elf.get_machine_arch().lower()
    if 'x86' in machine or machine in {'x64', 'i386', 'intel 80386'}:
        return Cs(CS_ARCH_X86, CS_MODE_64 if elf.elfclass == 64 else CS_MODE_32)
    if 'aarch64' in machine or 'arm64' in machine:
        return Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN if elf.little_endian else CS_MODE_BIG_ENDIAN)
    if 'arm' in machine:
        return Cs(CS_ARCH_ARM, CS_MODE_ARM | (CS_MODE_LITTLE_ENDIAN if elf.little_endian else CS_MODE_BIG_ENDIAN))
    return None


def discover_functions(elf, limit=1500):
    found = {}
    for name in ('.symtab', '.dynsym'):
        sec = elf.get_section_by_name(name)
        if sec is None:
            continue
        for symbol in sec.iter_symbols():
            if str(symbol['st_info']['type']) != 'STT_FUNC' or symbol['st_shndx'] == 'SHN_UNDEF':
                continue
            address = int(symbol['st_value'])
            if not symbol.name or not address:
                continue
            key = (address, symbol.name)
            found[key] = {'name': symbol.name, 'address': hex(address), 'size': int(symbol['st_size']), 'source': name}
    return sorted(found.values(), key=lambda r: (int(r['address'], 16), r['name']))[:limit]


def disassemble_function(elf, address, size=0, max_instructions=180, max_bytes=4096):
    """Read from executable file-backed section; never execute binary code."""
    decoder = _decoder(elf)
    if decoder is None:
        return [{'address': '-', 'bytes': '-', 'instruction': 'Architecture not supported'}]
    address = int(address, 0) if isinstance(address, str) else int(address)
    for section in elf.iter_sections():
        start, length = int(section['sh_addr']), int(section['sh_size'])
        if not (int(section['sh_flags']) & 4 and start <= address < start + length):
            continue
        offset = address - start
        bounded = min(size if size > 0 else max_bytes, max_bytes, length - offset)
        data = section.data()[offset:offset + bounded]
        rows = []
        for ins in decoder.disasm(data, address):
            rows.append({'address': hex(ins.address), 'bytes': ins.bytes.hex(' '),
                         'instruction': f'{ins.mnemonic} {ins.op_str}'.strip()})
            if len(rows) >= max_instructions:
                break
        return rows or [{'address': '-', 'bytes': '-', 'instruction': 'No instructions decoded'}]
    return [{'address': '-', 'bytes': '-', 'instruction': 'Function address not in executable section'}]
