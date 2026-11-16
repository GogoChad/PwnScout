"""Small entry-point disassembly preview using Capstone."""
def disassemble_entry(elf, max_instructions=100):
    try:
        from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_ARM64
        from capstone import CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    except ImportError:
        return [{"address": "-", "bytes": "-", "instruction": "Capstone is not installed"}]

    machine = elf.get_machine_arch().lower()
    bits = elf.elfclass
    if "x86" in machine or machine in {"x64", "i386"}:
        arch, mode = CS_ARCH_X86, CS_MODE_64 if bits == 64 else CS_MODE_32
    elif "aarch64" in machine or "arm64" in machine:
        arch, mode = CS_ARCH_ARM64, 0
    elif "arm" in machine:
        arch, mode = CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN
    else:
        return [{"address": "-", "bytes": "-", "instruction": f"Unsupported architecture: {machine}"}]

    entry = int(elf.header["e_entry"])
    for section in elf.iter_sections():
        start = int(section["sh_addr"])
        size = int(section["sh_size"])
        if start <= entry < start + size and int(section["sh_flags"]) & 4:
            offset = entry - start
            data = section.data()[offset:offset + 2048]
            md = Cs(arch, mode)
            rows = []
            for ins in md.disasm(data, entry):
                rows.append({
                    "address": hex(ins.address),
                    "bytes": ins.bytes.hex(" "),
                    "instruction": f"{ins.mnemonic} {ins.op_str}".strip(),
                })
                if len(rows) >= max_instructions:
                    break
            return rows
    return [{"address": "-", "bytes": "-", "instruction": "Entry point not found in an executable section"}]
