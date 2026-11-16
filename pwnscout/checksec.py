"""Best-effort checksec-style inspection using ELF headers and dynamic symbols."""
def inspect_protections(elf):
    has_nx = None
    has_relro = False
    bind_now = False
    for segment in elf.iter_segments():
        if segment["p_type"] == "PT_GNU_STACK":
            has_nx = not bool(int(segment["p_flags"]) & 1)  # PF_X
        if segment["p_type"] == "PT_GNU_RELRO":
            has_relro = True

    dynamic = elf.get_section_by_name(".dynamic")
    if dynamic:
        for tag in dynamic.iter_tags():
            if tag.entry.d_tag == "DT_BIND_NOW":
                bind_now = True
            elif tag.entry.d_tag == "DT_FLAGS":
                bind_now = bind_now or bool(int(tag.entry.d_val) & 8)  # DF_BIND_NOW
            elif tag.entry.d_tag == "DT_FLAGS_1":
                bind_now = bind_now or bool(int(tag.entry.d_val) & 1)  # DF_1_NOW

    imports = set()
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym:
        imports = {sym.name for sym in dynsym.iter_symbols() if sym.name}

    is_pie = str(elf.header["e_type"]) == "ET_DYN"
    return {
        "NX": "Enabled" if has_nx is True else ("Disabled" if has_nx is False else "Unknown"),
        "PIE": "Enabled" if is_pie else "Disabled",
        "RELRO": "Full" if has_relro and bind_now else ("Partial" if has_relro else "No RELRO"),
        "Stack Canary": "Enabled" if "__stack_chk_fail" in imports else "Not detected",
        "FORTIFY": "Enabled" if any(x.endswith("_chk") for x in imports) else "Not detected",
    }
