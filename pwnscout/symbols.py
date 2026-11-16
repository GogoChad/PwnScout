"""Symbol and relocation extraction."""
def inspect_symbols(elf):
    imports, exports, all_symbols = [], [], []
    dynsym = elf.get_section_by_name(".dynsym")
    symtab = elf.get_section_by_name(".symtab")
    for section in (dynsym, symtab):
        if not section:
            continue
        for sym in section.iter_symbols():
            name = sym.name
            if not name:
                continue
            item = {"name": name, "value": hex(int(sym["st_value"])),
                    "size": int(sym["st_size"]), "type": str(sym["st_info"]["type"])}
            all_symbols.append(item)
            if sym["st_shndx"] == "SHN_UNDEF":
                imports.append(name)
            elif section.name == ".dynsym":
                exports.append(item)

    relocations = []
    for section in elf.iter_sections():
        if not hasattr(section, "iter_relocations"):
            continue
        for rel in section.iter_relocations():
            sym_name = ""
            symtab_idx = section["sh_link"]
            linked = elf.get_section(symtab_idx)
            if linked and rel.entry.r_info_sym:
                sym_name = linked.get_symbol(rel.entry.r_info_sym).name
            relocations.append({
                "section": section.name,
                "offset": hex(int(rel.entry.r_offset)),
                "symbol": sym_name or "(none)",
                "type": str(rel.entry.r_info_type),
            })
    return {
        "imports": sorted(set(imports)),
        "exports": exports[:500],
        "all": all_symbols[:1000],
        "relocations": relocations[:1000],
    }
