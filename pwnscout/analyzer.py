"""ELF analysis orchestration. Analysis is static: target files are never executed."""
from pathlib import Path
from .checksec import inspect_protections
from .disassembler import disassemble_entry
from .gadgets import find_gadgets
from .symbols import inspect_symbols
from .vulnerabilities import find_risky_imports


class BinaryAnalyzer:
    def __init__(self, path):
        self.path = Path(path)

    def analyze(self):
        if not self.path.is_file():
            raise FileNotFoundError(self.path)
        with self.path.open("rb") as stream:
            magic = stream.read(4)
        if magic != b"\x7fELF":
            raise ValueError("Input is not an ELF binary")

        from elftools.elf.elffile import ELFFile
        with self.path.open("rb") as stream:
            elf = ELFFile(stream)
            metadata = {
                "file": str(self.path.resolve()),
                "name": self.path.name,
                "class": f"ELF{elf.elfclass}",
                "endianness": "little" if elf.little_endian else "big",
                "architecture": elf.get_machine_arch(),
                "type": str(elf.header["e_type"]),
                "entry": hex(int(elf.header["e_entry"])),
                "bits": elf.elfclass,
            }
            protections = inspect_protections(elf)
            symbols = inspect_symbols(elf)
            disassembly = disassemble_entry(elf, max_instructions=100)
        return {
            "metadata": metadata,
            "protections": protections,
            "symbols": symbols,
            "vulnerabilities": find_risky_imports(symbols["imports"]),
            "gadgets": find_gadgets(self.path),
            "disassembly": disassembly,
        }
