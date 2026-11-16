"""Static ELF analysis orchestration; target binary is never executed."""
import hashlib
from pathlib import Path
from elftools.elf.elffile import ELFFile
from .checksec import inspect_protections
from .disassembler import disassemble_entry
from .elfdetails import inspect_elf_details, inspect_security_details
from .functions import discover_functions
from .hardening import explain_protections, build_hardening_suggestion
from .gadgets import find_gadgets
from .symbols import inspect_symbols
from .vulnerabilities import find_risky_imports


class BinaryAnalyzer:
    def __init__(self, path):
        self.path = Path(path)

    def analyze(self):
        if not self.path.is_file():
            raise FileNotFoundError(self.path)
        with self.path.open('rb') as stream:
            if stream.read(4) != b'\x7fELF':
                raise ValueError('Input is not an ELF binary')
            stream.seek(0)
            digest = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
            sha256 = digest.hexdigest()
        with self.path.open('rb') as stream:
            elf = ELFFile(stream)
            metadata = {
                'file': str(self.path.resolve()), 'name': self.path.name,
                'class': f'ELF{elf.elfclass}', 'endianness': 'little' if elf.little_endian else 'big',
                'architecture': elf.get_machine_arch(), 'type': str(elf.header['e_type']),
                'entry': hex(int(elf.header['e_entry'])), 'bits': elf.elfclass,
                'size_bytes': self.path.stat().st_size, 'sha256': sha256,
            }
            protections = inspect_protections(elf)
            symbols = inspect_symbols(elf)
            details = inspect_elf_details(elf)
            functions = discover_functions(elf)
            disassembly = disassemble_entry(elf, max_instructions=100)
            security_details = inspect_security_details(elf, details, protections)
            protection_guide = explain_protections(protections)
        vulnerabilities = find_risky_imports(symbols['imports'])
        return {
            'metadata': metadata, 'protections': protections, 'symbols': symbols,
            'vulnerabilities': vulnerabilities, 'gadgets': find_gadgets(self.path),
            'disassembly': disassembly, 'details': details, 'functions': functions,
            'security_findings': security_details,
            'protection_guide': protection_guide,
            'hardening_flags': build_hardening_suggestion(protection_guide),
            'summary': {'functions': len(functions), 'dependencies': len(details['dependencies']),
                        'security_findings': len(security_details), 'risky_imports': len(vulnerabilities)},
        }
