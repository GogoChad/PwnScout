"""Pure unit tests for ELF type classification (no ELF dependencies needed)."""
from pwnscout.checksec import inspect_protections


class FakeELF:
    def __init__(self, elf_type, segments=()):
        self.header = {'e_type': elf_type}
        self._segments = [{'p_type': name, 'p_flags': flags} for name, flags in segments]

    def iter_segments(self):
        return iter(self._segments)

    def get_section_by_name(self, name):
        return None


def test_pie_executable_with_interpreter():
    elf = FakeELF('ET_DYN', [('PT_INTERP', 4), ('PT_GNU_STACK', 6)])
    findings = inspect_protections(elf)
    assert findings['PIE'] == 'Enabled'
    assert findings['NX'] == 'Enabled'


def test_shared_library_is_not_automatically_pie():
    assert inspect_protections(FakeELF('ET_DYN'))['PIE'] == 'Unknown'


def test_non_pie_executable():
    assert inspect_protections(FakeELF('ET_EXEC'))['PIE'] == 'Disabled'


def test_other_elf_types_are_unknown():
    assert inspect_protections(FakeELF('ET_REL'))['PIE'] == 'Unknown'
