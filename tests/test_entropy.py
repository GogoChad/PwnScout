"""Entropy calculations and safe handling of sections without stored bytes."""
import math
import pytest
from pwnscout.entropy import shannon_entropy, inspect_section_entropy


def test_known_byte_distributions():
    assert shannon_entropy(b'') == 0
    assert shannon_entropy(b'A' * 1000) == 0
    assert shannon_entropy(b'AB' * 100) == pytest.approx(1)
    assert shannon_entropy(bytes(range(256))) == pytest.approx(8)
    assert math.isfinite(shannon_entropy(b'hello world'))


class FakeSection:
    def __init__(self, name, typ, size, offset):
        self.name = name
        self.header = {'sh_type': typ, 'sh_size': size, 'sh_offset': offset}

class FakeELF:
    def __init__(self, stream):
        self.stream = stream

    def iter_sections(self):
        yield FakeSection('.text', 'SHT_PROGBITS', 16, 0)
        yield FakeSection('.bss', 'SHT_NOBITS', 1024 * 1024 * 256, 0)
        yield FakeSection('.empty', 'SHT_PROGBITS', 0, 16)


def test_entropy_sampling_and_bss(tmp_path):
    path = tmp_path / 'test.bin'
    path.write_bytes(bytes(range(16)))
    with path.open('rb') as stream:
        stream.seek(6)
        result = inspect_section_entropy(FakeELF(stream), max_sample=8)
        assert stream.tell() == 6
    assert result[0]['entropy'] == pytest.approx(3)
    assert result[0]['status'] == 'Sampled'
    assert result[0]['sampled_bytes'] == 8
    assert result[1]['entropy'] is None
    assert result[1]['status'].startswith('No file bytes')
    assert result[2]['status'] == 'Empty'


def test_entropy_is_exported_to_html_and_txt(tmp_path):
    from pwnscout.reporter import export_html, export_txt
    report = {
        'metadata': {'name': 'example', 'file': '/tmp/example', 'architecture': 'x64', 'type': 'ET_EXEC', 'entry': '0x0'},
        'protections': {}, 'vulnerabilities': [],
        'gadgets': {'message': 'unavailable', 'items': []},
        'entropy': [{'name': '<.text>', 'entropy': 7.123, 'sampled_bytes': 16,
                     'section_bytes': 16, 'status': 'Complete'}],
    }
    export_html(report, tmp_path / 'result.html')
    export_txt(report, tmp_path / 'result.txt')
    html = (tmp_path / 'result.html').read_text()
    txt = (tmp_path / 'result.txt').read_text()
    assert '7.123' in html and '&lt;.text&gt;' in html
    assert '7.123' in txt and 'SECTION ENTROPY' in txt
