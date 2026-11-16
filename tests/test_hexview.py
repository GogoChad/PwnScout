"""Regression tests for the bounded file hex reader."""
import pytest
from pwnscout.hexview import read_hex_page


def test_hex_ascii_and_paging(tmp_path):
    path = tmp_path / 'raw.bin'
    path.write_bytes(b'ELF\x00abc\xff' + bytes(range(32)))
    page = read_hex_page(path, offset=0, rows=2, width=8)
    assert page['rows'][0] == {'offset': '0x00000000', 'hex': '45 4C 46 00 61 62 63 FF', 'ascii': 'ELF.abc.'}
    assert page['next_offset'] == 16
    assert read_hex_page(path, offset=16, rows=1, width=8)['rows'][0]['offset'] == '0x00000010'


def test_end_of_file_and_empty_file(tmp_path):
    path = tmp_path / 'empty'
    path.write_bytes(b'')
    assert read_hex_page(path)['rows'] == []
    path.write_bytes(b'hello')
    assert read_hex_page(path, 999)['rows'] == []
    assert read_hex_page(path, 3)['rows'][0]['ascii'] == 'lo'


@pytest.mark.parametrize('offset', [-1, 1.2, '3'])
def test_invalid_offsets(tmp_path, offset):
    path = tmp_path / 'file'
    path.write_bytes(b'hello')
    with pytest.raises(ValueError):
        read_hex_page(path, offset)


def test_bounded_read(tmp_path):
    path = tmp_path / 'long'
    path.write_bytes(b'A' * 10000)
    page = read_hex_page(path, rows=4)
    assert len(page['rows']) == 4
    assert page['next_offset'] == 64
