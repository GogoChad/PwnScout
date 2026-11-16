import json
from pathlib import Path
from pwnscout.reporter import export_html, export_json, export_txt
from pwnscout.elfdetails import inspect_security_details


def test_html_escapes_untrusted_elf_strings(tmp_path):
    report = {'metadata': {'name': '<script>alert(1)</script>', 'architecture': 'x64', 'type': 'ET_EXEC', 'entry': '0x1'},
              'protections': {'NX': 'Enabled'}, 'security_findings': [],
              'vulnerabilities': [{'severity': 'High', 'function': '<img src=x>', 'reason': 'x', 'suggestion': 'fix'}],
              'details': {'dependencies': ['evil&lib.so'], 'sections': [], 'segments': []}, 'functions': []}
    target = tmp_path / 'nested' / 'test.html'
    export_html(report, target)
    page = target.read_text()
    assert '&lt;script&gt;' in page and '<script>alert(1)' not in page
    assert '&lt;img src=x&gt;' in page
    assert 'evil&amp;lib.so' in page
    assert '<!doctype html>' in page


def test_reporters_create_parents(tmp_path):
    report = {'metadata': {'file': '/tmp/x', 'architecture': 'x64', 'type': 'ET_EXEC', 'entry': '0x1'},
              'protections': {}, 'vulnerabilities': [], 'gadgets': {'message': 'not installed', 'items': []}}
    export_json(report, tmp_path / 'a' / 'out.json')
    export_txt(report, tmp_path / 'b' / 'out.txt')
    assert json.loads((tmp_path / 'a' / 'out.json').read_text())['metadata']['type'] == 'ET_EXEC'
    assert 'PROTECTIONS' in (tmp_path / 'b' / 'out.txt').read_text()


def test_wx_and_rpath_findings():
    details = {'rpath': ['/untrusted'], 'runpath': [], 'segments': [{'type': 'PT_LOAD', 'vaddr': '0x1000', 'permissions': 'RWX'}]}
    protections = {'NX': 'Enabled', 'PIE': 'Disabled', 'RELRO': 'Partial', 'Stack Canary': 'Not detected'}
    codes = {x['code'] for x in inspect_security_details(None, details, protections)}
    assert {'RPATH', 'WX_SEGMENT', 'PIE_OFF', 'RELRO_PARTIAL'} <= codes
