"""Optional end-to-end tests. Compile an ELF fixture but never execute it."""
import shutil
import subprocess
from pathlib import Path
import pytest


def test_real_elf_metadata_functions_and_html(tmp_path, monkeypatch):
    pytest.importorskip('elftools')
    pytest.importorskip('capstone')
    if not shutil.which('gcc'):
        pytest.skip('gcc not installed')
    source = Path(__file__).resolve().parents[1] / 'samples' / 'vulnerable.c'
    target = tmp_path / 'demo'
    subprocess.run(['gcc', '-g', '-O0', '-fno-stack-protector', '-no-pie',
                    '-Wno-implicit-function-declaration', '-o', str(target), str(source)],
                   check=True, capture_output=True, timeout=30)
    from pwnscout.analyzer import BinaryAnalyzer
    from pwnscout.reporter import export_html
    from pwnscout.functions import disassemble_function
    from elftools.elf.elffile import ELFFile
    # Prevent invoking optional ROPgadget in this integration test.
    monkeypatch.setattr('pwnscout.analyzer.find_gadgets', lambda p: {'available': False, 'items': [], 'message': 'skipped'})
    report = BinaryAnalyzer(target).analyze()
    assert report['metadata']['sha256'] and len(report['metadata']['sha256']) == 64
    assert report['details']['sections'] and report['details']['segments']
    assert report['details']['dependencies']
    assert any(f['name'] == 'main' for f in report['functions'])
    assert any(f['function'] == 'gets' for f in report['vulnerabilities'])
    function = next(f for f in report['functions'] if f['name'] == 'main')
    with target.open('rb') as fp:
        rows = disassemble_function(ELFFile(fp), function['address'], function['size'])
    assert rows and rows[0]['address'] == function['address']
    export_html(report, tmp_path / 'report.html')
    assert 'Functions (symbol-derived)' in (tmp_path / 'report.html').read_text()
