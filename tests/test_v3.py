"""V3 regression tests; pure functions and serializers need no ELF dependencies."""
import json
from pwnscout.hardening import explain_protections, build_hardening_suggestion
from pwnscout.comparison import compare_reports
from pwnscout.reporter import export_json, export_txt, export_html


def report(name, pie, imports, deps, risky=()):
    return {
        'metadata': {'name': name, 'file': '/tmp/' + name, 'sha256': 'a' * 64,
                     'architecture': 'x64', 'type': 'ET_EXEC', 'entry': '0x1', 'size_bytes': 10},
        'protections': {'NX': 'Enabled', 'PIE': pie, 'RELRO': 'Partial',
                        'Stack Canary': 'Not detected', 'FORTIFY': 'Not detected'},
        'symbols': {'imports': imports},
        'details': {'dependencies': deps, 'sections': [], 'segments': []},
        'vulnerabilities': [{'function': name} for name in risky],
        'gadgets': {'message': 'not installed', 'items': []},
        'functions': [], 'security_findings': [],
    }


def test_hardening_guidance_is_status_aware():
    g = explain_protections({'NX': 'Unknown', 'PIE': 'Disabled', 'RELRO': 'Partial',
                             'Stack Canary': 'Not detected', 'FORTIFY': 'Enabled'})
    by_name = {x['name']: x for x in g}
    assert by_name['NX']['recommendation'] == 'Inspect manually'
    assert by_name['PIE']['needs_attention']
    assert by_name['RELRO']['needs_attention']
    assert not by_name['FORTIFY']['needs_attention']
    flags = build_hardening_suggestion(g)
    assert '-fPIE -pie' in flags
    assert '-Wl,-z,relro,-z,now' in flags
    assert '-O2 -D_FORTIFY_SOURCE=2' not in flags


def test_comparison_differences_are_sorted_and_symmetric():
    left = report('one', 'Disabled', ['gets', 'puts'], ['libc.so.6'], ('gets',))
    right = report('two', 'Enabled', ['puts', 'printf'], ['libc.so.6', 'libm.so.6'])
    diff = compare_reports(left, right)
    assert diff['changed_protections'] == 1
    assert diff['imports'] == {'only_left': ['gets'], 'only_right': ['printf']}
    assert diff['risky_imports'] == {'only_left': ['gets'], 'only_right': []}
    assert diff['dependencies']['only_right'] == ['libm.so.6']
    reverse = compare_reports(right, left)
    assert reverse['imports']['only_left'] == diff['imports']['only_right']
    assert reverse['imports']['only_right'] == diff['imports']['only_left']


def test_comparison_and_guidance_export_all_formats(tmp_path):
    left = report('<img src=x onerror=alert(1)>', 'Disabled', ['gets'], ['libc.so.6'])
    right = report('other', 'Enabled', ['puts'], ['libm.so.6'])
    left['comparison'] = compare_reports(left, right)
    left['protection_guide'] = explain_protections(left['protections'])
    target = tmp_path / 'report'
    export_json(left, target.with_suffix('.json'))
    export_txt(left, target.with_suffix('.txt'))
    export_html(left, target.with_suffix('.html'))
    assert json.loads(target.with_suffix('.json').read_text())['comparison']['changed_protections'] == 1
    assert 'ELF COMPARISON' in target.with_suffix('.txt').read_text()
    page = target.with_suffix('.html').read_text()
    assert 'ELF comparison' in page and 'Mitigation guide' in page
    assert '&lt;img src=x onerror=alert(1)&gt;' in page
    assert '<img src=x onerror=alert(1)>' not in page


def test_compare_does_not_mutate_source_reports():
    left = report('a', 'Disabled', ['x'], [])
    right = report('b', 'Enabled', [], [])
    compare_reports(left, right)
    assert 'comparison' not in left and 'comparison' not in right


def test_comparison_warns_about_incompatible_elf_metadata():
    left = report('a', 'Disabled', [], [])
    right = report('b', 'Enabled', [], [])
    right['metadata']['architecture'] = 'AArch64'
    right['metadata']['type'] = 'ET_DYN'
    warnings = compare_reports(left, right)['warnings']
    assert any('architectures' in warning for warning in warnings)
    assert any('ELF types' in warning for warning in warnings)
    assert any('SHA-256' in warning for warning in warnings)

def test_comparison_equal_metadata_has_no_warnings_when_hashes_differ():
    left = report('a', 'Disabled', [], [])
    right = report('b', 'Enabled', [], [])
    right['metadata']['sha256'] = 'b' * 64
    assert compare_reports(left, right)['warnings'] == []
