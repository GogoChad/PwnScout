"""Report serialization, including escaped, self-contained HTML."""
import html
import json
from pathlib import Path


def _write(destination, data):
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding='utf-8')


def export_json(report, destination):
    _write(destination, json.dumps(report, indent=2, ensure_ascii=False))


def export_txt(report, destination):
    m = report['metadata']
    lines = ['PwnScout static analysis report', '=' * 32,
             f"File: {m['file']}", f"Architecture: {m['architecture']}",
             f"Type: {m['type']}", f"Entry: {m['entry']}", '',
             'PROTECTIONS', '-' * 32]
    lines.extend(f'{k}: {v}' for k, v in report['protections'].items())
    lines += ['', 'POTENTIALLY RISKY IMPORTS', '-' * 32]
    if report['vulnerabilities']:
        lines.extend(f"{x['severity']}: {x['function']} — {x['reason']}" for x in report['vulnerabilities'])
    else:
        lines.append('No known risky imports detected.')
    lines += ['', 'ROP GADGETS', '-' * 32, report['gadgets']['message']]
    lines.extend(report['gadgets']['items'])
    if 'security_findings' in report:
        lines += ['', 'SECURITY OBSERVATIONS', '-' * 32]
        lines.extend(f"{x['severity']}: {x['finding']} — {x['explanation']}" for x in report['security_findings'])
    if 'details' in report:
        lines += ['', 'DEPENDENCIES', '-' * 32, *report['details']['dependencies']]
    if 'protection_guide' in report:
        lines += ['', 'PROTECTIONS EXPLAINED / HARDENING', '-' * 32]
        for x in report['protection_guide']:
            lines.extend((f"{x['name']} [{x['status']}]", f"  Purpose: {x['what']}",
                          f"  Limits: {x['limits']}", f"  Recommendation: {x['recommendation']}",
                          f"  Compiler/linker options: {x['flags']}", f"  Verify: {x['verify']}", ''))
    if 'comparison' in report:
        c = report['comparison']
        lines += ['', 'ELF COMPARISON', '-' * 32, f"Left: {c['left']['path']}",
                  f"Right: {c['right']['path']}", c['note']]
        lines.extend(f"{p['name']}: {p['left']} -> {p['right']}" for p in c['protections'])
        for category in ('imports', 'risky_imports', 'dependencies'):
            for side in ('only_left', 'only_right'):
                lines.append(f"{category} / {side}: {', '.join(c[category][side]) or '(none)'}")
    _write(destination, '\n'.join(lines) + '\n')


def export_html(report, destination):
    """Local static report: escape every value derived from the inspected ELF."""
    esc = lambda x: html.escape(str(x), quote=True)
    def table(rows, keys):
        head = ''.join(f'<th>{esc(label)}</th>' for _, label in keys)
        body = ''.join('<tr>' + ''.join(f'<td>{esc(row.get(key, ""))}</td>' for key, _ in keys) + '</tr>' for row in rows)
        return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'
    blocks = []
    def section(title, value):
        blocks.append(f'<section><h2>{esc(title)}</h2>{value}</section>')
    section('Protections', table([{'key': k, 'value': v} for k, v in report['protections'].items()], [('key', 'Protection'), ('value', 'Result')]))
    section('Security observations', table(report.get('security_findings', []), [('severity', 'Severity'), ('finding', 'Finding'), ('explanation', 'Explanation')]))
    section('Risky imports (heuristic)', table(report['vulnerabilities'], [('severity', 'Severity'), ('function', 'Function'), ('reason', 'Reason'), ('suggestion', 'Suggestion')]))
    section('Dependencies', table([{'name': x} for x in report.get('details', {}).get('dependencies', [])], [('name', 'Library')]))
    section('Sections', table(report.get('details', {}).get('sections', []), [('name', 'Name'), ('type', 'Type'), ('address', 'Address'), ('size', 'Size'), ('flags', 'Flags')]))
    section('Segments', table(report.get('details', {}).get('segments', []), [('type', 'Type'), ('vaddr', 'Virtual address'), ('permissions', 'Permissions')]))
    section('Functions (symbol-derived)', table(report.get('functions', []), [('name', 'Name'), ('address', 'Address'), ('size', 'Size')]))
    if report.get('protection_guide'):
        section('Mitigation guide and GCC suggestions', table(report['protection_guide'],
                [('name', 'Protection'), ('status', 'Status'), ('what', 'Purpose'),
                 ('limits', 'Limitations'), ('flags', 'Suggested options'),
                 ('recommendation', 'Action'), ('verify', 'Verify')]))
    if report.get('comparison'):
        c = report['comparison']
        section('ELF comparison', '<p>' + esc(c['left']['path']) + ' vs ' + esc(c['right']['path']) +
                '</p><p>' + esc(c['note']) + '</p>' +
                table(c['protections'], [('name', 'Protection'), ('left', 'Left'), ('right', 'Right'), ('changed', 'Changed')]))
        differences = []
        for category in ('imports', 'risky_imports', 'dependencies'):
            for side in ('only_left', 'only_right'):
                differences.extend({'category': category, 'side': side, 'value': name}
                                   for name in c[category][side])
        section('Comparison differences', table(differences,
                [('category', 'Category'), ('side', 'Side'), ('value', 'Only on that side')]))
    section('Metadata', table([{'key': k, 'value': v} for k, v in report['metadata'].items()], [('key', 'Field'), ('value', 'Value')]))
    style = '''body{margin:0;background:#11101b;color:#e8e4f2;font:14px system-ui,sans-serif}main{max-width:1120px;margin:auto;padding:32px}header{background:#211b36;border:1px solid #443365;border-radius:14px;padding:22px}h1{margin:0;color:#dacaff}h2{font-size:17px;color:#c7b4fb}p{color:#a99ebc}section{background:#1a1727;border:1px solid #363049;border-radius:12px;padding:16px;margin:16px 0}.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;text-align:left}th,td{padding:9px 10px;border-bottom:1px solid #343044;vertical-align:top;overflow-wrap:anywhere}th{color:#bca8f3;font-size:12px}td{color:#e0dae8}code{color:#d5c5ff}'''
    m = report['metadata']
    document = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1">'
                f'<title>PwnScout — {esc(m["name"])}</title><style>{style}</style></head><body><main>'
                f'<header><h1>PwnScout / {esc(m["name"])}</h1><p>{esc(m["architecture"])} · {esc(m["type"])} · {esc(m["entry"])}</p>'
                '<p>Static heuristics only. Findings do not establish exploitability.</p></header>'
                + ''.join(blocks) + '</main></body></html>')
    _write(destination, document)
