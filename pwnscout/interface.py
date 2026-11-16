"""Compact purple Textual UI. All inspection remains static."""
from pathlib import Path
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer, Static, DataTable, TabbedContent, TabPane, Input
from .reporter import export_json, export_txt, export_html
from .functions import disassemble_function


class PwnScoutApp(App):
    TITLE = 'PwnScout'
    SUB_TITLE = 'ELF inspection'
    CSS = '''
    Screen { background: #110f1b; color: #e8e4f2; }
    Header { background: #241b3b; color: #e6ddff; }
    Footer { background: #241b3b; color: #c5b6ed; }
    #hero { height: 3; background: #1d1730; padding: 1 2; color: #d6c7ff; text-style: bold; }
    #meta { height: 3; background: #191626; padding: 0 2; color: #d0c8e4; }
    #filter { margin: 0 1; background: #241d36; border: tall #49346c; height: 3; }
    TabbedContent { background: #110f1b; }
    Tabs { background: #191427; }
    Tab { color: #b5abc7; }
    Tab.-active { color: #e9ddff; background: #523586; }
    Underline { color: #a78bfa; }
    TabPane { padding: 0 1; background: #110f1b; }
    .section { height: 2; padding: 0 1; color: #c4affc; text-style: bold; }
    .hint { height: 2; padding: 0 1; color: #ada0c6; }
    .summary { height: 4; background: #221b36; border: solid #43315e; padding: 1 2; margin-bottom: 1; }
    DataTable { background: #171423; height: 1fr; border: solid #302541; }
    DataTable > .datatable--header { background: #261d39; color: #dbccff; }
    DataTable:focus { border: solid #9573dc; }
    #security_view, #symbols_view, #sections_view, #overview_view, #explorer_view { height: 1fr; }
    #protection_table { height: 9; }
    #security_table { height: 1fr; }
    #risk_table { height: 8; }
    #function_table { width: 40%; height: 1fr; }
    #function_preview { width: 60%; height: 1fr; }
    #selected_function { height: 2; color: #d2beff; }
    #dep_table { height: 9; }
    #segment_table { height: 12; }
    #import_table { height: 45%; }
    #reloc_table { height: 1fr; }
    #rop_status { height: 2; color: #bba9df; }
    #status { dock: bottom; height: 1; background: #1c1830; padding: 0 1; color: #9d90bb; }
    '''
    BINDINGS = [
        ('q', 'quit', 'Quit'), ('slash', 'focus_filter', 'Search'),
        ('j', 'export_json', 'JSON'), ('t', 'export_txt', 'TXT'),
        ('h', 'export_html', 'HTML'), ('r', 'refresh', 'Reload'),
    ]

    def __init__(self, report):
        super().__init__()
        self.report = report
        self.query_text = ''
        self.selected_function = None
        self.function_by_row = {}
        self.preview = report['disassembly']

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static('  PWNSCOUT   /   STATIC ELF INSPECTION', id='hero')
        yield Static('', id='meta')
        yield Input(placeholder='Filter current findings, imports, functions, sections, gadgets...  ( / to focus )', id='filter')
        with TabbedContent(initial='overview'):
            with TabPane('Overview', id='overview'):
                yield Static('', id='summary', classes='summary')
                yield Static('Protections', classes='section')
                yield DataTable(id='protection_table')
                yield Static('Risky imports · heuristic', classes='section')
                yield DataTable(id='risk_table')
            with TabPane('Security', id='security'):
                yield Static('Security observations · not proof of exploitability', classes='hint')
                yield DataTable(id='security_table')
            with TabPane('Functions', id='functions'):
                yield Static('Select a named function (Enter / click). Stripped binaries may lack function symbols.', classes='hint')
                yield Static('Entry-point preview until a function is selected', id='selected_function')
                with Horizontal(id='explorer_view'):
                    yield DataTable(id='function_table')
                    yield DataTable(id='function_preview')
            with TabPane('Sections / deps', id='sections'):
                yield Static('Dynamic dependencies', classes='section')
                yield DataTable(id='dep_table')
                yield Static('Program segments', classes='section')
                yield DataTable(id='segment_table')
                yield Static('ELF sections', classes='section')
                yield DataTable(id='section_table')
            with TabPane('Symbols / PLT-GOT', id='symbols'):
                yield Static('Imported symbols', classes='section')
                yield DataTable(id='import_table')
                yield Static('Relocation entries', classes='section')
                yield DataTable(id='reloc_table')
            with TabPane('Entry disasm', id='disasm'):
                yield Static('Entry-point preview · bounded static disassembly', classes='hint')
                yield DataTable(id='disasm_table')
            with TabPane('ROP gadgets', id='rop'):
                yield Static('', id='rop_status')
                yield DataTable(id='gadget_table')
        yield Static(' / Search     j JSON     t TXT     h HTML     r Reload     q Quit', id='status')
        yield Footer()

    def on_mount(self):
        m = self.report['metadata']
        self.query_one('#meta', Static).update(
            f"[b]{m['name']}[/b]    {m['class']} / {m['architecture']}    {m['type']}    Entry {m['entry']}\n{m['file']}")
        s = self.report['summary']
        self.query_one('#summary', Static).update(
            f"[b]SECURITY[/b]  {s['security_findings']} observations      "
            f"[b]IMPORTS[/b]  {len(self.report['symbols']['imports'])} ({s['risky_imports']} flagged)      "
            f"[b]FUNCTIONS[/b]  {s['functions']}      [b]LIBRARIES[/b]  {s['dependencies']}")
        columns = {
            'protection_table': ('Protection', 'Result'),
            'risk_table': ('Severity', 'Function', 'Reason', 'Suggestion'),
            'security_table': ('Severity', 'Finding', 'Explanation'),
            'function_table': ('Address', 'Function', 'Size'),
            'function_preview': ('Address', 'Bytes', 'Instruction'),
            'dep_table': ('Dependency / loader path',),
            'segment_table': ('Type', 'Address', 'File bytes', 'Memory bytes', 'Perms'),
            'section_table': ('Name', 'Type', 'Address', 'Size', 'Flags'),
            'import_table': ('Imported symbol',),
            'reloc_table': ('Section', 'Offset', 'Symbol', 'Relocation type'),
            'disasm_table': ('Address', 'Bytes', 'Instruction'),
            'gadget_table': ('Gadget',),
        }
        for ident, labels in columns.items():
            table = self.query_one('#' + ident, DataTable)
            table.add_columns(*labels)
            table.cursor_type = 'row'
            table.zebra_stripes = True
        self.query_one('#rop_status', Static).update(self.report['gadgets']['message'])
        self.populate_tables()

    def _matches(self, *parts):
        return not self.query_text or self.query_text in ' '.join(map(str, parts)).casefold()

    def _fill(self, ident, rows):
        table = self.query_one('#' + ident, DataTable)
        table.clear()
        added = 0
        for row in rows:
            if self._matches(*row):
                table.add_row(*(str(x) for x in row))
                added += 1
        return added

    def populate_tables(self):
        r = self.report
        self._fill('protection_table', [(k, v) for k, v in r['protections'].items()])
        self._fill('risk_table', [(v['severity'], v['function'], v['reason'], v['suggestion']) for v in r['vulnerabilities']])
        self._fill('security_table', [(v['severity'], v['finding'], v['explanation']) for v in r['security_findings']])
        table = self.query_one('#function_table', DataTable)
        table.clear()
        self.function_by_row = {}
        for function in r['functions']:
            row = (function['address'], function['name'], function['size'])
            if self._matches(*row):
                key = table.add_row(*(str(x) for x in row))
                self.function_by_row[key.value] = function
        self._fill('function_preview', [(v['address'], v['bytes'], v['instruction']) for v in self.preview])
        detail = r['details']
        deps = detail['dependencies'] + [f'RPATH: {x}' for x in detail['rpath']] + [f'RUNPATH: {x}' for x in detail['runpath']]
        self._fill('dep_table', [(d,) for d in deps])
        self._fill('segment_table', [(v['type'], v['vaddr'], v['filesz'], v['memsz'], v['permissions']) for v in detail['segments']])
        self._fill('section_table', [(v['name'], v['type'], v['address'], v['size'], v['flags']) for v in detail['sections']])
        self._fill('import_table', [(x,) for x in r['symbols']['imports']])
        self._fill('reloc_table', [(v['section'], v['offset'], v['symbol'], v['type']) for v in r['symbols']['relocations']])
        self._fill('disasm_table', [(v['address'], v['bytes'], v['instruction']) for v in r['disassembly']])
        self._fill('gadget_table', [(x,) for x in r['gadgets']['items']])

    def on_input_changed(self, event: Input.Changed):
        if event.input.id == 'filter':
            self.query_text = event.value.strip().casefold()
            self.populate_tables()

    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        if event.data_table.id != 'function_table':
            return
        function = self.function_by_row.get(event.row_key.value)
        if function is None:
            return
        self.selected_function = function
        try:
            from elftools.elf.elffile import ELFFile
            with open(self.report['metadata']['file'], 'rb') as stream:
                elf = ELFFile(stream)
                self.preview = disassemble_function(elf, function['address'], function['size'])
        except (OSError, ValueError) as exc:
            self.notify(f'Unable to load function: {exc}', severity='error')
            return
        self.query_one('#selected_function', Static).update(
            f"[b]{function['name']}[/b] @ {function['address']} · {function['size']} bytes (0 = unknown, bounded preview)")
        self._fill('function_preview', [(v['address'], v['bytes'], v['instruction']) for v in self.preview])

    def action_focus_filter(self):
        self.query_one('#filter', Input).focus()

    def _export(self, ext, exporter):
        target = Path('reports') / f"{Path(self.report['metadata']['name']).stem}.pwnscout.{ext}"
        try:
            exporter(self.report, target)
        except OSError as exc:
            self.notify(f'Export failed: {exc}', severity='error')
        else:
            self.notify(f'Saved {target}')

    def action_export_json(self):
        self._export('json', export_json)

    def action_export_txt(self):
        self._export('txt', export_txt)

    def action_export_html(self):
        self._export('html', export_html)

    def action_refresh(self):
        self.notify('Snapshot analysis. Relaunch to re-scan a changed file.')
