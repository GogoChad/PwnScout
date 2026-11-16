"""Textual dashboard."""
from textual.app import App, ComposeResult
from textual.containers import Vertical, Horizontal
from textual.widgets import Header, Footer, Static, DataTable, TabbedContent, TabPane


class PwnScoutApp(App):
    TITLE = "PwnScout"
    SUB_TITLE = "ELF static reconnaissance"
    CSS = """
    Screen { background: #0b1020; }
    #banner { height: 3; padding: 1 2; color: #70f0c0; background: #121c30; }
    .section-title { color: #70f0c0; text-style: bold; padding: 1 0; }
    DataTable { height: 1fr; }
    #meta { height: auto; padding: 1 2; background: #121c30; }
    """
    BINDINGS = [("q", "quit", "Quit"), ("r", "refresh", "Refresh")]

    def __init__(self, report):
        super().__init__()
        self.report = report

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(" P W N S C O U T   //   STATIC ELF ANALYSIS", id="banner")
        with TabbedContent(initial="overview"):
            with TabPane("Overview", id="overview"):
                yield Static("", id="meta")
                yield Static("Security protections", classes="section-title")
                yield DataTable(id="protections")
                yield Static("Potentially risky imports", classes="section-title")
                yield DataTable(id="vulns")
            with TabPane("Symbols / PLT-GOT", id="symbols"):
                yield Static("Imported symbols", classes="section-title")
                yield DataTable(id="imports")
                yield Static("Relocations (PLT/GOT-related entries where present)", classes="section-title")
                yield DataTable(id="relocs")
            with TabPane("Disassembly", id="disasm"):
                yield DataTable(id="disasm_table")
            with TabPane("ROP gadgets", id="rop"):
                yield Static("", id="rop_status")
                yield DataTable(id="gadgets")
        yield Footer()

    def action_refresh(self):
        self.notify("This is a static analysis snapshot. Relaunch PwnScout to analyze a changed file.")

    def on_mount(self):
        m = self.report["metadata"]
        self.query_one("#meta", Static).update(
            f"[b]{m['name']}[/b]   {m['class']} / {m['architecture']}   "
            f"Type: {m['type']}   Entry: {m['entry']}\n{m['file']}"
        )
        t = self.query_one("#protections", DataTable)
        t.add_columns("Protection", "Result")
        for key, value in self.report["protections"].items():
            t.add_row(key, value)
        v = self.query_one("#vulns", DataTable)
        v.add_columns("Severity", "Function", "Reason", "Suggestion")
        for item in self.report["vulnerabilities"]:
            v.add_row(item["severity"], item["function"], item["reason"], item["suggestion"])
        if not self.report["vulnerabilities"]:
            v.add_row("—", "None detected", "No matching imported functions", "Review code and call sites")

        it = self.query_one("#imports", DataTable)
        it.add_columns("Imported symbol")
        for name in self.report["symbols"]["imports"]:
            it.add_row(name)
        rt = self.query_one("#relocs", DataTable)
        rt.add_columns("Section", "Offset", "Symbol", "Relocation type")
        for item in self.report["symbols"]["relocations"]:
            rt.add_row(item["section"], item["offset"], item["symbol"], item["type"])

        dt = self.query_one("#disasm_table", DataTable)
        dt.add_columns("Address", "Bytes", "Instruction")
        for item in self.report["disassembly"]:
            dt.add_row(item["address"], item["bytes"], item["instruction"])

        gadgets = self.report["gadgets"]
        self.query_one("#rop_status", Static).update(gadgets["message"])
        gt = self.query_one("#gadgets", DataTable)
        gt.add_columns("Gadget")
        for item in gadgets["items"]:
            gt.add_row(item)
        if not gadgets["items"]:
            gt.add_row("No gadgets returned")
