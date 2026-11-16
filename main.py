#!/usr/bin/env python3
"""PwnScout command-line entry point."""
import argparse
import sys
from pathlib import Path

from pwnscout.analyzer import BinaryAnalyzer
from pwnscout.interface import PwnScoutApp
from pwnscout.reporter import export_json, export_txt, export_html


def main():
    parser = argparse.ArgumentParser(
        prog="pwnscout",
        description="Interactive static reconnaissance for ELF binaries."
    )
    parser.add_argument("binary", help="Path to the ELF binary to inspect")
    parser.add_argument("--json", dest="json_out", help="Write a JSON report")
    parser.add_argument("--txt", dest="txt_out", help="Write a text report")
    parser.add_argument("--html", dest="html_out", help="Write a standalone HTML report")
    parser.add_argument("--no-tui", action="store_true",
                        help="Print a concise report without launching the TUI")
    args = parser.parse_args()

    path = Path(args.binary).expanduser()
    if not path.is_file():
        parser.error(f"file not found: {path}")

    try:
        report = BinaryAnalyzer(path).analyze()
    except Exception as exc:
        print(f"[!] Analysis failed: {exc}", file=sys.stderr)
        return 2

    if args.json_out:
        export_json(report, args.json_out)
        print(f"[+] JSON report written to {args.json_out}")
    if args.txt_out:
        export_txt(report, args.txt_out)
        print(f"[+] Text report written to {args.txt_out}")

    if args.html_out:
        export_html(report, args.html_out)
        print(f"[+] HTML report written to {args.html_out}")

    if args.no_tui:
        from rich.console import Console
        from rich.table import Table
        console = Console()
        table = Table(title=f"PwnScout — {path.name}")
        table.add_column("Protection")
        table.add_column("Status")
        for key, value in report["protections"].items():
            table.add_row(key, str(value))
        console.print(table)
        console.print(f"Architecture: {report['metadata'].get('architecture', 'unknown')}")
        console.print(f"Imported symbols: {len(report['symbols']['imports'])}")
        console.print(f"Potentially risky imports: {len(report['vulnerabilities'])}")
        return 0

    PwnScoutApp(report).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
