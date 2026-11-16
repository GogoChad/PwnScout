"""Report serialization."""
import json
from pathlib import Path


def export_json(report, destination):
    Path(destination).write_text(json.dumps(report, indent=2), encoding="utf-8")


def export_txt(report, destination):
    m = report["metadata"]
    lines = ["PwnScout static analysis report", "=" * 32,
             f"File: {m['file']}", f"Architecture: {m['architecture']}",
             f"Type: {m['type']}", f"Entry: {m['entry']}", "",
             "PROTECTIONS", "-" * 32]
    lines.extend(f"{k}: {v}" for k, v in report["protections"].items())
    lines += ["", "POTENTIALLY RISKY IMPORTS", "-" * 32]
    if report["vulnerabilities"]:
        lines.extend(f"{x['severity']}: {x['function']} — {x['reason']}" for x in report["vulnerabilities"])
    else:
        lines.append("No known risky imports detected.")
    lines += ["", "ROP GADGETS", "-" * 32, report["gadgets"]["message"]]
    lines.extend(report["gadgets"]["items"])
    Path(destination).write_text("\n".join(lines) + "\n", encoding="utf-8")
