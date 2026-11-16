import json
from pwnscout.reporter import export_json


def test_json_export(tmp_path):
    target = tmp_path / "report.json"
    export_json({"ok": True}, target)
    assert json.loads(target.read_text()) == {"ok": True}
