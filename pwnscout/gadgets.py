"""Optional ROPgadget integration; gracefully degrades if unavailable."""
import shutil
import subprocess


def find_gadgets(path, limit=80):
    binary = shutil.which("ROPgadget")
    if not binary:
        return {"available": False, "items": [], "message": "ROPgadget not found on PATH"}
    try:
        proc = subprocess.run(
            [binary, "--binary", str(path), "--only", "ret|pop|syscall|int", "--depth", "5"],
            capture_output=True, text=True, timeout=45, check=False
        )
        lines = [line.strip() for line in proc.stdout.splitlines()
                 if " : " in line and not line.startswith("Unique gadgets")]
        return {"available": True, "items": lines[:limit],
                "message": f"ROPgadget exit code: {proc.returncode}"}
    except subprocess.TimeoutExpired:
        return {"available": True, "items": [], "message": "ROPgadget timed out after 45 seconds"}
    except OSError as exc:
        return {"available": False, "items": [], "message": str(exc)}
