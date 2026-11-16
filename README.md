# PwnScout 1.0

PwnScout is an interactive, static reconnaissance tool for Linux ELF binaries. It presents security metadata, imported symbols, relocation entries, heuristic risky-import findings, an entry-point disassembly preview, and optional ROP gadget results.

> **Safety and scope:** PwnScout does not execute the target binary. The included `samples/vulnerable.c` is intentionally unsafe and exists only as a local training fixture. Do not deploy it or expose it to a network. Findings are heuristics, not proof of an exploitable vulnerability.

## Features

- Textual terminal UI with Overview, Symbols/PLT-GOT, Disassembly, and ROP tabs.
- ELF class, architecture, endianness, type, entry point, and file path.
- Best-effort NX, PIE, RELRO, stack-canary, and FORTIFY checks.
- Imports, dynamic exports, and relocation records (including GOT/PLT-related relocations when present).
- Heuristic identification of selected risky imported functions.
- Capstone entry-point disassembly preview for x86, x86-64, ARM, and AArch64.
- Optional ROPgadget integration, with a graceful fallback if it is absent.
- JSON and TXT report export.
- Pytest unit tests.

## Requirements

- Linux (Kali, Ubuntu, Debian, Arch or similar)
- Python 3.10+
- `gcc` or `clang` only if you want to compile the sample
- Optional: `ROPgadget`

## Installation

### Debian / Ubuntu / Kali

Some distributions mark their system Python as externally managed. Use a virtual environment:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip build-essential
cd PwnScout
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements-optional.txt
```

### Arch Linux

```bash
sudo pacman -Syu --needed python python-pip python-virtualenv base-devel
cd PwnScout
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements-optional.txt
```

If ROPgadget is unavailable from pip, install it through your distribution package manager or omit the optional dependency. The rest of PwnScout still works.

## Build the local demonstration binary

From the project root:

```bash
gcc -g -O0 -fno-stack-protector -no-pie \
  -Wno-implicit-function-declaration \
  -o samples/vulnerable samples/vulnerable.c
```

On some modern compilers, `gets` is hidden from headers. To make the demo compile consistently, use this alternative:

```bash
gcc -g -O0 -fno-stack-protector -no-pie \
  -include stdio.h -o samples/vulnerable samples/vulnerable.c
```

The compiler may warn about `gets`; that warning is expected for this deliberately vulnerable sample.

## Run

```bash
python main.py ./samples/vulnerable
```

Or use the concise non-interactive mode:

```bash
python main.py ./samples/vulnerable --no-tui
```

Export reports:

```bash
python main.py ./samples/vulnerable --json reports/vulnerable.json --txt reports/vulnerable.txt
```

The output directory must exist before export:

```bash
mkdir -p reports
```

## Keyboard controls

- `Tab` / `Shift+Tab`: move between controls and tabs
- Arrow keys: navigate table rows and tabs
- `q`: quit
- `r`: explain that the current report is a snapshot; relaunch to analyze a changed file

## Tests

```bash
python -m pytest -q
```

## Project layout

```text
PwnScout/
├── main.py
├── requirements.txt
├── requirements-optional.txt
├── pwnscout/
│   ├── analyzer.py
│   ├── checksec.py
│   ├── disassembler.py
│   ├── gadgets.py
│   ├── interface.py
│   ├── reporter.py
│   ├── symbols.py
│   └── vulnerabilities.py
├── samples/
│   └── vulnerable.c
└── tests/
    ├── test_reporter.py
    └── test_scanner.py
```

## Methodology and limitations

1. PwnScout verifies the ELF magic and parses the file with `pyelftools`.
2. Protection checks are inferred from program headers, dynamic tags, and imported symbols.
3. The risky-function scanner checks imported symbol names only. It does not prove that a call is reachable, attacker-controlled, or exploitable.
4. Relocation output is a raw relocation inventory. Exact PLT/GOT labeling depends on the binary's ABI, linker, and available sections.
5. Disassembly begins at the ELF entry point and is limited to a short preview. It is not a complete recursive disassembler.
6. Gadget discovery delegates to the external `ROPgadget` executable and is optional.

For a professional audit, validate results with independent tools such as `readelf`, `objdump`, `checksec`, and a debugger in an isolated lab.

## Suggested demo flow (3–5 minutes)

1. Show the project tree and explain that the tool performs static analysis only.
2. Run `python main.py ./samples/vulnerable`.
3. In Overview, point out architecture and security protections.
4. Show the `gets` finding and explain why the warning is heuristic.
5. Open Symbols/PLT-GOT and identify imported functions and relocation entries.
6. Open Disassembly and explain the entry-point preview.
7. Open ROP gadgets and explain the optional ROPgadget integration.
8. Export JSON/TXT and run the test suite.

## License

Educational project. Add a license of your choice before public redistribution.

## V2 additions (November 2026)

- Dark violet compact Textual dashboard with a global case-insensitive filter. Press `/` to focus search; **Tab** or click to switch tabs.
- Symbol-based function explorer: select a function row and press **Enter** (or click). Preview is limited to 180 instructions / 4 KiB. Stripped binaries might expose no named functions. ARM Thumb and some ABI-specific instruction modes are not inferred.
- ELF sections (address/size/flags), program segments (R/W/X), DT_NEEDED libraries, RPATH and RUNPATH.
- Security observations: NX/PIE/RELRO, canary heuristic, embedded library paths and writable+executable PT_LOAD segments. Findings are **heuristic indicators**, not proof of exploitation.
- SHA-256 and file size in metadata.
- Escaped offline HTML report using `--html`; HTML includes observations, imports, dependencies, sections, segments and known function symbols.
- All original tabs and JSON/TXT export are retained. In the TUI press `j` for JSON, `t` for TXT, `h` for HTML; reports are saved under `reports/`.

### V2 commands

```bash
python main.py samples/vulnerable --no-tui
python main.py samples/vulnerable --html reports/vulnerable.html --json reports/vulnerable.json --txt reports/vulnerable.txt
python -m pytest -v
```

In **Fish Shell**, activate with `source .venv/bin/activate.fish` instead of `activate`.

To inspect useful named functions, compile with debugging symbols (`gcc -g -O0 ...`). Stripped binaries can have no `.symtab` and thus significantly fewer functions.

### Validation limitations

Check results against `readelf -W -h -S -l -d samples/vulnerable`, `nm -an samples/vulnerable`, and `objdump -d samples/vulnerable`. The V2 code is intended for local testing, including TUI interaction and imports/exports on the user's distribution.
