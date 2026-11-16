# PwnScout

**Outil Python d’inspection statique de binaires ELF sous Linux.**  
Interface TUI avec Textual, exports JSON/TXT/HTML et comparaison de deux exécutables.

> PwnScout ne lance pas les fichiers analysés. Les résultats sont descriptifs et heuristiques : ils ne constituent ni une preuve de vulnérabilité ni un audit de sécurité complet.

## Fonctionnalités

- **Overview / Security** : métadonnées ELF, SHA-256, NX, PIE, RELRO, stack canary, FORTIFY, imports sensibles, observations sur les segments RWX et chemins de chargement.
- **Functions / Disassembly** : fonctions identifiées à partir des symboles et désassemblage limité via Capstone ; aperçu du point d’entrée.
- **Sections / deps** : sections, segments, permissions, dépendances dynamiques, RPATH et RUNPATH.
- **Symbols / PLT-GOT** : imports, exports et relocations.
- **ROP gadgets** : consultation facultative via l’outil externe ROPgadget.
- **Hardening** : explications pédagogiques des protections et suggestions GCC/linker conditionnelles.
- **Compare ELF** : différences de protections, imports et dépendances entre deux ELF.
- **Exports** : rapports JSON, texte et HTML statique. Recherche dans les tableaux de la TUI.

## Pré-requis

- Linux, Python 3.10 ou plus récent, accès à un terminal compatible avec Textual.
- GCC et `binutils` pour compiler l’exemple et vérifier manuellement les résultats.
- ROPgadget facultatif (`requirements-optional.txt`).

## Installation

Dans le répertoire du projet :

```sh
python -m venv .venv
python -m pip --version  # facultatif : vérifie le Python actif
```

Avec **Fish** (CachyOS / Arch) :

```fish
source .venv/bin/activate.fish
python -m pip install -r requirements.txt
```

Avec **Bash / Zsh** :

```sh
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Sur CachyOS/Arch, si les outils système manquent : `sudo pacman -S --needed python python-pip gcc binutils`. Pour Debian/Kali/Ubuntu : `sudo apt install python3 python3-venv python3-pip gcc binutils`.

## Démonstration reproductible

L’échantillon `samples/vulnerable.c` utilise volontairement une API dangereuse. **Ne pas exécuter le binaire compilé** : il sert exclusivement à l’inspection statique.

Depuis la racine du dépôt :

```sh
gcc -g -O0 -fno-stack-protector -no-pie -Wl,-z,norelro \
  -Wno-implicit-function-declaration -o samples/weak samples/vulnerable.c

gcc -g -O0 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now \
  -Wno-implicit-function-declaration -o samples/hardened samples/vulnerable.c
```

Les avertissements GCC concernant `gets` sont attendus sur ce programme de démonstration. Selon le compilateur/libc, la compilation peut nécessiter une adaptation du code d’exemple.

```sh
python main.py samples/weak
python main.py samples/weak --compare samples/hardened
python main.py samples/weak --compare samples/hardened --no-tui
```

Exports :

```sh
mkdir -p reports
python main.py samples/weak --compare samples/hardened --no-tui \
  --json reports/comparison.json \
  --txt reports/comparison.txt \
  --html reports/comparison.html
```

Consulter toutes les options avec `python main.py --help`.

## Navigation dans la TUI

| Touche | Action |
|---|---|
| `/` | Accéder au filtre de recherche |
| `Tab` / flèches | Naviguer parmi onglets et tableaux |
| `Entrée` | Afficher une fonction ou l’explication d’une protection sélectionnée |
| `j` / `t` / `h` | Exporter en JSON / TXT / HTML |
| `q` | Quitter |

Les raccourcis d’export produisent des fichiers dans `reports/`.

## Validation

```sh
python -m pytest -v
python -m compileall -q main.py pwnscout tests
readelf -W -h -l -S -d samples/weak
readelf -W -h -l -S -d samples/hardened
```

Comparer notamment PIE, RELRO et les symboles disponibles avec `readelf` ou `checksec`. Certains tests d’intégration sont ignorés si le compilateur ou les dépendances nécessaires sont absents. Le comportement interactif de la TUI est à contrôler sur la machine de démonstration.

## Organisation

```text
PwnScout/
├── main.py                  # CLI et orchestration
├── pwnscout/
│   ├── analyzer.py          # analyse principale
│   ├── checksec.py          # protections ELF
│   ├── comparison.py        # comparaison de rapports
│   ├── disassembler.py      # aperçu Capstone
│   ├── elfdetails.py        # sections, segments, dépendances
│   ├── functions.py         # exploration des fonctions
│   ├── gadgets.py           # intégration ROPgadget
│   ├── hardening.py         # guide de durcissement
│   ├── interface.py         # TUI Textual
│   ├── reporter.py          # sorties JSON, TXT et HTML
│   ├── symbols.py           # symboles et relocations
│   └── vulnerabilities.py   # heuristiques d’imports
├── samples/vulnerable.c
├── tests/
├── RAPPORT_TECHNIQUE.md
├── IA.md
└── VERSION_HISTORY.md
```

## Limites connues

La présence d’un import sensible ne démontre pas qu’il existe un chemin d’exécution exploitable. L’identification de fonctions dépend des symboles présents ; un binaire *stripped* peut en fournir très peu. L’inférence de Canary et FORTIFY par les symboles n’est pas exhaustive. Le désassemblage et la collecte de gadgets ne remplacent pas une analyse de flot de contrôle. Les drapeaux de compilation suggérés ne corrigent pas une fonction dangereuse du code source.

Le fonctionnement détaillé et les conditions de validation sont décrits dans [RAPPORT_TECHNIQUE.md](RAPPORT_TECHNIQUE.md). L’utilisation de l’IA est consignée dans [IA.md](IA.md). La provenance des instantanés V1 à V3 est décrite dans [VERSION_HISTORY.md](VERSION_HISTORY.md).

## Hex Viewer and section entropy (V3.1)

The **Hex Viewer** tab displays file offsets, hexadecimal bytes and printable ASCII.
Enter a byte offset such as `0x40` or `64` and press Enter to load up to 16 rows
(256 bytes) without executing the inspected file. Offsets are **file positions**,
not virtual addresses; input is bounded to prevent unbounded reads.

The **Entropy** tab shows Shannon entropy for each ELF section in bits per byte
(0 to 8), the number of bytes sampled and whether the measurement is complete.
At most 1 MiB is sampled from the start of each file-backed section; sections
such as `.bss` with no bytes in the file are excluded from entropy calculation.
High entropy alone cannot establish encryption, packing or malicious intent.
Section entropy is also included in JSON, TXT and HTML exports.

Run the regression tests with `python -m pytest -v`.
