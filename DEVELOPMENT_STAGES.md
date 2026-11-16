# PwnScout — découpage technique et traçabilité

Ce document est une **carte de lecture des modules**, et non une chronologie Git rétroactive.
Les étapes 1–16 décrivent des composants présents dans les instantanés V1, V2 et V3 importés le 16/11/2026. Elles **ne correspondent pas à 16 commits historiques**. Les étapes 17–19 sont des axes de validation et de finalisation ; elles ne doivent être cochées que lorsque les vérifications sont effectuées.

| Étape | Objet technique | Fichiers principaux | Instantané d'origine |
|---|---|---|---|
| 1 | Structure CLI et projet | `main.py`, `requirements.txt` | V1 |
| 2 | Orchestration d'analyse ELF | `pwnscout/analyzer.py` | V1 |
| 3 | Analyse NX, PIE, RELRO, canary, FORTIFY | `pwnscout/checksec.py` | V1 |
| 4 | Symboles et relocations | `pwnscout/symbols.py` | V1 |
| 5 | Imports potentiellement sensibles | `pwnscout/vulnerabilities.py` | V1 |
| 6 | Désassemblage depuis le point d'entrée | `pwnscout/disassembler.py` | V1 |
| 7 | Gadgets ROP optionnels | `pwnscout/gadgets.py` | V1 |
| 8 | Interface terminal | `pwnscout/interface.py` | V1 |
| 9 | Rapports JSON/TXT | `pwnscout/reporter.py` | V1 |
| 10 | Sections, segments et dépendances ELF | `pwnscout/elfdetails.py` | V2 |
| 11 | Explorateur et désassemblage par fonction | `pwnscout/functions.py` | V2 |
| 12 | Refonte violette et filtres | `pwnscout/interface.py` | V2 |
| 13 | Export HTML | `pwnscout/reporter.py` | V2 |
| 14 | Comparaison de deux ELF | `pwnscout/comparison.py` | V3 |
| 15 | Guide des protections et durcissement | `pwnscout/hardening.py` | V3 |
| 16 | Tests existants de ces fonctions | `tests/test_*.py` | V1–V3 |
| 17 | Vérification avec `readelf`/`checksec` | résultats à collecter sur machine cible | À effectuer |
| 18 | Gestion d'entrées invalides et de binaires stripped | tests supplémentaires et corrections | À effectuer |
| 19 | Finalisation et démonstration | README, rapport, vidéo et preuve des tests | À effectuer |

## Commits Git réels

Le dépôt comporte quatre commits d'import documentés dans `VERSION_HISTORY.md`, puis des commits de maintenance réalisés après l'import. Ils ont été créés le même jour ; aucune date n'a été antidatée. Les correctifs ajoutés ensuite sont visibles avec `git log --oneline` et `git show <hash>`.

## Vérification reproductible

Depuis la racine du projet, dans un environnement virtuel avec `requirements.txt` installé :

```sh
python -m pytest -v
python main.py --help
gcc -g -O0 -fno-stack-protector -no-pie -Wno-implicit-function-declaration -o samples/weak samples/vulnerable.c
gcc -g -O0 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now -Wno-implicit-function-declaration -o samples/hardened samples/vulnerable.c
python main.py samples/weak --compare samples/hardened --no-tui
```

Ces commandes restent à valider dans l'environnement du rendu. La présence de la commande ici ne constitue pas un résultat d'exécution.
