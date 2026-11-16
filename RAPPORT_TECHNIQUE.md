# PwnScout — Rapport technique

**Objet :** analyse statique de binaires ELF sous Linux  
**Version :** V3  
**Date du document :** 16 novembre 2026

## 1. Présentation

PwnScout rassemble dans une interface terminal les informations nécessaires à une première inspection de sécurité d’un binaire ELF. Il extrait des métadonnées, vérifie certains mécanismes de protection, inventorie symboles et dépendances, présente des aperçus de désassemblage et compare deux binaires.

Le programme **n’exécute pas la cible**. Son périmètre est celui d’un outil de reconnaissance et de formation, non d’un moteur de preuve d’exploitabilité.

## 2. Architecture

Le point d’entrée `main.py` parse la ligne de commande, appelle `BinaryAnalyzer` et transmet le rapport structuré à la TUI ou aux exporteurs.

| Composant | Rôle |
|---|---|
| `analyzer.py` | Coordination de l’analyse, validation ELF et empreinte SHA-256 |
| `checksec.py` | Estimation NX, PIE, RELRO, stack canary et FORTIFY |
| `symbols.py` | Imports, exports et relocations |
| `vulnerabilities.py` | Heuristiques de fonctions importées sensibles |
| `elfdetails.py` | Sections, segments, dépendances, chemins dynamiques et segments RWX |
| `functions.py` / `disassembler.py` | Fonctions identifiables via les symboles et aperçu Capstone |
| `gadgets.py` | Recherche optionnelle de gadgets via ROPgadget |
| `comparison.py` | Comparaison de deux analyses ELF |
| `hardening.py` | Explications des protections et pistes de compilation |
| `interface.py` | Navigation et recherche dans Textual |
| `reporter.py` | Exports JSON, TXT et HTML |

**Bibliothèques principales :** Python 3.10+, `pyelftools`, `capstone`, `textual`, `rich`, `pytest`. `ROPgadget` est facultatif.

## 3. Méthodes

### 3.1 Extraction ELF

L’analyse commence par une vérification de la signature ELF, puis lit les en-têtes, tables de symboles, relocations, sections et segments au moyen de `pyelftools`. Elle calcule une empreinte SHA-256 du fichier analysé. Certaines informations peuvent manquer dans les binaires dépouillés de leurs symboles.

### 3.2 Indicateurs de protection

- **NX :** examen des permissions du segment de pile `PT_GNU_STACK`.
- **PIE :** distinction des exécutables position-independent et des bibliothèques partagées ; le seul type `ET_DYN` ne suffit pas toujours.
- **RELRO :** inspection de `PT_GNU_RELRO` et des indicateurs de liaison immédiate pour distinguer les configurations usuelles.
- **Canary :** recherche d’indicateurs comme `__stack_chk_fail`, non exhaustive.
- **FORTIFY :** détection heuristique de fonctions renforcées (`*_chk`), non exhaustive.

Des observations complémentaires concernent notamment les segments à la fois inscriptibles et exécutables et les chemins `RPATH` / `RUNPATH`.

### 3.3 Fonctions sensibles et désassemblage

Les imports sont comparés à une liste de fonctions justifiant une revue (`gets`, `strcpy`, etc.). Un résultat indique uniquement la présence d’un nom importé, **pas une vulnérabilité avérée**. Capstone permet de lire des instructions proches du point d’entrée ou d’une fonction identifiable par les symboles. Les architectures et modes d’instructions pris en charge sont limités.

La recherche de gadgets délègue à ROPgadget, lorsqu’il est installé. Elle peut être indisponible sans empêcher les autres fonctionnalités.

### 3.4 Comparaison et recommandations

Avec `--compare`, deux fichiers sont analysés séparément. PwnScout affiche les écarts de protections, d’imports et de dépendances. Il signale certaines incompatibilités (type ELF, architecture) et les fichiers identiques selon SHA-256. Une différence n’indique pas automatiquement qu’un fichier est plus sûr que l’autre.

Le guide de durcissement associe aux protections des descriptions, limites, méthodes de vérification et options GCC/linker indicatives. Ces options **ne réparent pas le code source**.

## 4. Interface et rapports

La TUI Textual regroupe Overview, Security, Hardening, Functions, Sections/deps, Symbols/PLT-GOT, Disassembly, ROP gadgets et, lorsqu’un deuxième ELF est fourni, Compare ELF. Elle propose un filtrage interactif ainsi que des exports JSON, TXT et HTML. L’export HTML échappe les champs issus du binaire pour produire une page statique consultable hors ligne.

## 5. Reproduction et contrôle

Les commandes détaillées figurent dans `README.md` : installation dans un environnement virtuel, compilation des variantes `samples/weak` et `samples/hardened`, lancement avec `--compare`, exports et tests.

Validation recommandée :

```sh
python -m pytest -v
python -m compileall -q main.py pwnscout tests
readelf -W -h -l -S -d samples/weak
readelf -W -h -l -S -d samples/hardened
python main.py samples/weak --compare samples/hardened --no-tui
```

Les vérifications automatisées effectuées dans l’environnement de génération ne couvrent pas toutes les interactions Textual ni tous les formats ELF. Les tests d’intégration qui exigent des dépendances absentes peuvent être ignorés ; leur exécution complète sur le poste cible reste nécessaire.

## 6. Limites et précautions

- Analyse statique uniquement, aucune observation du comportement à l’exécution.
- Détection de protections principalement fondée sur les en-têtes, tags et symboles : résultats parfois indéterminés.
- Pas de décompilation, d’analyse de flot de données ni de preuve automatique de vulnérabilité.
- Navigation par fonction limitée par la disponibilité des symboles et la prise en charge de Capstone.
- Résultats à recouper avec `readelf`, `objdump`, `checksec` et une analyse manuelle.
- Le programme C livré en exemple est volontairement vulnérable et doit rester un échantillon de laboratoire.

## 7. Traçabilité

L’utilisation de l’IA et les contrôles réalisés sont documentés dans `IA.md`. Les instantanés V1, V2 et V3 ont été importés dans Git le 16 novembre 2026 et leur provenance est décrite dans `VERSION_HISTORY.md`. Les dates d’import ne doivent pas être interprétées comme un historique hebdomadaire antérieur.
