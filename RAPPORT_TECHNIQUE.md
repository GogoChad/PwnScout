# PwnScout — Rapport technique

**Projet :** outil TUI d'analyse statique de binaires ELF  
**Version de travail :** 1.0  
**Date de préparation de cette documentation :** 16/11/2026

## 1. Objectif

PwnScout vise à centraliser dans un terminal des informations utiles lors d'une première reconnaissance d'un exécutable ELF Linux : métadonnées, protections, symboles importés, relocations, fonctions potentiellement sensibles, aperçu de désassemblage et gadgets ROP facultatifs.

L'outil est destiné à l'apprentissage et à l'analyse de binaires que l'utilisateur est autorisé à examiner.

## 2. Périmètre et sécurité

L'analyse est statique : PwnScout lit le fichier et ne lance pas le binaire cible. L'intégration de ROPgadget appelle un outil externe sur le fichier en entrée. Le binaire d'exemple fourni est volontairement vulnérable et doit rester un fichier de laboratoire local.

Les alertes de fonctions dangereuses sont heuristiques. La présence de `strcpy`, `gets` ou `system` dans les imports ne démontre pas à elle seule une vulnérabilité exploitable. Il faut examiner les appels, les données contrôlées par l'utilisateur, les tailles de buffers et le flot d'exécution.

## 3. Architecture

- `main.py` : arguments CLI, orchestration et lancement de l'interface.
- `pwnscout/analyzer.py` : validation ELF et coordination des modules.
- `checksec.py` : inférence des protections à partir des segments, tags dynamiques et imports.
- `symbols.py` : extraction des imports, exports et relocations.
- `vulnerabilities.py` : règles heuristiques sur les noms de fonctions importées.
- `disassembler.py` : aperçu des instructions à partir du point d'entrée via Capstone.
- `gadgets.py` : intégration facultative de ROPgadget avec délai maximal.
- `interface.py` : tableaux et onglets Textual.
- `reporter.py` : export JSON et TXT.

## 4. Dépendances

Python 3.10+, Textual, Rich, pyelftools, Capstone et pytest. ROPgadget est facultatif. La compilation de l'échantillon nécessite GCC ou Clang.

## 5. Méthodes d'analyse

### 5.1 Format ELF

Le parseur vérifie la signature ELF puis extrait la classe, l'architecture, l'endianness, le type et l'adresse d'entrée. Les structures sont lues avec pyelftools.

### 5.2 Protections

- **NX :** présence d'un segment GNU_STACK non exécutable.
- **PIE :** type ELF dynamique (ET_DYN), interprété comme PIE dans le contexte d'un exécutable.
- **RELRO :** présence de GNU_RELRO ; le mode Full dépend également de l'activation de NOW.
- **Canary :** recherche de l'import `__stack_chk_fail`.
- **FORTIFY :** recherche d'importations suffixées `_chk`.

Ces vérifications sont des indicateurs best-effort et peuvent nécessiter une interprétation manuelle, notamment pour les bibliothèques partagées et binaires atypiques.

### 5.3 Fonctions sensibles

Le scanner compare les symboles importés à une liste de fonctions connues pour nécessiter une attention particulière. Il fournit une sévérité indicative, une explication et une piste de remplacement. Il ne réalise pas d'analyse de taint ni de preuve d'exploitabilité.

### 5.4 Symboles et relocations

Les imports et exports sont extraits des tables de symboles. Les entrées de relocation sont affichées avec section, offset, symbole et type. Selon le format, l'architecture et le linker, ces données correspondent aux mécanismes utilisés pour résoudre des références, notamment celles liées à la PLT/GOT. L'affichage n'est pas un désassemblage complet des stubs PLT.

### 5.5 Désassemblage et ROP

Capstone décode un aperçu limité à partir de l'adresse d'entrée dans une section exécutable. ROPgadget est appelé en option ; son absence ne doit pas empêcher les autres analyses.

## 6. Installation et utilisation

Consulter `README.md` pour les commandes adaptées à Debian/Ubuntu/Kali et Arch. Commande principale :

```bash
python main.py ./samples/vulnerable
```

Exports :

```bash
mkdir -p reports
python main.py ./samples/vulnerable --json reports/report.json --txt reports/report.txt
```

Tests :

```bash
python -m pytest -v
```

## 7. Plan de validation à effectuer et résultats à renseigner

Ne renseigner cette section qu'après exécution réelle.

| Vérification | Résultat observé |
|---|---|
| Installation des dépendances | À exécuter |
| Compilation de l'échantillon | À exécuter |
| Ouverture de la TUI | À exécuter |
| Détection de `gets` dans l'échantillon | À exécuter |
| Comparaison Checksec avec `readelf`/`checksec` | À exécuter |
| Export JSON et TXT | À exécuter |
| Tests pytest | À exécuter |
| Binaire ELF invalide / architecture non prise en charge | À exécuter |

## 8. Limites et améliorations possibles

- Ajouter des tests d'intégration sur des binaires de référence compilés avec différentes options.
- Distinguer précisément les exécutables PIE des bibliothèques partagées.
- Améliorer l'identification des sections et stubs PLT selon l'architecture.
- Ajouter une désassemblage par fonction et une navigation par symboles.
- Ajouter des règles configurables et un niveau de confiance aux alertes.
- Ajouter une comparaison automatique avec les sorties de `readelf` et `checksec`.

## 9. Utilisation de l'IA

Un premier squelette multi-fichiers a été généré avec assistance IA le 16/11/2026. Le détail des demandes, éléments gardés, éléments à vérifier et décisions est consigné dans `IA.md`. Cette documentation ne remplace ni les validations pratiques ni la compréhension du code par l'étudiant.

## Extension V3 — comparaison de deux ELF et recommandations

La V3 produit deux analyses statiques indépendantes et compare les champs NX, PIE, RELRO, Canary, FORTIFY ainsi que les noms d'imports, les imports marqués à risque et les dépendances dynamiques. Les différences sont descriptives ; elles ne constituent ni un score de sûreté ni une preuve de vulnérabilité. Le guide des protections expose le principe de chaque atténuation, ses limites, une commande de vérification et des options GCC/linker indicatives. Le rapport HTML et les exports texte et JSON incluent ces informations. L'affichage TUI et la comparaison sont soumis à validation d'intégration sur la machine de destination.
