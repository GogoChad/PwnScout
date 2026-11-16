# Journal d'utilisation de l'IA

Ce journal est commencé le 16/11/2026. Il décrit les usages réellement effectués dans cette conversation. Il ne prétend pas reconstituer un historique antérieur.

## 16/11/2026 · ChatGPT (GPT-6) · cadrage et génération d'un premier squelette

**Demande :** partir du sujet PwnScout (outil CLI/TUI Python d'analyse statique ELF) et produire une base de projet Linux comprenant une interface Textual, des contrôles de protections, l'inventaire des symboles/relocations, un repérage heuristique de fonctions sensibles, un aperçu Capstone, une intégration facultative de ROPgadget, des exports, des tests et une documentation.

**Fourni par l'IA :** un premier squelette multi-fichiers comprenant `main.py`, les modules de `pwnscout/`, les tests, `README.md`, les dépendances et un exemple C volontairement vulnérable.

**Gardé provisoirement :**
- La séparation en modules (analyseur, protections, symboles, désassemblage, gadgets, rapport et interface), car elle facilite les tests et l'explication.
- L'approche d'analyse statique sans exécution du binaire cible.
- L'idée d'un échantillon local pour illustrer les détections.

**À vérifier et corriger par l'étudiant avant rendu :**
- Installer les dépendances sur la machine cible et exécuter réellement l'application TUI.
- Compiler le programme de démonstration avec le compilateur disponible.
- Vérifier les résultats de NX, PIE, RELRO, Canary et FORTIFY avec `readelf`/`checksec` sur plusieurs binaires.
- Vérifier la collecte des relocations et la présentation PLT/GOT selon l'architecture et le linker.
- Tester les architectures prises en charge et les cas non pris en charge.
- Exécuter `pytest -v`, compléter les tests d'intégration et consigner les résultats réellement observés.
- Vérifier les raccourcis Textual et améliorer la navigation si nécessaire.
- Ne pas présenter le repérage d'importations sensibles comme une preuve de vulnérabilité : il s'agit d'heuristiques.

**Rejeté :**
- Toute affirmation selon laquelle le projet serait déjà intégralement validé sur Kali/Ubuntu/Arch ou que tous les tests auraient été exécutés, faute d'exécution et de vérification sur l'environnement de rendu.
- Toute idée de fabriquer des commits antidatés ou de reconstituer un historique hebdomadaire.

**Décision :** cette base est un point de départ assisté par IA, pas une preuve de travail personnel achevé. Les modifications, validations et choix techniques ultérieurs doivent être faits et expliqués par l'étudiant.

**Commit :** à renseigner après le véritable commit de cette entrée et des fichiers concernés. Ne pas inventer de hash.

## Évolution V2 — assistance IA (16/11/2026)

**Intervention dans cet échange :** proposition et génération d'une refonte de la TUI violet/sombre, modules d'inspection des sections et segments ELF, détection de chemins dynamiques et segments RWX, exploration des fonctions à partir des symboles, export HTML et tests associés.

**Vérifications effectuées dans l'environnement de génération :** contrôle de syntaxe Python (`compileall`), tests unitaires ne nécessitant pas les bibliothèques d'analyse (7 réussis), compilation d'un binaire C de démonstration. Les bibliothèques `textual`, `pyelftools` et `capstone` n'ont pas pu être installées dans cet environnement faute de réseau ; les interactions de la TUI et le test ELF de bout en bout restent donc **à valider sur la machine cible**.

**Travail restant à effectuer et documenter par le porteur du projet :** installer les dépendances, lancer les tests complets, comparer les observations avec `readelf`/`objdump`, examiner les fonctionnalités et ajuster le code selon les résultats. Cette entrée décrit l'intervention IA de cette session, et ne présume pas de la chronologie antérieure du projet.

## Évolution V3 — assistance IA (16/11/2026)

**Demande dans cet échange :** conserver la V2 et ajouter une comparaison de deux ELF, des explications des mécanismes de protection, et des recommandations de durcissement GCC dans l'interface et les rapports.

**Généré avec l'aide de l'IA :** `pwnscout/comparison.py`, `pwnscout/hardening.py`, adaptation de `main.py`, `analyzer.py`, `interface.py`, `reporter.py`, tests V3, documentation et cas de compilation comparative.

**Vérifié dans l'environnement de génération :** syntaxe Python et tests unitaires. Le test ELF de bout en bout dépend de `pyelftools` et `capstone`, absents de cet environnement, et n'a donc pas été exécuté ici. Le comportement interactif Textual sur CachyOS reste à vérifier par l'étudiant.

**Limites retenues :** comparaison de métadonnées et d'indicateurs seulement ; conseils GCC présentés comme pistes de durcissement, pas comme correctifs automatiques. Aucune revendication d'une exploitation détectée ou empêchée.

**À faire par l'étudiant :** exécuter les tests d'intégration et la TUI sur sa machine, confronter les résultats à `readelf` et `checksec`, comprendre et vérifier chaque nouvel onglet, conserver ses véritables commits Git et documenter les changements effectivement réalisés. Cette entrée ne prétend pas reconstituer de travaux passés.
