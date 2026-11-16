# Historique des instantanés V1 → V2 → V3

Ce dépôt Git a été **initialisé le 16 novembre 2026** à partir des archives existantes `PwnScout-1.0-avec-journal.zip`, `PwnScout-V2.zip` et `PwnScout-V3.zip`.

Les trois premiers commits présentent les **différences réelles entre les trois versions** du code, importées dans l’ordre V1 → V2 → V3. **Ce ne sont pas des commits réalisés pendant le développement initial et ils ne démontrent pas une activité Git étalée sur plusieurs semaines.** Les dates des commits sont celles de l’import actuel. Leur auteur local est `PwnScout Snapshot Import` pour ne pas attribuer artificiellement ces imports à une personne.

- **V1** : socle d’analyse ELF, protections, symboles, désassemblage initial, gadgets facultatifs et rapports.
- **V2** : interface violet/dark, extraction de métadonnées et sections ELF, explorateur de fonctions, recherche et rapport HTML.
- **V3** : comparaison ELF, guide pédagogique des protections et recommandations de durcissement GCC.

`IA.md` détaille la contribution de l’assistant. Pour les changements futurs, configurer `git config user.name` et `git config user.email` avec ses propres coordonnées, puis créer des commits à mesure que le travail est réalisé.
