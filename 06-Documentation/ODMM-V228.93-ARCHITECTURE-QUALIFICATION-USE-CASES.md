# ODMM V228.93 — Architecture, adéquation aux usages et qualification

Auteur : Abdelhalim Talbi. Statut : revue technique fondée sur les sources et les workflows ; les preuves d'exécution sont les rapports GitHub Actions, et non des captures fictives.

## 1. Périmètre et vérité produit

**Deux capacités distinctes :**
1. **Windows Compact** est un **client de supervision en lecture seule**. Il consulte un registre de jobs, filtre, trie, pagine, présente les diagnostics et ouvre des rapports JSON. Il ne migre aucun fichier, ne modifie pas les ACL et ne pilote pas de bascule.
2. **Moteur natif POSIX** : implémentations expérimentales de copie, reprise et registre transactionnel SQLite. Les tests de crash et de journalisation ne prouvent ni fidélité ACL/SMB multi-fournisseurs, ni performances 150–500 To, ni capacité de migration NAS en production.

Il serait trompeur de vendre le binaire Windows comme moteur de migration NetApp/FlashBlade/PowerScale : son interface n'expose aucune opération de transfert.

## 2. Matrice objectifs / capacités / preuves

| Besoin prioritaire | Implémentation observée | Niveau de qualification | Écart / prochaine action |
|---|---|---|---|
| EXE Windows portable sans Python | PyInstaller, auto-test Tcl/Tk, démarrage hors sources | Tests automatisés Windows CI | Essais manuels Windows 10/11, antivirus, DPI et accessibilité non attestés |
| Installateur et désinstallation | Inno Setup + smoke silencieux | Tests automatisés Windows CI | Installation interactive, droits utilisateur, upgrade et rollback à qualifier |
| Supervision lecture seule | API jobs avec Bearer, recherche, filtres, pagination, détails | Tests unitaires + démarrage GUI | Parcours humain E2E et tests réseau réels manquants |
| Contrat API et sécurité | HTTPS distant obligatoire, pas de redirection, JSON strict, réponse bornée | Tests adversariaux | TLS avec PKI d'entreprise, proxy et authentification réelle à qualifier |
| Statut données LIVE/STALE/DEMO | Marqueurs explicites dans l'interface | Contrats UI et smoke démarrage | Test automatisé de transition complète avec faux serveur à construire |
| Copie et reprise POSIX | SQLite WAL, intentions, tests de crash | Tests Linux CI | Matrice NFS/SMB/ACL fournisseurs non qualifiée |
| NetApp ↔ Pure FlashBlade | Objectif stratégique | Pas de preuve d'intégration NAS E2E | Connecteurs, jeu de données, identité/ACL et cutover à développer et qualifier |
| PowerScale/Isilon ↔ NetApp/FlashBlade | Objectif stratégique | Pas de preuve E2E | Qualification multi-protocoles, propriétaires, SID/UID/GID |
| Millions de fichiers / 150–500 To | Cible de dimensionnement | Non démontré | Benchmarks réalistes, débit, erreurs, reprise, fenêtres et gouverneur |
| Audit reproductible | Manifestes SHA256, source commit, rapports CI | Vérifications automatisées | Signatures cryptographiques de provenance non attestées |

## 3. Architecture d'exécution

Windows Compact Tkinter → validation locale de l'origine et du jeton → worker asynchrone GET /api/v1/operations/jobs?limit=200 → validation JSON/contrat → file bornée et génération → thread UI Tk → vue paginée et diagnostics. Les données ne sont pas transférées par le client.

Moteur POSIX expérimental → inventaire/planning → intention SQLite durable → opération de copie → vérification/réconciliation opérateur → preuve d'audit. Le chemin exact et les garanties doivent être démontrés scénario par scénario.

## 4. Politique de sécurité et de résilience

- Refuser les URL malformées et HTTP distant ; ne pas exporter le jeton.
- Refuser les redirections de requêtes authentifiées et les JSON ambigus.
- Préserver les données précédentes sur échec, en les affichant comme **périmées**, jamais comme LIVE.
- Ne jamais déclarer un cutover ou une restauration ACL qualifiés sans test de droits effectifs sur NAS réel.
- Ne pas assimiler SHA256 à une signature d'éditeur ; provenance et authenticité nécessitent des contrôles supplémentaires.

## 5. Recette Windows obligatoire

1. Exécuter les tests unitaires Windows et les tests de sécurité des manifestes.
2. Compiler portable et installateur avec le script unique BUILD-WINDOWS-COMPACT.cmd.
3. Vérifier l'initialisation Tcl/Tk et le démarrage hors arbre de sources.
4. Installer et désinstaller silencieusement, conserver le rapport d'exécution.
5. Vérifier le manifeste cumulatif, l'empreinte des fichiers et le SHA du commit.
6. Vérifier manuellement sur Windows 10/11 : connexion valide/invalide, token, réseau interrompu, démonstration, sélection, filtres, export, navigation clavier, affichage DPI.
7. Documenter les preuves réelles ; aucune maquette n'est une capture de test.

## 6. Priorités architecturales après V228.93

**P0** : contrat E2E serveur ↔ supervision Windows, contrôles de sécurité et gestion des erreurs, intégrité de release. **P1** : scénarios de migration NetApp ↔ FlashBlade avec NFS/SMB et tests d'accès effectif, reprise, bascule, rollback et audit. **P2** : PowerScale ↔ NetApp/FlashBlade, multi-datamovers, benchmarks volumétriques, compatibilité firmware. **P3** : améliorations cosmétiques seulement après preuves fonctionnelles.

## 7. Limites des preuves

Les workflows verts démontrent uniquement les tests effectivement automatisés. Ils ne constituent pas une homologation de migration NAS, une validation Windows 10/11 multi-environnements, ni une certification de sécurité. Le paquet reste une préversion tant que les scénarios critiques ci-dessus ne sont pas qualifiés.
