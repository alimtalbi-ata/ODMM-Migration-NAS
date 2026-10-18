# ODMM — Audit statique, rationalisation et feuille de route V228.78–V231
Auteur : Abdelhalim Talbi
Date : 2026-10-18
Statut : audit statique du dépôt GitHub ; **ne vaut pas validation sur NAS réel**.

## 1. Périmètre et méthode
Référence : branche principale du dépôt `alimtalbi-ata/ODMM-Migration-NAS`, après qualification Windows #17. Inventaire de l'arbre Git et lecture ciblée de l'interface Windows Compact, du moteur POSIX, du portail d'opérations, des scripts de compilation, du workflow et de l'audit antérieur. Aucun benchmark NAS, test SMB/AD/LDAP réel, exécution sur poste client propre ou test de migration 150–500 To n'a été réalisé dans cet audit. Les constats sur les composants non lus restent des risques à vérifier, pas des défauts démontrés.

## 2. Inventaire mesuré
- 1 598 fichiers versionnés ; environ 25,5 Mo de blobs Git (hors historique).
- 1 158 fichiers `.py`, dont 751 noms de modules Python comportant un suffixe de version.
- 37 scripts `BUILD-WINDOWS*.cmd` et 36 fichiers `.iss` historiques.
- 25 PDF et 25 DOCX ; répertoires documentaires `05-Documentation` et `06-Documentation`, et qualifications `04-Tests-et-Qualification` et `05-Tests-Qualification`.
- `02-Sources` contient 1 383 fichiers ; il mélange implémentations, anciens points d'entrée, scripts de build, rapports et audits.
Ces nombres sont un état instantané et doivent être recalculés automatiquement dans les prochaines releases.

## 3. Conclusions techniques vérifiables
### P0 — Ne pas présenter le superviseur Windows comme moteur de migration
`02-Sources/odmm_windows_compact_v22811.py` annonce explicitement une console de supervision en lecture seule, sans exécution de migration. Son périmètre doit rester clairement distinct de Linux Full et du moteur de copie.

### P0 — Qualification réelle NFS/SMB et ACL non démontrée
`native_posix_migration.py` annonce un prototype conservateur limité aux fichiers réguliers, sans symlinks ni écrasement. Il comporte des protections contre les modifications concurrentes et une traçabilité SQLite, mais cela ne constitue pas une validation de préservation ACL NFSv4/SMB, ADS, héritage, SID, groupes AD/LDAP, fichiers ouverts ou cutover. Prévoir un laboratoire multi-fournisseur et des tests d'accès effectif.

### P0 — Publication Windows fiable mais portabilité terrain encore à vérifier
Workflow Windows 2022 avec Python 3.11, PyInstaller 6.16.0 et Inno Setup ; compilation #17 réussie, contrôles Tcl/Tk, GUI, exécution isolée et installation/désinstallation. Cela ne remplace pas une matrice de machines propres Windows 10/11 x64, comptes non administrateurs, SmartScreen/Defender, chemins Unicode/espaces, absence de réseau, politiques GPO, proxy et DPI. Conserver les preuves, hashes, provenance et rapport d'installation. Signer les exécutables quand un certificat de signature de code sera disponible.

### P1 — Dette de versionnage et duplication
La prolifération de modules `_vNNN` et de scripts `.cmd`/`.iss` versionnés crée une surface de maintenance disproportionnée et des risques de divergence. Il faut choisir un seul point d'entrée actif par édition, des packages stables et des tags Git pour l'historique. Ne supprimer aucun ancien module tant que les imports et contrats de compatibilité n'ont pas été inventoriés.

### P1 — Découplage de l'interface
Le fichier Windows Compact importe directement la logique de registre, dashboard, santé, pagination, diagnostics et triage. Extraire progressivement `services/registry_client.py`, `domain/jobs.py`, `presentation/windows_compact/`, `config/`, avec adaptateurs de compatibilité. Préserver l'UI existante jusqu'aux tests de non-régression et snapshots réels.

### P1 — Documentation et version de produit
Le README racine indique encore qu'aucun binaire n'est fourni alors que des artefacts qualifiés sont publiés par GitHub Actions. Distinguer version produit (`7.9.31`), version cumulative (`V228.77`) et numéro de build CI. Éviter les commentaires de version périmés dans le code. Chaque livraison doit inclure architecture, procédures Windows/Linux, matrice compatibilité, limites, rapports et captures réelles ou leur absence explicite.

### P1 — Observabilité et sécurité
Centraliser événements structurés, ID de job, trace de décision, raisons de refus, latences, erreurs et preuves. Ne jamais journaliser tokens, SID sensibles ou secrets. Introduire une matrice de compatibilité déclarative source/cible/protocole/ACL et refuser tout transfert non qualifié.

## 4. Architecture cible (transition progressive)
```text
ODMM
├── editions/
│   ├── windows_compact/       # supervision et diagnostic, lecture seule
│   ├── linux_compact/         # contrôle local
│   └── linux_full/            # orchestration et datamovers
├── odmm/
│   ├── domain/                # job, états, politiques, identité canonique
│   ├── application/           # planification, validation, cutover
│   ├── adapters/              # ONTAP, FlashBlade, PowerScale, NFS, SMB
│   ├── engines/               # moteur natif, adaptateurs externes explicites
│   ├── persistence/           # SQLite local et transactions
│   ├── observability/         # métriques, journaux, audit
│   └── security/              # ACL, identité, preuve, secrets
├── packaging/windows/         # une entrée build et un .iss actifs
├── tests/{unit,contract,integration,e2e,performance}/
├── docs/{architecture,installation,exploitation,qualification}/
├── archive/                   # historique hors chemin runtime
└── binary/                    # artefacts CI, non sources de vérité
```
Arborescence cible **proposée**, pas encore appliquée. Migration incrémentale avec wrappers d'import et tests, sans renommage massif immédiat.

## 5. Fonctionnalités priorisées selon utilité et risque
| Priorité | Capacité | Livrable / critère de sortie |
|---|---|---|
| P0 | Préqualification source/cible ONTAP ↔ FlashBlade | inventaire réel, matrice NFS/SMB, capacités, refus explicite |
| P0 | Intégrité et reprise | manifeste transactionnel, reprise idempotente, hashes et rapport vérifiable |
| P0 | Fidélité identité/ACL | matrices SID/UID/GID, héritage, tests de droits effectifs ; refus si perte de droits |
| P0 | Cutover sûr | dry-run, delta, fenêtre, validation HITL, rollback et fencing |
| P0 | Packaging Windows autonome | portable + installateur, Tcl/Tk, poste propre, provenance et SHA-256 |
| P1 | PowerScale/Isilon ↔ ONTAP/FlashBlade | mêmes contrats et tests avant élargissement |
| P1 | Supervision opérationnelle | débit, fichiers/s, backlog, erreurs, ETA bornée, diagnostics lisibles |
| P1 | Gouverneur QoS | limites bande passante/IOPS, fenêtres, arrêt/reprise, équité |
| P2 | Orchestration multi-datamover | leases/fencing et tests de concurrence/failover |
| P2 | Assistants IA | recommandations explicables, jamais exécution destructive implicite |

## 6. Plan d'évolution
### V228.78 — Stabilisation / inventaire de dépendances
- Générer inventaire des imports actifs, graphes d'appels, scripts réellement utilisés et manifeste des artefacts.
- Éliminer les divergences README/version/build sans casser l'API.
- Ajouter lint, `compileall`, tests rapides et tests de contrats par édition ; baseline reproductible.
- Compléter tests Windows sans sources, et matrice d'installation sur poste propre.

### V228.79 — Refactor Windows Compact
- Séparer présentation / service registre / modèles / configuration.
- Maintenir compatibilité de l'ancien point d'entrée et fonctionnalités de lecture seule.
- Tester navigation clavier, accessibilité, états vide/chargement/erreur, connexion et pagination.
- Captures d'écran réelles et comparaisons avant/après.

### V229.0 — Préqualification NAS
- Contrats source/cible ONTAP ↔ FlashBlade, NFS/SMB, capacités et risques ACL.
- Plan de migration exportable, simulations clairement étiquetées, refus si non qualifié.

### V230.0 — Moteur fiable
- Transferts natifs et delta incrémental sur banc réel, journal transactionnel, checksum, reprise après crash, débit et QoS.
- Tests d'accès effectif AD/LDAP et ACL NFSv4/SMB, plus comparaison de données.
- Pas de statut « production » sans preuves sur matériels/firmwares réellement testés.

### V231.0 — Échelle et cutover
- Multi-datamover, segmentation réseau, coordination, fencing, bascule et rollback sous approbation.
- Scénarios 150/300/500 To avec charge représentative et KPI observés.

## 7. Stratégie de rationalisation sans rupture
1. Geler le contrat d'entrée/sortie et enregistrer les tests de référence.
2. Identifier par analyse AST les imports réellement accessibles depuis les trois éditions ; marquer les modules non atteints comme **candidats** seulement.
3. Créer packages stables et adaptateurs de compatibilité ; migrer un sous-système à la fois.
4. Mettre à jour les tests et la documentation au même commit.
5. Déplacer les historiques dans `archive/` seulement après vérification de l'absence d'import, de référence build et de dépendance de release.
6. Valider sur Linux et Windows avant fusion, conserver tags et ZIP cumulatifs.
7. Conserver les historiques dans Git même après déplacement ; ne pas écraser les branches de travail existantes.

## 8. Critères d'acceptation
- Aucun recul des contrôles de sécurité ni du caractère fail-closed.
- Un seul chemin de build officiellement supporté par édition, avec version/provenance cohérentes.
- CI rapide et complète, preuves réelles identifiées, zéro simulation présentée comme test.
- Fonctions P0 testées sur protocoles/fournisseurs cibles avant toute promesse de production.
- Windows Compact exécutable sans Python ni code source sur une machine Windows propre ; l'exécution sur le runner seul ne suffit pas.
