# ODMM Linux — Full multiserveur et Compact portable

Auteur : Abdelhalim Talbi. Document d'architecture et d'exploitation. État : développement/qualification partielle, **pas une validation de migration NAS de production**.

## Éditions

**Linux Full** est destiné à l'orchestration et aux datamovers séparés sur plusieurs hôtes. L'infrastructure cible recommande quatre rôles logiques : control plane/API, registre/audit transactionnel, datamovers proches des réseaux NAS, et observabilité. Les rôles peuvent être regroupés en environnement de laboratoire ; les séparer en production évite de concentrer les accès réseau et les écritures. **La topologie décrite est une architecture cible, pas un cluster HA livré et testé.**

**Linux Compact** est un utilitaire Python portable de **supervision en lecture seule**, exploitable depuis un répertoire copié, avec fichier de rapport JSON ou connexion API. Ce n'est pas un moteur de copie autonome.

## Démarrage portable et préqualification

À la racine de l'archive, sur un hôte Linux disposant de Python 3.10+ :

```bash
bash 03-Build-Installation/RUN-LINUX-COMPACT.sh --preflight
bash 03-Build-Installation/RUN-LINUX-COMPACT.sh --demo-overview
bash 03-Build-Installation/RUN-LINUX-COMPACT.sh --report /chemin/rapport.json --overview
bash 03-Build-Installation/RUN-LINUX-FULL.sh --preflight
bash 03-Build-Installation/RUN-LINUX-FULL.sh --check
```

Le préflight est **non destructif**, ne monte aucun NAS et ne démarre aucune migration. Il retourne un JSON avec `passed`, `checks`, `edition`, `hostname` et `nas_migration_qualified=false`. Code retour 0 : prérequis locaux vérifiés ; 1 : prérequis manquant ; 2 : erreur d'E/S. Le seuil d'espace libre est de 1 Gio, uniquement pour le poste de contrôle : il ne dimensionne pas le stockage de migration.

## Architecture multiserveur cible

```text
Console/CLI Linux Compact -- HTTPS/mTLS cible --> Control plane / API
                                                    |
                                                Scheduler
                                                    |
                                        Registre/audit SQLite ou DB HA cible
                                                    |
                        +---------------------------+---------------------------+
                        |                           |                           |
                   Datamover A                 Datamover B                 Datamover N
                 VLAN NAS source             VLAN NAS cible             Site distant
                        +------------ inventaire, copie, vérification ------------+
```

**Invariants avant exécution réelle** : authentification forte des agents, séparation lecture/écriture, identité canonique SID/UID/GID, préservation ACL/xattr/ADS selon protocole, journal d'intentions durable, fencing d'ownership, idempotence, reprise explicite des écritures incertaines, contrôles d'accès effectifs et preuve d'intégrité. Aucun de ces invariants ne doit être supposé satisfait par le seul préflight.

## Parcours de qualification requis

1. Déploiement isolé sur au moins trois VM Linux avec segmentation réseau et secrets hors dépôt.
2. Vérification des ports et de la connectivité contrôlée ; ne pas ouvrir SMB/NFS globalement.
3. Qualification fonctionnelle source/cible NetApp ↔ FlashBlade, puis PowerScale ↔ NetApp/FlashBlade.
4. Jeux de données représentatifs NFS et SMB : liens, verrouillages, caractères Unicode, fichiers volumineux, ACL imbriquées, UID/GID/SID, xattr/ADS.
5. Reprise après kill -9, coupure réseau, redémarrage datamover et divergence de registre ; aucun retry silencieux après état incertain.
6. Vérification indépendante des fichiers, métadonnées et droits effectifs ; simulation de cutover et rollback.
7. Mesure sur millions de fichiers et charges progressives avant toute affirmation de performance à 150–500 To.

## Preuves CI

Le workflow `.github/workflows/linux-deployment-preflight.yml` exécute les tests et la vérification des prérequis séparément pour les éditions full et compact sur Ubuntu 24.04. Il conserve un rapport JSON par édition. Une CI verte prouve les contrôles locaux, **pas le fonctionnement multiserveur, ni l'HA, ni la migration NAS réelle**.

## Feuille de route

P0 : sécuriser le contrat API/agent et les invariants d'écriture. P1 : datamover POSIX/NFS qualifié, reprise et audit. P2 : fidélité SMB/ACL multi-vendeur et bascule contrôlée. P3 : packaging portable autonome et orchestration HA multi-sites. La compatibilité NAS dépend des versions firmware/API et doit être documentée par couples source/cible.

## Validation de topologie Linux Full (inventaire hors ligne)

Créer un fichier JSON local, par exemple :

```json
{
  "schema_version": 1,
  "nodes": [
    {"name": "control-1", "address": "10.1.0.1", "roles": ["control", "registry"], "site": "paris", "networks": []},
    {"name": "mover-1", "address": "10.1.0.2", "roles": ["datamover"], "site": "paris", "networks": ["nas-a"]}
  ]
}
```

Cet exemple est **fictif** et ne représente pas une installation testée. Commande :

```bash
python3 03-Build-Installation/ODMM-LINUX-PREFLIGHT.py --edition full --topology topology.json
```

La validation refuse les rôles requis manquants, les doublons d'adresse, les nœuds malformés, les JSON ambigus et les datamovers sans réseau NAS. Elle ne vérifie pas l'accessibilité réseau ni le fencing distribué ; `ready_for_live_migration` reste toujours `false`.

## Registre transactionnel de réservation des datamovers — prototype

Le module `02-Sources/odmm_linux_lease_registry.py` utilise SQLite et `BEGIN IMMEDIATE` pour sérialiser l'attribution de tâches. Chaque réservation comporte un identifiant de tâche, un propriétaire, une échéance et un **jeton de fencing croissant**. Les opérations `claim`, `renew` et `release` refusent les propriétaires ou jetons périmés ; l'expiration permet un nouveau claim avec un nouveau jeton. Le registre est persistant après réouverture de la base.

**Limite critique** : la validité du jeton doit être imposée **sur chaque opération d'écriture du datamover** et, idéalement, par le service propriétaire de la ressource cible. Un ancien agent qui conserve un accès NAS peut encore écrire après expiration si ce contrôle n'est pas intégré. Ce module ne doit donc pas être utilisé comme garantie de fencing distribué, ni comme preuve de sécurité HA. Aucun datamover réel n'est branché sur ce registre.

La qualification future doit inclure plusieurs processus concurrents, interruption pendant transaction, pertes de réseau, dérive des horloges, changement de propriétaire et validation de l'absence d'écriture avec jeton obsolète. Le temps d'expiration dépend pour l'instant de l'horloge fournie : une autorité temporelle et un contrat d'expiration centralisés restent à concevoir.

## Contrôle atomique des effets sur le registre

Le module `odmm_linux_lease_registry.py` expose maintenant `assert_current()` et `guarded_registry_effect()`. La seconde fonction verrouille la transaction SQLite avec `BEGIN IMMEDIATE`, vérifie le propriétaire, le jeton et l'expiration, puis exécute une mutation SQL dans **la même transaction**. Si le callback échoue, les écritures SQL sont annulées. Les tests couvrent l'expiration, un propriétaire incorrect et le rollback.

**Ne jamais exécuter d'écriture NAS, de commande shell, d'accès réseau ou de copie de fichiers dans le callback** : la transaction ne peut annuler ces effets externes. Pour l'exécution distribuée, un protocole supplémentaire est requis : journal d'intentions avant effet, contrôle du fencing au niveau du service cible ou proxy, confirmation durable après effet, état INCERTAIN en cas de crash, et réconciliation humaine avant reprise. Les protections du registre ne valent pas qualification du datamover.

## Journal durable des intentions de migration (prototype)

`02-Sources/odmm_linux_datamover_intents.py` enregistre chaque intention avant tout effet externe, sous un identifiant unique, avec l'identifiant de tâche, le propriétaire, le jeton de fencing et l'empreinte SHA-256 canonique du contenu. Les états sont `PREPARED`, `IN_FLIGHT`, `UNCERTAIN`, `VERIFIED` et `ABORTED`. Les transitions vers VERIFIED et ABORTED sont exposées avec contrôles de propriétaire, de jeton et d'état, mais **aucune opération NAS ne peut être considérée indépendamment vérifiée par ce composant**.

Le contrat impose de persister `PREPARED`, puis `IN_FLIGHT` **avant** d'autoriser un éventuel effet externe. Au redémarrage, `quarantine_unfinished()` transforme les opérations `IN_FLIGHT` en `UNCERTAIN` ; elles nécessitent une inspection des données et métadonnées cibles avant toute décision de reprise. Le journal refuse la réutilisation d'un identifiant d'intention avec une autre empreinte et contrôle le jeton de réservation lors des transitions.

**Limites** : SQLite `synchronous=FULL` et le journal WAL doivent être configurés par l'installeur/exploitant ; les tests de réouverture ne sont pas des essais de coupure électrique. L'empreinte SHA-256 protège l'identité de l'intention, pas l'intégrité d'un fichier NAS. Aucun protocole d'acknowledgment distant, fencing cible, moteur de copie ni vérification d'accès effectif n'est intégré à ce stade. Une validation humaine doit précéder la sortie de `UNCERTAIN`.

## Transitions de confirmation et d'annulation

`record_verification()` autorise `IN_FLIGHT → VERIFIED` uniquement avec un propriétaire, un jeton et une empreinte de l'intention valides. **Attention** : l'empreinte vérifiée est celle de la description d'intention ; elle n'est pas une preuve de checksum du contenu NAS, ni une validation des ACL. Une couche d'attestation indépendante doit être ajoutée avant l'exploitation réelle.

`abort_prepared()` autorise uniquement `PREPARED → ABORTED`. Toute tentative d'annuler `IN_FLIGHT` ou `UNCERTAIN` est rejetée, car l'effet externe pourrait déjà s'être produit. Les tests de transitions couvrent les états et empreintes incompatibles.

## Vérification indépendante des fichiers en laboratoire

Le module `02-Sources/odmm_linux_lab_verifier.py` fournit `verify_pair(source, target)` pour des fichiers réguliers locaux. Il ouvre les fichiers en lecture seule, refuse les liens symboliques, compare SHA-256, taille et mode POSIX, et signale un changement de fichier observé durant la lecture.

Exemple **fictif**, sans NAS :

```python
from odmm_linux_lab_verifier import verify_pair
result = verify_pair("/tmp/odmm-lab/source.bin", "/tmp/odmm-lab/target.bin")
assert result["verified"] and not result["nas_acl_qualified"]
```

Cette vérification **n'atteste pas** des propriétaires, groupes, ACL NFSv4/SMB, attributs étendus, ADS, horodatages ou accès effectifs. Elle ne remplace pas une vérification d'intégrité liée au journal transactionnel. Les chemins sont supposés situés dans un environnement de test maîtrisé ; un attaquant contrôlant les répertoires parents pourrait exploiter des courses de résolution de chemin, et les modifications concurrentes à granularité identique ne sont pas toutes détectables. Le module ne doit pas être utilisé comme vérificateur de sécurité NAS de production.

## Pipeline Linux local de laboratoire — première intégration bout en bout

Le module `02-Sources/odmm_linux_lab_pipeline.py` relie le bail SQLite, l'intention `PREPARED → IN_FLIGHT`, une copie locale exclusive `O_EXCL`, un `fsync` du fichier et du répertoire, une vérification indépendante SHA-256 + mode POSIX et la transition `VERIFIED`. Il refuse les cibles existantes et ne supprime pas une copie partielle après échec ; l'intention reste `IN_FLIGHT` et sera placée `UNCERTAIN` au redémarrage. Une répétition de la même cible ne peut pas écraser le résultat existant.

**Limites majeures** : prototype sur répertoire local isolé uniquement ; pas de montage NFS/SMB, ACL, propriétaire, xattr, ADS, contrôle de capacité, snapshots, vérification d'accès effectif, réplication HA ou coordination inter-hôtes. Les protections contre les liens symboliques et les modifications concurrentes ne sont pas complètes : l'ouverture de la source et la résolution des répertoires parents nécessitent un durcissement avant tout usage sur un système de fichiers non fiable. L'écriture de fichier n'est pas atomique avec la transaction SQLite ; le journal marque donc toute interruption en cours comme incertaine. Ce code **ne doit pas être utilisé pour migrer des données de production**.

La CI `linux-deployment-preflight.yml` inclut les tests `test_linux_lab_pipeline.py` (copie vérifiée, refus d'écrasement, refus de répétition).

## Injection de pannes et quarantaine de reprise

Le pipeline local accepte le paramètre de laboratoire `fault_at="after_intent"` ou `fault_at="after_copy_fsync"`. Le premier déclenche une exception après persistance de `IN_FLIGHT` et avant ouverture de la cible. Le second déclenche une exception après copie et `fsync` du fichier, avant mise à jour des permissions et vérification.

Dans les deux scénarios, `quarantine_unfinished()` convertit `IN_FLIGHT` en `UNCERTAIN`. Le fichier cible éventuellement présent n'est ni écrasé ni effacé automatiquement. Les tests `test_linux_lab_pipeline.py` vérifient ces invariants.

**Qualification limitée** : injections d'exceptions déterministes dans le même processus. Aucun `SIGKILL`, redémarrage de machine, perte de disque, défaut NFS/SMB, panne réseau ou bascule HA n'a été qualifié. L'état `UNCERTAIN` exige une réconciliation explicite avant toute reprise.

## Durcissement du descripteur source

La copie de laboratoire ouvre désormais la source avec `O_NOFOLLOW` et `O_NONBLOCK`, valide par `fstat` qu'il s'agit d'un fichier régulier, et copie à partir d'un descripteur déjà ouvert. Elle compare les informations `device/inode/taille/mtime_ns` avant et après lecture afin de rejeter une modification observée pendant la copie. Les permissions de la cible proviennent du descripteur source initial, et non d'un nouveau `stat` sur le chemin. Des tests supplémentaires rejettent les sources symboliques et les points d'injection inconnus.

**Limite** : ces contrôles réduisent les courses sur le chemin source mais ne constituent pas une protection complète contre les répertoires parents malveillants, les modifications invisibles dans les métadonnées observées ou les opérations NAS distantes. Une isolation par descripteurs de répertoire et `openat2` ainsi qu'une vérification des ACL restent nécessaires.

## Essai d'arrêt brutal de processus Linux

Le test `09-Tools/test_linux_lab_process_crash.py` démarre un sous-processus Python avec une base SQLite WAL et `synchronous=FULL`, persiste une intention `IN_FLIGHT`, puis termine ce sous-processus par `SIGKILL`. Le processus de test rouvre ensuite le registre, constate la présence de l'intention et la place en `UNCERTAIN` via `quarantine_unfinished()`.

**Périmètre exact** : arrêt brutal d'un processus applicatif, et non panne électrique, arrêt du noyau, corruption disque, perte d'accès NAS ou bascule multiserveur. Le test se déclenche avant la création du fichier cible ; les scénarios de `SIGKILL` pendant une copie partielle et après `fsync` du fichier restent à qualifier. L'exécution est désormais requise dans le workflow Linux.

## SIGKILL aux trois frontières d'écriture

La suite `test_linux_lab_process_crash.py` couvre désormais trois scénarios de sous-processus terminés par `SIGKILL` : `after_intent` (cible absente), `during_copy` (cible partielle avec premier bloc synchronisé), `after_copy_fsync` (cible complète mais non confirmée). Chaque scénario rouvre SQLite et exige `IN_FLIGHT → UNCERTAIN`. Aucun scénario ne doit marquer la tâche `VERIFIED` ni écraser une cible existante pendant une reprise automatique.

Les points d'injection sont des arrêts déterministes après exception et `SIGKILL` du processus ; ils ne reproduisent pas toutes les fenêtres d'interruption possibles à l'instruction près. Un test de coupure de courant et un test NAS distant restent hors périmètre.

## Réconciliation en lecture seule des intentions UNCERTAIN

Le module `odmm_linux_lab_reconciliation.py` propose `inspect_uncertain(db, intent_id, source, target)`. Il exige un état `UNCERTAIN` et produit un rapport en lecture seule : `TARGET_ABSENT`, `CONTENT_MISMATCH`, `POSIX_MODE_MISMATCH`, ou `LOCAL_CONTENT_AND_MODE_MATCH` (avec SHA-256 de la cible). La décision reste **MANUAL_REVIEW_REQUIRED** dans tous les cas ; aucune transition automatique `UNCERTAIN → VERIFIED`, aucune suppression, ni relance de copie n'est autorisée.

Les tests reproduisent les trois scénarios de laboratoire (absence, copie partielle, copie complète non confirmée) et contrôlent que l'état SQLite reste `UNCERTAIN`. Le rapport ne prouve pas la conformité des ACL NFSv4/SMB, xattr, propriétaires ou permissions effectives et ne constitue pas une attestation NAS de production.

## Audit humain et vérification des preuves

Le journal SQLite `odmm_linux_lab_reconciliation_audit.py` conserve l'identifiant de revue, l'identité déclarée de l'opérateur, une décision parmi `HOLD`, `REQUEST_RECHECK` et `ESCALATE`, l'horodatage et l'empreinte SHA-256 du rapport de réconciliation canonique. La fonction `verify_review()` recalcule cette empreinte et signale les divergences de preuves sans jamais autoriser une reprise (`authorizes_resume: false`). Les identifiants de revue dupliqués sont refusés et les intentions demeurent `UNCERTAIN`.

**Limites de sécurité** : le journal n'authentifie pas l'identité déclarée, n'applique pas de RBAC, n'est pas signé et n'est pas inviolable face à un administrateur SQLite. Une vérification de l'empreinte ne prouve pas la véracité de la mesure d'origine. Ce mécanisme reste un contrôle de laboratoire, non une approbation de migration NAS en production.

## Politique RBAC du journal de revue (laboratoire)

Le module `odmm_linux_lab_review_policy.py` définit trois rôles : `observer` (aucune écriture), `reviewer` (`HOLD`, `REQUEST_RECHECK`) et `incident_lead` (ces deux décisions et `ESCALATE`). `record_review()` applique désormais cette politique avant toute insertion SQLite et refuse par défaut une identité non attestée (`identity_verified=False`). La décision `APPROVE_RESUME` reste interdite. Les tests couvrent les droits minimaux, le refus d'identité non vérifiée et le maintien de `UNCERTAIN`.

**Limitation importante** : `identity_verified=True` est une assertion fournie par l'appelant et ne constitue pas une authentification réelle. Aucun OIDC, certificat mTLS, signature d'identité, preuve RBAC distante ni protection contre un appelant compromis n'est intégré. L'API doit être confinée au laboratoire jusqu'à intégration d'un fournisseur d'identité et d'un contexte d'authentification non falsifiable.

## Assertions cryptographiques d'identité (laboratoire)

`odmm_linux_lab_review_identity.py` fournit des assertions HMAC-SHA256 à durée de vie limitée (1 à 900 secondes), liant l'identifiant opérateur, le rôle et les horodatages. `record_review()` exige désormais une assertion valide et une clé de vérification externe ; le booléen `identity_verified=True` seul n'autorise plus l'enregistrement. Les signatures sont comparées en temps constant et les assertions expirées ou futures sont rejetées.

**Restriction essentielle** : l'émetteur et le vérificateur partagent un secret. Toute entité possédant ce secret peut fabriquer une assertion ; aucune authentification OIDC, distribution de clé, rotation, anti-rejeu à usage unique ni attestation de l'émetteur n'est fournie. Les clés doivent rester hors du dépôt et hors des requêtes non fiables. Ce composant reste réservé au laboratoire isolé et ne certifie pas l'identité en production.

## Linux Compact — premier binaire portable autonome

Le workflow GitHub Actions `linux-compact-portable.yml` compile le point d'entrée de supervision `odmm_linux_compact_v22811.py` avec PyInstaller sous Ubuntu 24.04, puis assemble un ZIP `ODMM-Linux-Compact-Portable-v228.93.zip` comprenant l'exécutable, le source, cette documentation et des SHA-256. La première compilation a réussi dans le run 39668861592. Le smoke test vérifie le démarrage sans `python3` dans le PATH ; la qualification est désormais étendue au parcours `--demo-overview` avec données explicitement synthétiques. Le binaire n'est pas testé sur toutes les distributions ou versions de glibc et n'est pas un datamover NAS.

Pour utiliser le ZIP : extraire, vérifier `sha256sum -c 04-Manifests/SHA256SUMS` depuis le dossier `ODMM-Linux-Compact-Portable`, puis lancer `./01-Application/odmm-linux-compact --help` ou `--demo-overview`. La commande de démonstration ne réalise aucune connexion NAS.
