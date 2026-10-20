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

`02-Sources/odmm_linux_datamover_intents.py` enregistre chaque intention avant tout effet externe, sous un identifiant unique, avec l'identifiant de tâche, le propriétaire, le jeton de fencing et l'empreinte SHA-256 canonique du contenu. Les états sont `PREPARED`, `IN_FLIGHT`, `UNCERTAIN`, `VERIFIED` et `ABORTED`. **Les transitions vers VERIFIED et ABORTED ne sont pas encore exposées** : aucune opération NAS ne peut être considérée vérifiée par ce composant.

Le contrat impose de persister `PREPARED`, puis `IN_FLIGHT` **avant** d'autoriser un éventuel effet externe. Au redémarrage, `quarantine_unfinished()` transforme les opérations `IN_FLIGHT` en `UNCERTAIN` ; elles nécessitent une inspection des données et métadonnées cibles avant toute décision de reprise. Le journal refuse la réutilisation d'un identifiant d'intention avec une autre empreinte et contrôle le jeton de réservation lors des transitions.

**Limites** : SQLite `synchronous=FULL` et le journal WAL doivent être configurés par l'installeur/exploitant ; les tests de réouverture ne sont pas des essais de coupure électrique. L'empreinte SHA-256 protège l'identité de l'intention, pas l'intégrité d'un fichier NAS. Aucun protocole d'acknowledgment distant, fencing cible, moteur de copie ni vérification d'accès effectif n'est intégré à ce stade. Une validation humaine doit précéder la sortie de `UNCERTAIN`.
