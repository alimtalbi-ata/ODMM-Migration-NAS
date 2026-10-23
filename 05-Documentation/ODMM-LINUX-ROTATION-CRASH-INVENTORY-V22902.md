# ODMM V229.02 — Inventaire de crash des reçus HMAC (laboratoire Linux)

**Auteur : Abdelhalim Talbi** — 23 octobre 2026.

## Risque et objectif

La publication atomique de V229.01 utilise un fichier de préparation `*.pending-<32 hex>`, un hardlink exclusif vers le reçu final, puis la suppression du nom temporaire. Un SIGKILL peut survenir entre les frontières de synchronisation. Après le hardlink, le reçu final et le pending peuvent désigner le même inode (`st_nlink=2`). Un reçu cryptographiquement correct n'est alors pas suffisant pour déclarer la publication propre.

Cette évolution ajoute une inspection **strictement en lecture seule** de l'état de publication, puis impose l'état `FINAL_PRESENT_UNVERIFIED` avant et après l'authentification dual-HMAC. Il ne s'agit ni d'un garbage collector, ni d'un orchestrateur de reprise.

## Contrat de l'inspecteur

Module : `02-Sources/odmm_linux_lab_rotation_recovery.py`. API : `inspect_rotation_publication(anchor_dir, intent_id, to_key_id)`.

L'inspection épingle la chaîne complète des répertoires POSIX, énumère les pending correspondant à l'identifiant de reçu attendu, refuse les noms malformés, les symlinks, les fichiers non réguliers, les permissions groupe/autres, les tailles anormales, les liens inattendus et les inventaires excessifs. Elle contrôle la stabilité des inodes et du répertoire durant l'énumération. Elle n'ouvre pas les fichiers pour écrire et ne consulte pas les clés HMAC.

| Statut | Sens opérationnel |
| --- | --- |
| `ABSENT` | Aucun reçu final ni pending observé. Authentification refusée. |
| `PENDING_ONLY` | Préparation interrompue avant publication. Aucun nettoyage automatique. |
| `PUBLISHED_WITH_PENDING` | Deux noms vers le même inode ; fenêtre de crash après hardlink. Authentification refusée. |
| `UNRELATED_PENDING` | Un pending distinct coexiste avec le reçu final. Investigation requise. |
| `MULTIPLE_PENDING` | Plusieurs préparations : aucun choix automatique de la bonne version. |
| `UNSAFE_OR_UNAVAILABLE` | Anomalie, course ou indisponibilité : refus par défaut. |
| `FINAL_PRESENT_UNVERIFIED` | Topologie propre uniquement ; la vérification cryptographique et la politique externe restent obligatoires. |

Les réponses exposent `authorizes_resume=false` et `nas_migration_qualified=false` dans **tous** les cas. Le journal SQLite `UNCERTAIN` n'est jamais promu automatiquement. Les fichiers pending ne sont jamais supprimés par cette API.

## Qualification

`09-Tools/test_linux_lab_rotation_recovery.py` contient des régressions d'inventaire, de hardlinks, de symlinks et de limites d'énumération. Trois scénarios utilisent de **vrais SIGKILL sur des sous-processus de laboratoire jetables** : après fsync de préparation, avant hardlink, et immédiatement après hardlink. Chaque scénario vérifie l'absence d'authentification et la conservation de `UNCERTAIN`.

La matrice GitHub Actions exécute les mêmes tests pour Linux Full et Linux Compact. Une réussite CI démontre un comportement de processus POSIX local, **pas** une panne électrique, une garantie de fsync du stockage sous-jacent, un comportement NFS/SMB ni une migration NAS multiserveur. Aucune capture réelle d'interface, binaire V229.02 ou ZIP cumulatif n'est revendiqué par ce changement.

## Procédure opérateur (sans action destructive)

Isoler le répertoire d'ancres en lecture seule, sauvegarder la base SQLite WAL/SHM et les reçus, conserver les empreintes et la chaîne de garde, puis examiner la chronologie de crash. Une intervention manuelle sur les orphelins doit faire l'objet d'une procédure indépendante, approuvée, journalisée et testée. Ne pas renommer, écraser, supprimer ni rejouer une migration sur la seule base de cet inventaire.

## Risques résiduels

Une substitution ABA entre deux observations, un changement de mount namespace, une corruption matérielle, la compromission du fournisseur de clés et la non-atomicité entre SQLite et le système de fichiers restent hors du contrat. La qualification des ACL POSIX/NFSv4/NTFS, UID/GID/SID, xattrs, NFSv3/v4 et SMB sur deux serveurs demeure à réaliser avant tout usage de production.
