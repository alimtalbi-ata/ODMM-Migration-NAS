# ODMM V207.7 — NAS source/cible : cluster, snapshots, virtualisation et qualité
Auteur : Abdelhalim Talbi

## 1. Topologie et cluster
Identifier les nœuds, HA pairs, quorum, protocol LIF/VIP, DNS, namespaces globaux, volumes, pools, placement et chemins clients. Ne jamais utiliser une IP de nœud comme identité logique durable. Les bascules peuvent entraîner reconnexions SMB, états NFS, changement de chemins, invalidation de cache, latence et doublons apparents. Qualifier le comportement des handles SMB durables/persistants et verrous, leases/oplocks, NFSv4 state/locks, NFSv3 stateless, sessions et grace period, selon configuration réellement observée. Tester failover et failback avec charge, mesurer RTO, erreur I/O, perte de verrou et progression idempotente.

## 2. Snapshots, clones et réplication
Distinguer snapshot crash-consistent, filesystem-consistent et application-consistent (quiesce); une image instantanée n'est pas automatiquement une image cohérente de bases ou de VMs. Décider snapshot de départ, incrémentaux, gel des écritures et fenêtre de conservation. Mesurer COW/ROW, pression espace, réserve, fragmentation, déduplication/compression et performance des lectures de snapshots. Sur cible, planifier snapshots de protection sans les confondre avec une preuve de migration. Ne jamais supprimer automatiquement des snapshots ni déduire la possibilité de rollback de leur simple existence. Snapshots de fournisseur souvent non portables : recréer la politique sur cible, conserver les anciens sur source selon rétention validée.

## 3. Virtualisation NAS
Distinguer SVM/vserver, NAS VM, namespaces de conteneurs, passerelles, exports virtuels, jonctions et pools physiques. Inventorier tenant, namespace, volume, quotas, snapshots, politiques et backend; comparer l'isolation et les chemins logiques source/cible. Les ACL de partage SMB et les ACL fichiers sont deux plans distincts. Contrôler les collisions de noms, casse Unicode, liens symboliques, junctions, hardlinks, xattrs et ADS.

## 4. Fidélité ACL et identités
Capturer avant/après des ACL brutes et canoniques, ordre ACE, héritage, owner/group, SID/UID/GID, domaines AD/LDAP, idmap, NFSv4 ACL et POSIX ACL, permissions share/export, root squash et accès effectifs. Vérifier les utilisateurs/groupes représentatifs, y compris deny, nested groups, comptes orphelins, changement de domaine et accès multiprotocole. Une copie bit-à-bit ne garantit pas les droits. Toute conversion NTFS↔NFSv4↔POSIX exige une qualification explicite, pas de mapping implicite.

## 5. Performance, cohérence et bascule
Établir une baseline ops/s, MB/s, latence p50/p95/p99, IOPS, métadonnées, CPU, mémoire, réseau, snapshot COW, cache, taux de changement, taille/quantité de fichiers. Mesurer le débit **soutenable** sous charge, non le débit de pointe. Pour converger en incrémental, débit de copie > débit de changement ; prévoir une marge et une fenêtre de gel si nécessaire. Gouverneur ODMM : plafonds de bande passante, opérations/s, concurrence par share/volume/tenant, backoff sur latence, équilibrage de datamovers et priorité production. Tester charge pendant failover et pendant snapshot/replication, ainsi que comparaison hash + métadonnées et delta final.

## 6. Plan de qualification
1. Inventaire read-only source/cible et firmware, version, configuration réelle, topologie.
2. Cartographie des namespaces, volumes, clusters, tenants, snapshots, ACL et identités.
3. Évaluation de compatibilité spécifique à la paire et au protocole; preuves datées et traçables.
4. Préflight ACL, accès effectifs, données ouvertes, snapshot cohérent et capacité COW.
5. Simulation et mesures sous charge ; test failover, reprise, interruption et idempotence.
6. Copie native ODMM, incrémentaux, validations par échantillon et contrôles exhaustifs ciblés.
7. Gel contrôlé, delta final, vérification, décision humaine, bascule et plan de rollback.
8. Vérification post-bascule, SLA, accès applicatifs, surveillance et conservation des preuves.

## 7. Spécificités fournisseurs à qualifier
NetApp ONTAP : SVM, LIF, FlexVol/FlexGroup, Snapshot, SnapMirror, export policy et security style; Dell PowerScale : OneFS, SmartConnect, access zones, snapshots, SyncIQ; Dell Unity : NAS servers, filesystems, replication/snapshots; Pure FlashBlade : blades, file systems, snapshots/replication; IBM Storage Scale : CES, filesets, AFM, ACL; HPE, Hitachi HNAS : namespaces, cluster, replication, ACL; TrueNAS, Synology, QNAP : pools/datasets, snapshots, SMB/NFS et idmap. Ces exemples sont des **axes de découverte**, non une certification d'une version ni une preuve de compatibilité. Toujours recouper avec les datasheets, guides d'administration et matrices support de la version/firmware exacts.

## 8. Implémentation V207.7 et limites
`odmm_nas_topology_v2077.py` ajoute un moteur d'évaluation read-only et fail-closed pour inventaire, cluster, snapshots, virtualisation, ACL, preuves, convergence delta et latence. Il ne collecte pas lui-même les informations des appliances et ne déclenche aucune migration, snapshot ou cutover. Son état le plus favorable est `READY_FOR_HUMAN_REVIEW`, jamais une autorisation automatique. Tests unitaires sur données synthétiques; qualification matérielle et mesure de performance réelles restent à faire.
