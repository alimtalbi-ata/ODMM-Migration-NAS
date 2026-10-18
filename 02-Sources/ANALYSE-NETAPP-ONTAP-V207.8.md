# ODMM V207.8 — NetApp ONTAP en priorité
Auteur : Abdelhalim Talbi

## Découverte et qualification (lecture seule)
Inventorier version ONTAP, nœuds et état HA, SVM, volumes FlexVol/FlexGroup, junction paths, LIF data, protocoles et clients, exports NFS et partages SMB, security styles (UNIX/NTFS/mixed), ACL effectives, quotas, snapshots, SnapMirror, SnapLock/WORM, chiffrement, tiers FabricPool, QoS, thin provisioning et capacité libre. **Le collecteur V207.8 implémente seulement quatre appels REST de base** (cluster, nœuds, SVM, volume) et marque le reste inconnu jusqu'à qualification. Les champs exacts REST dépendent de la version ONTAP : vérifier la documentation Swagger de l'appliance avant usage réel.

## HA, cluster et namespace
Préférer SVM + namespace logique + LIF de données plutôt qu'IP d'un nœud. Cartographier les propriétaires des agrégats, la mobilité des volumes et des LIF, les chemins SMB/NFS, les paires HA et les politiques de failover. Répéter un failover contrôlé avec clients pilotes; mesurer reconnexion SMB durable/persistent handles, NFS lock recovery, sessions et impacts de coupure. Ne pas supposer que toutes les variantes SMB/NFS ont les mêmes garanties.

## Snapshots et réplication
Découvrir politiques Snapshot, rétention, espace disponible, snapshots verrouillés, dépendances SnapMirror et RPO/RTO. Les snapshots ONTAP ne garantissent pas à eux seuls la cohérence applicative. Pour les applications transactionnelles, utiliser quiesce/consistency groups adaptés et valider un test de restauration. Prévoir l'amplification de capacité lors des changements, la cadence des incrémentaux et le coût des rescans.

## Virtualisation et qualité des ACL
Le SVM constitue une frontière de configuration et d'identité; documenter DNS, AD, LDAP, Kerberos, name-mapping UNIX/Windows, UID/GID/SID, export policies, SMB share ACL, NTFS/NFSv4 ACL, héritage et effective access. Sur security style mixed, qualifier les conversions et effets de dernière écriture. Tester des identités représentatives et des cas de refus, depuis les clients des deux protocoles; comparer propriétaire, mode, ACL brutes, ADS/xattrs, liens et timestamps. Les outils de copie externes ne doivent pas remplacer silencieusement le moteur ODMM natif.

## Performance
Mesurer source et cible séparément : IOPS, latence p95/p99, débit, opérations de métadonnées, CPU, saturation réseau, QoS, charge des contrôleurs, nombre de fichiers, arborescence et ratio petits fichiers. Tenir compte des snapshots, du tiering, de FlexGroup et de la réplication; plafonner le nombre de workers, les opérations/s et le débit selon les fenêtres métier. Définir des seuils de ralentissement/pause automatiques et un test de convergence du delta.

## Gate de migration
1. Discovery source/cible (avec provenance et horodatage), état de santé et version supportée.
2. Preflight ACL/identité, espace, cohérence snapshot, cluster, LIF, namespace et dépendances.
3. Baseline et dry-run avec mesures d'impact.
4. Copie native, incrémentaux et vérification des contenus/métadonnées/accès effectifs.
5. Simulation HA et restauration, validation de la fenêtre de bascule et du rollback.
6. Autorisation humaine explicite et audit immuable; aucune bascule automatique sur simple inventaire.

## État de réalisation V207.8
Implémenté : modèle d'inventaire REST de base, refus en cas de données absentes ou d'API indisponible, combinaison avec le gate NAS V207.7, tests synthétiques. Non implémenté : authentification ONTAP intégrée, collecte LIF/export/SMB/ACL/SnapMirror/FlexGroup/SnapLock, tests sur appliances, qualification de compatibilité par firmware, intégration au portail. Les tests ne constituent pas une certification constructeur.
