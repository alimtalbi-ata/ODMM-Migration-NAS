# ODMM — Audit technique indépendant du prototype V188.8
Auteur : Abdelhalim Talbi
Statut : audit statique ciblé et correctif limité ; **pas une qualification production**.

## Périmètre et méthode
Examen des sources Python du répertoire cumulatif V188.8, README, tests, collecteurs, registre SQLite et chaîne de preuves. Comparaison documentaire avec les capacités déclarées de Komprise Elastic Data Migration et NetApp XCP. Aucun accès à des NAS réels, aucune charge 150–500 To, aucune vérification AD/LDAP réelle. Aucune application Web/dashboards HTML/JS/CSS intégrée identifiée dans ce paquet ; l'ergonomie visuelle n'a donc pas été évaluée.

## Résultat exécutif
**Maturité : prototype de contrôle et qualification, non produit de migration complet.** Les centaines de modules et tests ne démontrent pas un moteur de migration haute performance de bout en bout. Éviter de confondre conformité de schéma de preuve, fidélité effective ACL et succès réel d'une migration.

## Constats prioritaires

### P0 — Défaut TOCTOU dans le collecteur V188.7 — CORRIGÉ DANS CETTE BRANCHE
`ldaps_two_host_observation.collect_local` faisait `is_symlink`, `is_file`, `stat`, puis `read_bytes`: le chemin pouvait changer entre contrôle et ouverture et la lecture n'était pas bornée au niveau du descripteur. Désormais la branche `file_sha256` utilise `ldaps_observation_hardened.observe_file`: O_NOFOLLOW, fstat, lecture limitée, contrôle d'identité avant/après. Limites : composants de chemin parents, montages, modifications furtives et preuves non immuables ne sont pas totalement couverts. 26 tests ciblés réussis.

### P0 — Qualification du moteur natif — NON DÉMONTRÉE
Le paquet examiné privilégie les politiques, registres, preuves et mécanismes de refus. Une migration de production nécessite des transferts natifs NFS/SMB mesurés, ACL/xattr/ADS/owner, reprise par fichier, vérification source/cible, gestion des fichiers ouverts et stratégie de cutover validée. Aucun benchmark multi-NAS réel n'est fourni. Maintenir les outils externes en complément/fallback explicite et jamais silencieux.

### P0 — Chaîne de confiance des preuves — PARTIELLE
HMAC et témoins distants améliorent la détection d'altération, mais les clés, l'horodatage, l'identité de l'opérateur et l'indépendance du domaine de sauvegarde doivent être prouvés. Une signature d'attestation ne prouve pas qu'un scénario a été réellement exécuté. Les API historiques contournables doivent être inventoriées et dépréciées.

### P1 — SQLite et concurrence — À INDUSTRIALISER
Tester chaque transaction et fermeture explicite de connexion. Les ResourceWarning d'objets SQLite non fermés sont des signaux d'hygiène à traiter. Définir les limites de SQLite par composant : contrôle local mono-nœud acceptable, mais coordination multi-datamover et quorum ne doivent pas dépendre d'une base partagée sur NFS. Ajouter fault injection, kill -9, crash avant/après commit, corruption WAL, sauvegarde cohérente et migration de schéma.

### P1 — ACL et identité — À PROUVER EN LABORATOIRE
Comparer ACL structurelles et droits effectifs sous de vrais comptes AD/LDAP et groupes imbriqués, sur matrices NFSv3/NFSv4/SMB avec variations fournisseurs et firmware. Bloquer les droits supplémentaires sur cible et préserver héritage, propriétaire, audit, ADS/xattr, hardlinks, symlinks, sparse files et timestamps suivant le protocole.

### P1 — Dashboard et API — NON ÉVALUABLES DANS LE PAQUET
Aucun portail Web intégré identifiable. Prévoir un cockpit opérateur : inventaire source/cible, matrice de compatibilité, capacité et performance, files d'attente, état des jobs, débit et IOPS, ETA avec intervalle de confiance, backlog, fichiers échoués, risque ACL, gouverneur QoS, fenêtre de cutover, traces d'audit et plan de rollback. Afficher distinctement SIMULÉ / OBSERVÉ / QUALIFIÉ / BLOQUÉ.

### P1 — Observabilité et performance — NON PROUVÉES
Mesurer fichiers/s, octets/s, ops/s, p50/p95/p99 de latence, taux d'erreur, retry, taille de backlog, occupation CPU/RAM, latence source/cible, impact QoS. Tester petites tailles, millions de fichiers, ACL complexes, latence WAN, interruptions réseau et saturation. Baselines comparables face à XCP, rsync/Robocopy et autres outils, à matériel et dataset identiques.

### P2 — Qualité logicielle et packaging
Remplacer la suite monolithique fragile par CI en couches : lint/type-check, tests unitaires rapides, tests de contrats, tests de concurrence, intégration locale, intégration multi-hôtes, performance et qualification fournisseur. Éliminer les imports implicites entre modules, définir API publique versionnée, SBOM, signature des artefacts, scans dépendances, support Windows/Linux et procédures d'upgrade/rollback.

## Feuille de route proposée
1. **R0 : stopper l'accumulation de fonctionnalités** et figer une baseline reproductible ; corriger ResourceWarning, tests bloquants, chemins non durcis, documentation des API.
2. **R1 : moteur natif E2E minimal prouvé** : source/target POSIX en sandbox, planification durable, checkpoint par fichier, reprise après kill, checksums et comparaison métadonnées, sans prétendre qualifier NAS.
3. **R2 : pilotes NFS et SMB réels** et matrice ACL/identités AD-LDAP avec tests d'accès effectifs ; aucun cutover sans validation.
4. **R3 : gouverneur de ressources et datamovers multiples** avec fencing, ownership, leases, reprise et simulation de partition réseau.
5. **R4 : cockpit produit et API** avec RBAC, traçabilité, états opérateur explicites et rapports détaillés.
6. **R5 : qualification marché** : bancs de charge comparatifs, tests 150/300/500 To progressifs, multi-vendeurs et essais de restauration/cutover supervisés.

## Critères de sortie production
Zéro perte de données détectée ; pas de dérive ACL ou élévation de privilèges ; reprise idempotente ; aucune migration/cutover sans approbation ; observabilité complète ; résultats reproductibles sur équipements et firmware documentés ; tests de rollback réels ; exploitation sécurisée et documentée.

## Sources publiques de comparaison
- Komprise : https://www.komprise.com/product/elastic-data-migration/
- Komprise migration guide : https://www.komprise.com/guides/data-migration-guide/
- NetApp XCP NFS verify : https://docs.netapp.com/us-en/xcp/xcp-nfs-reference-verify.html
- NetApp XCP SMB verify : https://docs.netapp.com/us-en/xcp/xcp-smb-reference-verify.html

## État de validation
Tests ciblés `test_ldaps_two_host_observation` + `test_ldaps_observation_hardened`: 26 OK. Suite complète : non confirmée sur cette branche dans le délai disponible. La suite du répertoire original V188.8 possède un ancien journal indiquant 1970 tests OK (27 ignorés), mais ce journal ne qualifie pas la branche corrigée.
