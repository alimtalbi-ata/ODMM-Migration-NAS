# Audit approfondi ODMM V196.6 — architecture, modules, UI, CLI
Auteur : Abdelhalim Talbi

## Périmètre et méthode
Analyse statique AST des fichiers Python de V196.5, recherche des assets UI et fichiers de déploiement, revue ciblée des points d’entrée rotation et des collecteurs. Cet audit n’est ni un pentest, ni une qualification NAS.

## Inventaire vérifié
- 173 modules Python hors tests, 199 modules de tests, 228 fonctions publiques de module.
- Fichiers UI HTML/JS/CSS trouvés : 0.
- Fichiers de déploiement standard trouvés : 0.
- Suite précédente : 808 tests réussis ; les tests unitaires ne démontrent pas l’intégration produit.

## Points de rupture et plan correctif

### A01 — P0
Constat : No integrated web UI assets or deployable app entrypoint evidenced in audited source tree.
Correction : Create a single versioned API service and UI; integrate CLI against same API contracts.

### A02 — P0
Constat : Production rotation binding remains an opt-in adapter.
Correction : Ship and enforce one hardened production bootstrap with route lockdown and authenticated audit.

### A03 — P0
Constat : Vendor endpoint paths are illustrative and unqualified on real devices.
Correction : Maintain vendor+firmware contract test fixtures and real equipment certification matrix.

### A04 — P0
Constat : Native engine, approval and evidence gates have no proven full end-to-end integration.
Correction : Create E2E workflow: inventory, preflight, plan, dry-run, execute, verify, rollback, audit.

### A05 — P1
Constat : Signed manifest is HMAC shared-secret based; signing and verification authority may coincide.
Correction : Separate key custody, rotation and deployer permissions; evaluate asymmetric signatures.

### A06 — P1
Constat : SQLite ResourceWarnings in current test log.
Correction : Instrument and close connections explicitly; enforce warning-as-error tests.

### A07 — P1
Constat : No deployable Compact Windows/Linux parity demonstrated by audited source tree.
Correction : Build signed cross-platform CLI binaries and installation smoke tests.

### A08 — P1
Constat : No observable browser-to-API workflows demonstrated.
Correction : Provide job timeline, evidence explorer, vendor capabilities, approvals and accessibility tests.

## Architecture cible unique
Navigateur UI et CLI -> API versionnée commune -> AuthN/AuthZ -> Orchestrateur durable -> Moteur natif -> datamovers -> NAS; preuves, CMDB, audits et validations liés au même identifiant de migration.

## Ordre de livraison
1. V196.7 : API/CLI unifiés en lecture seule et vues état/qualifications, tests contractuels.
2. V196.8 : service déployable, RBAC, audit, journal des jobs et UI intégrée.
3. V196.9 : reprise crash-safe E2E, fault injection, tests ACL réels sur banc.
4. V197.0 : certification par firmware, matrice Windows/Linux, packaging et gate production.

## Critères de sortie
Une fonctionnalité n’est livrée que si elle est exposée dans l’API et le CLI, visible dans l’UI lorsqu’applicable, couverte par tests intégration et par traces auditables. Aucune autorisation implicite de cutover.
