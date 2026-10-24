# ODMM V229.00 — Rollover HMAC à double signature (laboratoire Linux)

**Auteur : Abdelhalim Talbi** · 23 octobre 2026

## Objet et frontière de confiance

Les observations d'identité POSIX restent dans SQLite, tandis que l'ancre
HMAC v1 et les reçus de rotation sont stockés hors du périmètre de contrôle
du journal. Les clés et la politique d'état des clés sont fournies par des
services externes ; aucune clé ne doit figurer dans le dépôt, les artefacts,
les logs, les captures ou SQLite.

```text
SQLite (intent UNCERTAIN + observation)
    │
    ├── SHA-256 canonique de l'observation
    │
    ▼
Ancre immuable v1 [HMAC ancienne clé] ──┐
                                        ├── Reçu de rotation v1 (O_EXCL)
Résolveur de clés externe ──────────────┤     ├─ HMAC ancienne clé
Politique externe active/retired/revoked ┘     └─ HMAC nouvelle clé
                                              │
                                              ▼
                            Vérification en lecture seule
                            ≠ autorisation de reprise
```

## Contrat

- `create_rotation` exige une ancre d'origine déjà authentifiée, deux
  identifiants distincts et deux clés de 32 octets minimum. Il ne modifie
  jamais l'ancre d'origine ni le journal SQLite.
- Le reçu lie l'identifiant de l'intention, les identifiants de clés,
  l'empreinte SHA-256 de l'ancre d'origine et l'empreinte de l'observation
  SQLite. Les deux HMAC portent sur la même représentation JSON canonique.
- Publication exclusive `O_EXCL|O_NOFOLLOW`, permissions `0600`, `fsync`
  du fichier puis du répertoire. Un reçu déjà présent ne peut être écrasé.
- `verify_rotation` exige l'ancienne clé `active` ou `retired`, et la
  nouvelle clé `active`. `revoked`, absence de clé, erreur du fournisseur,
  lien symbolique, fichier non régulier, changement de chemin ou HMAC erroné
  sont refusés.
- Le statut `retired` signifie « interdite pour nouvelles signatures,
  conservée pour vérification historique ». Le statut `revoked` refuse
  également la vérification historique : une révocation de l'ancienne clé
  rend ce reçu non vérifiable jusqu'à une procédure de réattestation externe.
- Les retours contiennent toujours `authorizes_resume=False` et
  `nas_migration_qualified=False`. Les intentions `UNCERTAIN` ne sont
  jamais promues automatiquement.

## Qualification et limites

Exécuter sur Linux : `python3 -m unittest discover -s 09-Tools -p
'test_linux_lab_anchor_rotation.py' -v`. La matrice CI exécute la suite
sur les éditions Linux Full et Compact. Les tests vérifient les doubles
signatures, la non-réécriture, les clés erronées/révoquées, l'altération,
les symlinks, l'indisponibilité du coffre et la conservation de la quarantaine.

**Non couvert :** attestation cryptographique externe d'une politique de
révocation, protection contre la suppression des deux reçus, stockage WORM,
rotation multi-sauts, restauration d'une clé révoquée, crash au milieu de
la création du reçu, coupure électrique, rollback/ABA sur NAS, sécurité des
ACL NFSv4/NTFS, identité UID/GID/SID, xattrs, fidélité SMB, cluster
multiserveur et migrations de production. Ce module ne réalise aucune
migration NAS et ne fournit aucune preuve de performance NAS.

Les résultats CI, captures et artefacts doivent être vérifiés séparément :
un succès de test local ou CI ne démontre pas la qualification NAS réelle.
