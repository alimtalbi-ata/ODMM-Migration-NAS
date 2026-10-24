# ODMM V229.03 — Revue forensique non destructive des reçus HMAC orphelins

**Auteur : Abdelhalim Talbi** — 23 octobre 2026.

## Fonctionnalité

\`02-Sources/odmm_linux_lab_rotation_review.py\` expose \`review_rotation_orphans(anchor_dir, intent_id, to_key_id)\`. Cette API est **strictement en lecture seule** et ne modifie ni SQLite, ni les ancres, ni les fichiers pending. Elle enrichit l'inventaire de crash V229.02 par un SHA-256 borné du contenu de chaque reçu final et pending, ainsi que ses identités de fichier (device/inode), taille et nombre de hardlinks.

La vérification refuse les liens symboliques, permissions groupe/autres, tailles > 32 KiB, fichiers non réguliers, mutations durant la lecture et changements de répertoire. Les ancêtres sont épinglés par des descripteurs, avec vérifications avant et après la lecture. L'état de publication est réinspecté avant d'émettre un manifeste.

## Contrat de confiance et réponse

Le champ \`untrusted_inventory_sha256\` est **un simple condensat de comparaison** d'un manifeste JSON canonique : il n'est **ni signé ni authentifié**. Ne pas l'utiliser comme preuve de chaîne de garde indépendante, comme approbation de suppression ou comme autorisation de reprise. L'authentification des reçus nécessite toujours le vérificateur dual-HMAC, des clés externes et la politique de révocation.

Chaque réponse conserve \`requires_operator_review=true\`, \`authorizes_cleanup=false\`, \`authorizes_resume=false\` et \`nas_migration_qualified=false\`. En cas de course ou d'anomalie : \`inventory_complete=false\`, \`status=UNSAFE_OR_UNAVAILABLE\`, aucun manifeste. Les pending ne sont **jamais** supprimés. Les opérations SQLite \`UNCERTAIN\` ne sont jamais promues.

## Qualification et reproductibilité

Commande locale : \`python3 -m unittest discover -s 09-Tools -p 'test_linux_lab_rotation_review.py' -v\`.

Dix scénarios isolés couvrent absence, pending unique, hardlink après publication, pending indépendant, plusieurs pending sans final, final propre, symlink, permissions, mutation concurrente et limite de taille. La réinspection des métadonnées de chaque inode après hachage détecte également une mutation tardive d'un fichier déjà lu. GitHub Actions exécute ces scénarios dans la matrice Linux Full et Linux Compact. La qualification atteste un laboratoire POSIX local et des tests logiciels, **pas** une migration NFSv3/v4 ou SMB, ni une panne électrique, ni une fidélité ACL/UID/GID/SID/xattrs, ni une release installable.

## Procédure opérateur

Geler les écritures sur une copie forensique, préserver SQLite avec WAL/SHM, journaliser séparément l'origine et les empreintes de sauvegarde, exécuter l'inventaire sur la copie et comparer les métadonnées. Toute intervention sur un pending nécessite approbation humaine indépendante et procédure dédiée. Ce module n'effectue aucune remédiation.

## Limites

Une substitution ABA et une compromission de l'hôte ne sont pas éliminées ; un SHA-256 non authentifié est recalculable. Les inodes et timestamps ne constituent pas une identité globale NAS. Aucune capture d'application réelle, binaire autonome, archive cumulative ni qualification multiserveur n'est produite par ce changement.
