# ODMM V229.01 — Publication atomique des reçus HMAC (laboratoire Linux)

**Auteur : Abdelhalim Talbi** — 23 octobre 2026.

## Problème corrigé

V229.00 écrivait directement le reçu final avec O_EXCL. Une panne ou un SIGKILL entre l'ouverture et la fin de l'écriture pouvait laisser un reçu tronqué permanent, impossible à remplacer. Le vérificateur échouait alors correctement, mais la rotation devenait bloquée sans intervention manuelle.

## Nouveau protocole de publication

1. Vérifier l'ancre externe existante et exiger deux secrets HMAC distincts.
2. Sérialiser et signer le reçu en mémoire.
3. Ouvrir exclusivement un fichier de préparation à nom aléatoire dans le répertoire ancré (0600, O_NOFOLLOW, dir_fd).
4. Écrire le reçu intégral, flush et fsync du descripteur de préparation.
5. Revalider l'identité de l'inode et la chaîne des répertoires.
6. Publier atomiquement avec un hardlink exclusif vers le nom final ; jamais de remplacement d'un reçu existant.
7. fsync du répertoire, supprimer seulement notre propre inode temporaire, fsync du répertoire à nouveau.

**Sécurité des échecs :** une panne avant le hardlink ne publie aucun reçu final. Un SIGKILL peut laisser un fichier pending orphelin ; il est ignoré par le vérificateur. Une panne entre le hardlink et la suppression du pending peut laisser deux liens vers le même inode : la vérification refuse alors le reçu (nlink != 1). Une panne de fsync après publication laisse la durabilité incertaine : aucune migration ou reprise n'est autorisée. La réparation d'orphelins doit être une procédure manuelle auditée, jamais un nettoyage automatique aveugle.

Le répertoire d'ancres et le fournisseur de clés doivent être administrés indépendamment du journal SQLite et protégés contre les écritures adverses. Les hardlinks supposent un système de fichiers local POSIX compatible ; **pas de garantie de durabilité NFS/SMB ou multiserveur**.

## Qualification

Six nouveaux tests de laboratoire POSIX local couvrent la visibilité atomique, l'échec du hardlink, l'échec fsync de préparation, le doublon, les clés identiques et les fichiers pending orphelins. Ils s'ajoutent aux tests historiques via le workflow Linux Full/Compact existant.

Statuts à vérifier dans GitHub Actions après publication. Tests unitaires locaux, CI et qualification NAS de production ne sont pas équivalents. Aucun exécutable autonome ni capture UI réelle n'est revendiqué pour cette modification.

## Suites recommandées

Tester les crashs SIGKILL à chaque frontière fsync/link/unlink avec réouverture SQLite ; formaliser une procédure de réconciliation manuelle des pending ; qualifier ensuite les vrais partages NFSv3/v4 et SMB sur deux serveurs isolés sans toucher à la production.
