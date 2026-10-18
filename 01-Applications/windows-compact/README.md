# ODMM Windows Compact — édition de supervision

Auteur : Abdelhalim Talbi

## Fonction
Client de supervision **en lecture seule**. L'interface n'exécute pas de migration NAS. Le client peut nécessiter l'accès au serveur ODMM pour afficher les jobs.

## Installation
Pour les utilisateurs Windows 10/11 x64, télécharger l'artefact `ODMM-V228.77-Windows-binary` depuis la [compilation Windows #17 qualifiée](https://github.com/alimtalbi-ata/ODMM-Migration-NAS/actions/runs/39144790119), ou depuis une exécution plus récente réussie. Choisir le portable ou l'installateur. Aucun Python ni source n'est requis pour exécuter l'EXE produit par le workflow.

Pour les développeurs : `03-Build-Installation/BUILD-WINDOWS-COMPACT.cmd` nécessite Python 3.11 et Inno Setup 6. Le workflow installe les outils de compilation sur un runner Windows et qualifie Tcl/Tk, démarrage GUI isolé, installation/désinstallation.

## Utilisation
F5 ou Ctrl+R : actualiser. Ctrl+F : recherche. Échap : effacer le filtre. Ctrl+Tab : changer d'onglet. En-têtes du tableau : tri.

## Limites
La compilation GitHub sur Windows Server 2022 ne remplace pas une validation sur un PC Windows propre. Le mode démonstration est fictif et ne déclenche pas de migration. Les tests réels doivent être documentés comme tels.

## Architecture et rationalisation
Voir `06-Documentation/AUDIT-ARCHITECTURE-ROADMAP-V228.78.md`. Le point d'entrée actuel reste `02-Sources/odmm_windows_compact_v22811.py` ; la séparation UI/services est planifiée sans rupture.
