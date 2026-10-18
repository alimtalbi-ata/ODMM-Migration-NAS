# Open Data Migration Manager (ODMM) — Démarrer ici

Auteur : **Abdelhalim Talbi**

## Éditions et périmètre
- **Windows Compact** : console de supervision **en lecture seule**, pas un moteur de migration.
- **Linux Compact** : outils de contrôle local, selon composants disponibles.
- **Linux Full** : composants d'orchestration/migration en cours de qualification. Ne pas supposer la compatibilité ACL/NFS/SMB sur NAS réel sans preuves spécifiques.

## Télécharger Windows Compact
La compilation Windows est automatisée dans [GitHub Actions](https://github.com/alimtalbi-ata/ODMM-Migration-NAS/actions/workflows/windows-compact-release.yml). Les exécutions réussies publient :
- `ODMM-V228.77-Windows-binary` : EXE portable et installateur ;
- `ODMM-V228.77-Windows-qualified-cumulative` : ZIP cumulatif incluant binaires, sources, documentation et rapports.

Dernière compilation vérifiée lors de cette mise à jour : [#17](https://github.com/alimtalbi-ata/ODMM-Migration-NAS/actions/runs/39144790119), réussie sur runner Windows. Vérifier les exécutions plus récentes avant téléchargement.

**Portabilité :** tests automatisés Tcl/Tk, démarrage isolé sans sources et sans Python dans le PATH, installation/désinstallation silencieuses. La compatibilité sur un autre PC Windows propre doit être validée séparément ; le résultat CI n'en est pas une preuve universelle.

## Compiler sur Windows
Point d'entrée supporté : `03-Build-Installation/BUILD-WINDOWS-COMPACT.cmd`. Prérequis **de compilation** : Python 3.11, PyInstaller 6.16.0 (installé par le script) et Inno Setup 6. Les postes utilisateurs ne doivent pas avoir besoin de ces outils. Sorties : `binary/portable/` et `binary/installer/`.

## Architecture, dette technique et évolutions
Lire [l'audit d'architecture et la feuille de route V228.78–V231](06-Documentation/AUDIT-ARCHITECTURE-ROADMAP-V228.78.md). Les déplacements et consolidations y sont **proposés**, pas encore appliqués.

## Sécurité et limites
Ne pas utiliser de migration de données sensibles ou de cutover de production avant qualification réelle de la fidélité ACL/identités, de la reprise, des vérifications source/cible et du rollback. Distinguer démonstration, simulation, validation automatisée et tests sur équipements réels.
