# ODMM V228.71 — Qualification Windows Compact

Auteur : Abdelhalim Talbi

## Nouveautés
- Packaging version 7.9.27.
- Test d’installation silencieuse et de désinstallation sur runner Windows jetable.
- Refus du test si une installation existe déjà, afin de ne pas effacer une installation utilisateur.
- Rapport `binary/WINDOWS-INSTALL-SMOKE.json` et conservation des preuves en cas d’échec.
- Publication des exécutables uniquement après succès du workflow.

## Compilation Windows
Lancer `03-Build-Installation\BUILD-WINDOWS-COMPACT.cmd` sur Windows x64.
Sorties attendues : `binary/portable/ODMM-Compact.exe` et `binary/installer/ODMM-Compact-Setup-V7.9.27.exe`.
Le test d’installation est réservé à une machine Windows de CI jetable sans installation ODMM préexistante.

## Limites
Les binaires natifs ne sont pas précompilés dans cette archive. Le workflow GitHub Actions doit être exécuté dans un dépôt Windows compatible. Aucun test Windows réel n’a été exécuté dans cet environnement Linux.
