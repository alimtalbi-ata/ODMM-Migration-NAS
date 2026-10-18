# ODMM V228.75 — Contrat de compilation Windows

Version packaging : 7.9.30. Auteur : Abdelhalim Talbi.

## Changements vérifiables
- Version alignée entre script CMD, nom de l’installateur et tests du workflow.
- Nouveau contrôle `CHECK-WINDOWS-RELEASE-CONTRACT.py` exécuté avant le build sur runner Windows.
- Refus explicite d’une dérive de version ou de l’absence des contrôles de qualification.

## Génération
Sous Windows 10/11 x64 : `03-Build-Installation\BUILD-WINDOWS-COMPACT.cmd`.
Sorties attendues après succès : `binary/portable/ODMM-Compact.exe` et `binary/installer/ODMM-Compact-Setup-V7.9.30.exe`.

## Limites et preuves
La compilation native, l’installation et la désinstallation n’ont pas été exécutées dans cet environnement Linux. Aucun binaire Windows réel n’est présent. La documentation Word/PDF historique est conservée, mais **n’est pas actualisée pour V228.75**. Aucune capture Windows réelle n’est revendiquée.
