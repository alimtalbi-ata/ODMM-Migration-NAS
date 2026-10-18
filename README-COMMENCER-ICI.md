# ODMM V228.76 — Windows build evidence gate

Cette livraison fournit les sources et le workflow de compilation Windows, **pas les binaires natifs**.

La qualification Windows reste à exécuter sur un runner Windows. Les preuves d’installation, désinstallation, intégrité et provenance doivent être présentes avant la création du ZIP qualifié.

Point d’entrée : `03-Build-Installation/BUILD-WINDOWS-COMPACT.cmd`. Sorties attendues : `binary/portable/` et `binary/installer/`.
