# ODMM V228.74 — Qualification Windows native

## Etat reel
Le ZIP source ne contient aucun EXE Windows precompile. Le workflow est configure mais n’a pas ete execute dans cet environnement.

## Execution
1. Publier ce contenu dans un depot GitHub autorise.
2. Ouvrir Actions > ODMM Windows Compact native build V228.74 > Run workflow.
3. Examiner le journal des etapes de compilation, de lancement et d’installation.
4. Recuperer l’artefact `ODMM-V228.74-Windows-qualified-cumulative` uniquement si le workflow est vert.
5. Confirmer dans le ZIP qualifie `binary/portable/ODMM-Compact.exe` et `binary/installer/ODMM-Compact-Setup-V7.9.29.exe`.

## Diagnostics
En cas d’echec, telecharger `ODMM-V228.74-Windows-failure-evidence`. Le rapport runner contient la version Python, l'OS et l'identifiant de run. Ne jamais declarer un binaire qualifie sur la seule base de controles statiques Linux.

## Limites
La validation sur un runner Windows Server 2022 ne remplace pas les essais Windows 10 et Windows 11 sur machines representatives.
