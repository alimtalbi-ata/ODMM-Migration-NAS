# ODMM V228.73 — Packaging de livraison Windows qualifiée

Cette version ajoute une étape de CI qui crée **une seconde archive cumulative qualifiée** après compilation Windows native, contrôle des empreintes et test d'installation/désinstallation. Le ZIP source livré ici ne contient **aucun EXE précompilé**.

## Lancement
Déclencher le workflow `ODMM Windows Compact native build` dans GitHub Actions (Windows Server 2022). Le workflow génère les deux exécutables dans `binary/`, exécute les tests et téléverse l'archive `ODMM-V228.73-Windows-Qualified-Cumulative.zip` uniquement en cas de succès.

## Limites
Le runner GitHub Actions n'a pas été exécuté ici. Aucun résultat de compilation, d'installation ou de désinstallation native n'est revendiqué. Le test de démarrage GUI sur runner ne garantit pas une recette interactive Windows 10/11.

## Contrôles
Le script `PACKAGE-WINDOWS-RELEASE.py` exige la validation du manifeste SHA-256 et du rapport de tests natifs avant création du ZIP. Les fichiers de build temporaires et `.git` sont exclus. Le moteur de migration est inchangé.
