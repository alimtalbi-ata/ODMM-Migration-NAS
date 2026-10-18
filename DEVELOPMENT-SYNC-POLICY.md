# ODMM — Politique de synchronisation des développements

Dépôt de référence : https://github.com/alimtalbi-ata/ODMM-Migration-NAS

Auteur : Abdelhalim Talbi

## Règles de livraison
- Les évolutions de code, tests, scripts de compilation et documentation sont synchronisées dans ce dépôt.
- Le code du dépôt doit correspondre à la version indiquée dans les manifestes et les archives cumulatives.
- Les éditions Linux Full, Linux Compact et Windows Compact restent distinctes et cohérentes.
- Chaque archive cumulative inclut les sources, les tests, les manifestes et les guides Word/PDF mis à jour.
- Les captures sont qualifiées comme réelles uniquement lorsqu'elles proviennent d'une exécution effective ; les illustrations fictives sont explicitement identifiées.
- Les exécutables Windows portables et installateurs ne sont déclarés disponibles qu'après compilation native et qualification.
- Le workflow Windows publie les artefacts de build et les preuves de qualification.
- Ne jamais commettre de secrets, jetons, mots de passe ou fichiers temporaires.
- Les changements sont accompagnés de tests et de résultats reproductibles.

## Point de départ
L'archive cumulative V228.77 est disponible séparément. La synchronisation complète de son contenu avec le dépôt doit être vérifiée avant une compilation présentée comme V228.77.
