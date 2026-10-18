# ODMM Windows Compact — livraison cumulative V228.55

Client de supervision **en lecture seule**. Version interne du client : 7.9.12.

## Démarrer

Exécuter `03-Build-Installation\BUILD-WINDOWS-COMPACT.cmd` depuis Windows 10/11 x64 avec Python 3.10+ et Inno Setup 6. Ce script prépare un environnement virtuel, vérifie les dépendances, produit le portable puis l’installateur et contrôle les artefacts.

**Attention :** aucun exécutable Windows n'a été compilé ou testé nativement dans cette livraison.

## Interface

F5 ou Ctrl+R : actualiser. Ctrl+F : ouvrir et sélectionner la recherche, même depuis un autre onglet. Échap : effacer le filtre de recherche. Ctrl+Tab : changer d'onglet. Cliquer sur les en-têtes pour trier.

Le jeton API reste en mémoire et est effacé à la fermeture. La démonstration est fictive et ne déclenche aucune migration.
