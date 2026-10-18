# ODMM V188.4 — Qualification de témoin sur deux hôtes Debian 13

Auteur : Abdelhalim Talbi

## Prérequis

- Hôte A : client ODMM ; hôte B : témoin distinct (administration, sauvegardes et clés indépendantes).
- Réseau TCP autorisé uniquement de A vers B sur le port du témoin.
- Certificats mTLS, CA et clés HMAC distinctes, droits 0600 sur les clés.
- Déployer le service `ldaps_witness_daemon.py` avec le modèle systemd de V187.7.
- Vérifier manuellement la séparation administrative et la politique de sauvegarde.

## Vérification initiale (sur A)

Exécuter depuis le répertoire racine du ZIP (remplacer les valeurs) :

```bash
python3 ldaps_two_host_runbook.py \
  --host witness.example.internal --port 9443 \
  --ca /etc/odmm/ca.pem --cert /etc/odmm/client.pem --key /etc/odmm/client.key \
  --witness-hmac-key-file /etc/odmm/witness-hmac.key \
  --report-hmac-key-file /etc/odmm/report-hmac.key \
  --expected-count 1 --expected-last-mac "$(cat /secure/expected-head.txt)" \
  --incident-id QUAL-001 --output /secure/qual-001.json --operator-confirmed
```

Le résultat est un rapport signé HMAC ; il ne valide PAS l'indépendance de l'hôte ni une autorisation de cutover.

## Scénarios manuels à consigner

1. **Baseline** : exécuter le contrôle initial ; noter l'heure, le certificat et le digest du rapport.
2. **Coupure réseau** : sur l'infrastructure de test seulement, bloquer temporairement le flux A→B. Le contrôle doit échouer, sans rapport de réussite. Rétablir le flux puis relancer avec un nouveau nom de rapport.
3. **Redémarrage** : sur B, avec approbation d'exploitation, `sudo systemctl restart odmm-witness.service` (adapter au nom réel de l'unité). Vérifier `systemctl is-active` et comparer les preuves après reprise.
4. **Restauration ancienne** : dans un environnement isolé, restaurer un état antérieur du registre A ; vérifier que la comparaison avec B refuse toute divergence.
5. **Audit** : archiver les rapports signés, empreintes, journaux systemd et approbations hors du domaine restauré.

Ne jamais exécuter de coupure, restauration ou redémarrage sur une production non autorisée. Les scénarios 2 à 4 ne sont pas exécutés automatiquement par le kit.

## Critères de sortie

- Rapports signés valides, identité du serveur vérifiée et aucune divergence.
- Preuve d'indépendance administrative documentée et revue par un opérateur.
- Coupure réseau et reprise effectivement testées sur les deux machines.
- **Aucune publication, réparation, migration ou bascule automatique.**
