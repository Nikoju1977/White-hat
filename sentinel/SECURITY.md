# Politique de sécurité du prototype

**AEGIS Sentinel 0.2 n'est ni certifié ni inviolable.** Son déploiement en production exige revue du code, durcissement de l'hébergement, tests d'intrusion autorisés, sauvegardes et supervision de l'infrastructure.

## Configuration sûre

- Initialiser avec `python -m aegis.cli init` ; clés générées localement, jamais de mot de passe par défaut.
- Restreindre les permissions des fichiers `.env`, `.agent.env` et `data/` (ACL Windows ou chmod Unix).
- Conserver FastAPI sur `127.0.0.1`. Pour consulter depuis un autre appareil : reverse proxy HTTPS avec certificat valide et VPN d'accès (ex. WireGuard/Tailscale).
- Définir `AEGIS_ALLOWED_HOSTS` sur les **noms DNS exacts** autorisés si le domaine privé du proxy doit être accessible. Ne pas utiliser `*`.
- Désactiver toute indexation publique de la console, ne pas exposer le port API brut.
- Mettre à jour OS, Python et dépendances ; n'installer les outils IDS externes qu'à partir de sources vérifiées.
- Un collecteur compromis peut mentir sur ses mesures même avec TLS ; corroborer les détections avec journaux indépendants.
- Éviter toute automaticité qui fermerait un service de production sur un faux positif.
- Après exposition accidentelle d'un jeton agent, **révoquer cet agent** et générer une nouvelle identité ; en cas d'exposition de `.env`, réinitialiser secrets et sessions en concertation avec l'administrateur.

## Données et confidentialité

Stockage SQLite local des noms d'appareils, statistiques, ports et alertes. Historique des mesures supprimé au-delà de 30 jours ; incidents conservés jusqu'à suppression administrateur/maintenance de la base. Aucun transfert vers une API cloud n'est codé ; avec Ollama, utiliser uniquement un modèle local et vérifier sa configuration. Le tableau PWA ne cache jamais les réponses d'API.

## Lacunes connues avant production

- Pas de MFA / WebAuthn ni RBAC. Journal d’actions administratives **haché mais modifiable** par le propriétaire de la base.
- CSRF et sessions signées, mais pas de révocation de session persistante ni de gestion de flotte multi-tenant.
- Pas de mTLS sur le canal agent ; les jetons individuels servent de bearer tokens sur HTTPS. Rotation manuelle possible.
- Rate limiting en mémoire du serveur, non distribué. Les collectes ne sont pas envoyées en streaming. Le serveur limite les tailles déclarées mais un reverse proxy doit également limiter le corps HTTP réel.
- Pas de collecte des journaux Windows Event Log, macOS Unified Logs, ni des correctifs OS.
- Détections explicables de première génération, pas d'EDR full-kernel, ni de protection de l'agent contre sa neutralisation.
- Les états de pare-feu peuvent être « Non vérifié » et ne doivent pas être interprétés comme désactivés.
- L'application mobile est une console PWA, **pas** un antivirus système iOS/Android.

## Signaler un problème

Ne pas publier publiquement des clés, captures de journaux privés ou traces d'attaque exploitables. Procéder à une revue privée du projet avec l'administrateur propriétaire avant diffusion d'un correctif.

## Nouveaux contrôles de sécurité de la version 0.2

- L’envoi de télémétrie utilise un `sample_id` aléatoire et une table de reçus pour éviter les doublons après reprise.
- Une file locale d’envoi conserve les mesures si le réseau tombe ; chiffrez le disque local et protégez `.state.json` (les signatures d’alertes peuvent être sensibles).
- Le FIM en option surveille des fichiers expressément choisis par l’administrateur, sans transmettre leur contenu. Son état local n’est pas inviolable.
- Le journal d’audit haché signale certaines falsifications **mais ne résiste pas à un administrateur compromis** ou à une remise à zéro complète.
- La rotation manuelle des jetons invalide l’ancienne identité ; aucune rotation automatique ne fonctionne en arrière-plan.
