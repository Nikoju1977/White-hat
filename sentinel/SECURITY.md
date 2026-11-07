# Politique de sécurité du prototype

**AEGIS Sentinel 0.2.1 n'est ni certifié ni inviolable.** Son déploiement en production exige revue du code, durcissement de l'hébergement, tests d'intrusion autorisés, sauvegardes et supervision de l'infrastructure.

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

- Pas de MFA / WebAuthn ni RBAC. Chaîne d’audit locale présente, mais non immuable face à un administrateur du serveur.
- CSRF et sessions signées, mais pas de révocation de session persistante ni de gestion de flotte multi-tenant.
- Pas de mTLS sur le canal agent ; les jetons individuels servent de bearer tokens sur HTTPS et peuvent être renouvelés manuellement.
- Rate limiting en mémoire du serveur, non distribué. Les collectes longues ne sont pas envoyées en streaming.
- Pas de collecte des journaux Windows Event Log, macOS Unified Logs, ni des correctifs OS.
- Détections explicables de première génération, pas d'EDR full-kernel, ni de protection de l'agent contre sa neutralisation.
- Les états de pare-feu peuvent être « Non vérifié » et ne doivent pas être interprétés comme désactivés.
- L'application mobile est une console PWA, **pas** un antivirus système iOS/Android.

## Signaler un problème

Ne pas publier publiquement des clés, captures de journaux privés ou traces d'attaque exploitables. Procéder à une revue privée du projet avec l'administrateur propriétaire avant diffusion d'un correctif.

### Docker et dossier de données (v0.2)

`compose.yaml` partage `./data` avec le conteneur. Le processus n'est pas privilégié et doit utiliser l'UID/GID de l'utilisateur qui a exécuté `aegis.cli init` sur Linux. Vérifier les ACL du dossier et la confidentialité des sauvegardes ; le montage n'est pas chiffré par l'application.

### Protection de la file d’attente locale

`agent/.state.json` contient des relevés retenus lors des pannes réseau : chiffrement du disque, contrôle d'accès et sauvegardes adaptées sont nécessaires. Sa taille est bornée mais des relevés peuvent être perdus lorsque la file déborde.

### Preuve d'intégrité de l'audit

Le journal d'audit haché détecte une modification isolée et ne constitue **pas** une preuve inviolable ; un attaquant ayant pris le contrôle de la base peut le régénérer. Exporter périodiquement les empreintes hors de l'hôte pour établir un ancrage indépendant.
