# Matrice multiplateforme v0.2

| Plateforme | Collecteur natif Python | Console PWA | Limites |
|---|---|---|---|
| Windows 10/11 et Windows Server compatibles Python | Oui | Oui | Certaines métriques nécessitent des droits élevés ; statut Defender dépend de l’installation |
| Linux serveur et desktop | Oui | Oui | Le statut du pare-feu peut rester inconnu sans outils et droits nécessaires |
| macOS desktop | Oui | Oui | Télémétrie limitée par les permissions et la protection Apple |
| iPhone / iPad | Non | Oui (Safari, HTTPS) | Pas d’inspection générale des processus ou du noyau depuis la PWA |
| Android / tablettes | Non | Oui (navigateur compatible, HTTPS) | Pas de collecteur de privilèges OS depuis la PWA |

Les scripts de lancement facilitent le démarrage mais n’installent pas de service système permanent. Pour une exécution en production, configurer explicitement `systemd`, LaunchAgent ou le Planificateur de tâches et tester les permissions.

Aucune certification, indépendance au noyau, revue EDR externe ou garantie d’inviolabilité.
