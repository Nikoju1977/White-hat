# AEGIS — White Hat Security OS

[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-AEGIS-00c7a3?logo=github)](https://nikoju1977.github.io/White-hat/)

**AEGIS** est un cockpit de cybersécurité éthique consacré aux repositories publics de [Nikoju1977](https://github.com/Nikoju1977). Il est conçu pour l'inventaire et les contrôles défensifs en **lecture seule**.

## Ouvrir l'application

**https://nikoju1977.github.io/White-hat/** (accessible après le premier déploiement GitHub Pages réussi).

## Fonctions

- Tableau de bord et inventaire des dépôts publics GitHub, recherche et filtres.
- Audit heuristique des bonnes pratiques : README, LICENSE, SECURITY.md, Dependabot, lockfiles et configuration GitHub Actions.
- Contrôles approximatifs des références d'actions non épinglées, permissions larges et `pull_request_target`.
- Constatations manuelles avec gravité, statut, recommandations et exports JSON/CSV.
- Rapports imprimables et outils locaux (SHA-256, en-têtes HTTP, robustesse de mot de passe).
- Interface responsive 100 % statique, sans serveur et sans jeton GitHub.

**Limites :** les résultats ne constituent pas un audit de vulnérabilités complet. Aucun scan intrusif, exploitation, SAST réel, accès aux dépôts privés ou modification automatique des dépôts n'est réalisé. Les constats restent dans le stockage local du navigateur ; le site public n'héberge pas ces données.

## Publication via GitHub Pages

Le workflow `.github/workflows/deploy-pages.yml` publie automatiquement le site au push sur `main`.

1. Dans ce repository, ouvre **Settings → Pages**.
2. Dans **Build and deployment → Source**, sélectionne **GitHub Actions**.
3. Consulte l'onglet **Actions** pour vérifier l'exécution de « Publish AEGIS on GitHub Pages ».
4. Après succès, ouvre [AEGIS](https://nikoju1977.github.io/White-hat/).

Les fichiers HTML/CSS/JS sont regroupés dans `index.html` pour permettre un déploiement statique autonome. Les liens relatifs et les routes par fragments (`#`) fonctionnent sous le chemin `/White-hat/`.

## Sécurité et confidentialité

L'application utilise uniquement l'API GitHub publique (`api.github.com`) depuis le navigateur, sans token ni connexion OAuth. L'API anonyme peut imposer environ 60 requêtes par heure et par adresse IP. L'application ne lit pas le contenu des fichiers `.env`; elle peut détecter leur présence par le nom et signale les limites de ses contrôles. Les analyses ne prouvent jamais qu'un projet est exempt de failles.

Ce projet est réservé aux utilisations autorisées et à l'amélioration de la sécurité.

## Licence

Licence MIT. Les services externes et contenus de tiers restent soumis à leurs conditions respectives.
