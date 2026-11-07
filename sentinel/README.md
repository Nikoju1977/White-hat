# AEGIS Sentinel AI — Studio Niko

**Version de développement 0.2.1 — plateforme défensive multi-agents, données réelles uniquement**

AEGIS Sentinel centralise la télémétrie de **Windows, macOS, Linux et serveurs**, signale des faiblesses de posture et des anomalies, et offre une console responsive installable en PWA sur PC, Mac, tablette, iPhone et Android. L'application n'annonce ni protection absolue, ni IA préentraînée universelle, ni déploiement de capteurs qu'elle n'a pas effectué.

## Ce qui fonctionne dans ce dépôt

| Fonction | Réellement implémenté ? | Portée |
|---|---|---|
| Serveur API FastAPI et historique SQLite | **Oui** | Sur l'ordinateur/serveur qui exécute AEGIS |
| Authentification scrypt, session HttpOnly, CSRF, limitation des essais de connexion | **Oui** | Console web |
| Enrôlement, révocation, jeton individuel haché | **Oui** | Windows/macOS/Linux avec Python |
| Collecte CPU/RAM/disque, ports TCP, connexions, posture du pare-feu, Defender | **Oui** | Vérifications selon OS, privilèges et outils disponibles |
| Analyse d'anomalies par statistiques robustes | **Oui** | À partir de 12 mesures antérieures |
| Isolation Forest (apprentissage non supervisé) | **Oui** | À partir de 30 mesures et uniquement si données variables |
| Projection indicative d'un score de risque | **Oui** | À partir de 5 mesures précédentes. **Ce n'est pas une prédiction fiable d'attaque.** |
| Alerte réseau via Suricata EVE JSON | **Oui, connecteur** | Suricata externe, installé/configuré par l'administrateur |
| Corrélation de journaux Falco JSON | **Oui, connecteur** | Falco externe, installé/configuré |
| Corrélation d'alertes Wazuh JSON | **Oui, connecteur** | Wazuh externe, installé/configuré |
| Requête osquery à lecture seule, recherche de processus au binaire absent du disque | **Oui, connecteur** | osquery externe, installé/configuré |
| Conseiller LLM via Ollama local | **Oui, optionnel** | Nécessite Ollama et un modèle téléchargé (aucun modèle livré) |
| Application web responsive/PWA | **Oui** | Consultation et administration de la console |
| Installation PWA sur iOS / Android | **Compatible selon navigateur / HTTPS** | **Supervision de la console, pas antivirus de l'OS mobile** |
| Contrôle d’intégrité des fichiers (FIM) | **Oui, optionnel** | SHA-256 sur des fichiers locaux explicitement autorisés, jusqu’à 8 Mio |
| Réémission hors ligne et anti-doublons | **Oui** | File locale bornée à 96 relevés, identifiant de collecte unique et contrôle d’idempotence côté serveur |
| Journal d’audit administratif chaîné | **Oui** | Actions de gestion journalisées et vérification locale de cohérence ; aucune résistance à un administrateur compromis |
| Renouvellement des jetons agents | **Oui** | Invalidation immédiate de l’ancien jeton, réconfiguration manuelle du collecteur |
| Blocage automatique des attaques ou inspection profonde du noyau | **Non** | La commande locale facultative AEGIS SHIELD peut activer le pare-feu de l’OS avec confirmation ; pas d’IPS automatique |
| Utilisation des règles Sigma complètes | **Non** | Référence future, moteur de règles non implémenté |
| APK/IPA natif et capteur système sur iOS/Android | **Non** | Nécessite applications natives, signatures et droits de plateforme |
| Audit externe, certification, garantie d'inviolabilité | **Non** | Aucune garantie absolue possible |

**Important :** « 0 incident » signifie seulement qu'aucun capteur configuré n'a remonté d'incident ; pas que le poste est sain. Une alerte est un indice, pas une preuve d'intrusion.

## Installation rapide — PC Windows / macOS / Linux

**Prérequis :** Python >= 3.10 ; réseau local pour la console ; installation séparée des capteurs tiers si souhaitée.

```bash
# 1. Dans le dossier du projet
python -m pip install -r requirements.txt

# 2. Générer les clés et les identifiants (mot de passe fort demandé)
python -m aegis.cli init

# 3. Lancer le serveur central (terminal 1)
uvicorn aegis.main:app --host 127.0.0.1 --port 8765

# 4. Dans un autre terminal, tester un relevé local
python -m agent.collector --once

# 5. Démarrer les relevés périodiques du poste
python -m agent.collector --interval 60
```

Sur Windows, vous pouvez remplacer `python` par `py` selon l'installation. Ouvrir **http://127.0.0.1:8765** sur la machine où le serveur tourne. Se connecter avec le mot de passe fourni à l'initialisation.

Le premier démarrage ne crée **aucune fausse donnée**. Après une collecte réussie, une ligne d'appareil réel apparaît.

Le collecteur est **en lecture seule**. Il n'exécute ni « défense active » ni blocage automatique de ports, processus ou adresses : cela évite notamment de couper à tort une session de travail ou un serveur distant. Des outils de prévention effectifs comme Defender, le pare-feu système et Wazuh doivent être configurés séparément.

### Enrôler un autre PC/Mac/serveur

1. Dans la console, onglet **Ajouter un appareil**, saisir le nom du terminal et générer le jeton.
2. Sur cet appareil, installer Python et copier le code du dépôt AEGIS.
3. Dans le répertoire du projet, créer `.agent.env` à partir de la configuration fournie (gardez le jeton confidentiel). Ex. :

   ```ini
   AEGIS_SERVER_URL=https://aegis.votre-domaine-prive.fr
   AEGIS_DEVICE_ID=identifiant_genere
   AEGIS_AGENT_TOKEN=jeton_genere
   AEGIS_INTERVAL=60
   ```

4. Démarrer `python -m agent.collector --once` et vérifier l'arrivée du relevé, puis lancer `--interval 60` sous un gestionnaire de service adapté au système.
5. Le serveur distant **doit utiliser HTTPS**, et le serveur FastAPI doit idéalement rester derrière un reverse proxy ou VPN.

**Ne jamais publier `.env` ou `.agent.env`.** Les jetons ne sont affichés qu'une fois. Révoquez sans attendre un terminal compromis.

### Utilisation sur iPhone/iPad/Android

Ouvrir l'URL HTTPS privée de la console depuis Safari ou Chrome, puis utiliser « Ajouter à l'écran d'accueil » / « Installer l'application » selon le navigateur. La PWA permet de consulter les alertes et de gérer les enrôlements. Elle **ne protège pas directement le système mobile**, qui isole les applications. Un antivirus total sur iPhone n'est pas réalisable à partir d'une simple PWA.

### Intégrations open source optionnelles

Définir ces variables **dans l'environnement du processus collecteur**, ou dans `.agent.env` :

```ini
AEGIS_SURICATA_EVE_PATH=/var/log/suricata/eve.json
AEGIS_FALCO_JSON_PATH=/var/log/falco/events.json
AEGIS_WAZUH_ALERTS_JSON_PATH=/var/ossec/logs/alerts/alerts.json
AEGIS_OSQUERY_BIN=/usr/bin/osqueryi
```

Chaque chemin est optionnel. Le collecteur lit seulement les **nouveaux** enregistrements JSON de Suricata, Falco et Wazuh, et exécute une requête SQL **fixe et en lecture seule** dans `osqueryi`. Les chemins peuvent varier suivant les systèmes ; les droits de lecture doivent être accordés explicitement. Aucune dépendance tierce n'est installée par AEGIS et aucune connexion native aux API de Wazuh n'est prétendue. Les journaux d'autres programmes sont des données non fiables.

### Contrôle d’intégrité des fichiers (FIM, optionnel)

Depuis le poste collecteur, configurer des chemins de fichiers absolus dans `.agent.env` :

```ini
# Sur Linux/macOS, séparer les chemins par deux-points ; sur Windows, par point-virgule
AEGIS_FIM_PATHS=/etc/ssh/sshd_config:/etc/hosts
```

La première mesure établit une référence **sans alerte**. Une modification ultérieure produit un indice FIM, sans transmettre le contenu du fichier. Les fichiers illisibles, volumineux (plus de 8 Mio) ou non explicitement listés ne sont pas inspectés. Aucun changement de fichier n'est bloqué automatiquement.

### Reprise des envois et anti-doublons

En cas de réseau indisponible, le collecteur conserve jusqu'à 96 relevés dans `agent/.state.json` (permissions locales restreintes) et les renvoie en ordre au retour de la connexion. Au-delà, des mesures anciennes sont supprimées avec un avertissement ; il ne s'agit pas d'une garantie de conservation intégrale. `sample_id` permet de reconnaître un renvoi identique côté serveur. Protégez le fichier d'état : il peut contenir des signatures de journaux et des métadonnées système.

### Audit et rotation des identifiants

L’onglet **Journal d’audit** affiche les créations, révocations, rotations de jetons et changements de statut des incidents. Le chaînage SHA-256 indique une rupture locale mais **ne rend pas les événements immuables** : le propriétaire de la base peut réécrire toute la chaîne. Exportez les journaux vers un support de confiance indépendant si vous avez besoin de preuves résistantes à une compromission du serveur.

Dans **Ajouter un appareil**, le bouton **Renouveler le jeton** invalide immédiatement l'ancien jeton du terminal. Copiez le nouveau secret dans le `.agent.env` de ce terminal et redémarrez son collecteur ; aucune clé n'est publiée sur GitHub.

### IA locale optionnelle avec Ollama

Après installation d'Ollama et téléchargement *manuel* d'un modèle local compatible, ajouter à `.env` côté serveur (ou variable d'environnement) :

```ini
AEGIS_OLLAMA_MODEL=nom-du-modele-local
```

Relancer le serveur. Dans **Agents intelligents**, cliquer **Analyser les incidents avec Ollama**. La requête part uniquement vers `127.0.0.1:11434` sur le serveur, sans outillage de contrôle système. N'utilisez pas de modèle cloud si votre politique interdit de transférer les données ; vérifiez la configuration d'Ollama. Les recommandations LLM doivent être revues manuellement.

## Exécution dans Docker (serveur seulement)

Après `python -m aegis.cli init` sur l'hôte :

```bash
docker compose up --build -d
```

Docker Compose publie le serveur uniquement sur `127.0.0.1:8765` du serveur Docker et monte **le même dossier `./data`** que celui créé par `python -m aegis.cli init`. L'agent local généré à l'initialisation est ainsi autorisé côté serveur conteneurisé (contrairement à une base Docker séparée).

Sur Linux, lancer avec l'UID et le GID du propriétaire du dossier `data` pour permettre l'écriture à l'utilisateur non privilégié du conteneur :

```bash
AEGIS_UID="$(id -u)" AEGIS_GID="$(id -g)" docker compose up --build -d
```

Sous macOS/Windows Docker Desktop, vérifier que `./data` est partagé et accessible au conteneur. Ne lancez jamais le serveur conteneur avec des droits administrateur par défaut. Évitez de copier la base contenant les noms et preuves d'incidents sur un partage public. L'agent de collecte n'est **pas** inclus dans le conteneur : exécuter l'agent sur chaque système hôte. Voir `compose.yaml` et `SECURITY.md` avant toute exposition distante.

## Sécurité de l'architecture

- Authentification par mot de passe scrypt salé ; cookie de session signé, HttpOnly et SameSite strict.
- Protection CSRF pour les opérations administratives ; aucun CORS public ; CSP restrictive.
- Identifiants individuels (jetons aléatoires, SHA-256 en base) et révocation administrative.
- HTTPS imposé par le serveur aux hôtes non locaux ; le collecteur refuse le HTTP distant.
- Collecte sans commandes contrôlées depuis le réseau, sans action destructive automatique.
- Limitation basique des essais de connexion et de la taille des demandes déclarées ; stockage SQLite local.
- PWA ne met **jamais** les réponses API en cache ; aucune télémétrie simulée.

**Limites de durcissement :** absence de MFA, de PKI/mTLS, de rotation automatique des clés, de rate limit distribué, de contrôle d'intégrité des exécutables, d'audit externe, d'assurance d'intégrité des agents compromis et de chiffrement applicatif de la base SQLite. Ne pas exposer cette version directement à Internet. Utiliser HTTPS, VPN, gestion de sauvegardes et protection du serveur OS.

## Tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Les tests couvrent les seuils, les signaux Suricata/Wazuh, les contrôles d'authentification et CSRF, l'enrôlement/révocation et les appels réels de l'API locale. Ils ne constituent **pas** un audit de sécurité ni une qualification d'un OS complet.

## Pipeline multi-agents

`POSTURE → MENACES → COMPORTEMENT → PRÉDICTION → COORDINATION`

La collecte et les preuves sont séparées de l'analyse et du suivi. Le **score 0–100** est une priorité heuristique (selon la gravité des indicateurs), **pas une probabilité de compromission**. La prévision reflète une tendance mathématique courte. `IsolationForest` apprend uniquement les caractéristiques locales des derniers relevés après 30 échantillons ; il n'a pas été « surentraîné » sur toutes les attaques du monde.

## Projets libres de référence

- [Wazuh](https://github.com/wazuh/wazuh) — XDR/SIEM et capteurs Windows/macOS/Linux ; connecteur de journaux JSON dans AEGIS.
- [osquery](https://github.com/osquery/osquery) — introspection de systèmes ; requête read-only optionnelle dans AEGIS.
- [Suricata](https://github.com/OISF/suricata) — IDS réseau, format EVE JSON ; connecteur dans AEGIS.
- [Falco](https://github.com/falcosecurity/falco) — détection comportementale Linux ; connecteur JSON dans AEGIS.
- [SigmaHQ](https://github.com/SigmaHQ/sigma) — base de règles de détection ; inspiration, **pas encore implémentée**.
- [Ollama](https://github.com/ollama/ollama) — exécution locale de modèles ; conseil sur demande si installé.

Ces bibliothèques ne sont **pas** vendues comme des composants redistribués dans cette archive : leurs outils doivent être installés séparément, avec leurs propres licences et mises à jour.

Conçu par **Studio Niko**. Code original de l'application AEGIS : licence MIT (voir `LICENSE`).

## Protection préventive locale — AEGIS SHIELD

AEGIS ne remplace pas un pare-feu. En complément du monitorage, une **commande volontaire, locale et interactive** peut activer le pare-feu système sans créer de règles personnalisées :

```bash
python -m agent.shield audit
python -m agent.shield enable-firewall
```

`enable-firewall` exige une confirmation exacte `ACTIVER`, un terminal interactif, des privilèges administrateur et refuse les sessions SSH détectées. L'activation des profils Windows, du pare-feu d'applications macOS ou d'UFW Linux **peut interrompre des connexions ou services**. N'utiliser cette commande qu'avec accès console, après avoir vérifié les règles d'accès ; sur un serveur distant, préférer une procédure de changement avec rollback. Cette commande n'est jamais invoquée automatiquement par l'IA ni depuis la console web. Elle ne garantit pas l'absence d'intrusion.

### Scripts de démarrage simplifiés

- **Windows :** `START-WINDOWS.bat` (serveur), puis `AGENT-WINDOWS.bat` dans une autre fenêtre.
- **macOS/Linux :** `./START-MAC-LINUX.sh` (serveur), puis `./AGENT-MAC-LINUX.sh` dans un second terminal.

Ces scripts gardent les fenêtres ouvertes pour l'observation. Ils ne créent pas automatiquement de services permanents ou d'application mobile native.
