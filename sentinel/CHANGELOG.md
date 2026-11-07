# Historique des versions

## 0.2.1 — 2026-11-07

- Docker Compose partage la base SQLite déjà initialisée avec le collecteur hôte, en conservant un utilisateur non privilégié (UID/GID configurables).
- Validation de bout en bout : serveur HTTP réel, collecteur local, authentification administrateur et terminal retrouvé dans la console API.

## 0.2.0 — 2026-11-07

- Surveillance d’intégrité de fichiers locale (optionnelle, empreintes SHA-256) et intégration à l’agent de menace.
- Spool hors-ligne borné, reprise et protection anti-doublon des collectes.
- Journal d’audit administratif chaîné localement, vérification API et console.
- Renouvellement administratif des jetons de collecteurs, invalidation immédiate de l’ancien jeton.
- Tests de régression sur la rotation, le FIM, l’idempotence et la détection d’altération du journal.

## 0.1.0 — 2026-11-07

- Serveur FastAPI, console PWA, collecteurs desktop, IDS optionnels et IA statistique locale.
