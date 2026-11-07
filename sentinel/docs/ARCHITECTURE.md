# Architecture et sécurité par conception

```text
Terminaison TLS privée / VPN
          |
Navigateur PWA -- HTTPS --> FastAPI (authentification, CSRF, audit)
                                 |
                              SQLite
                                 |
                        Coordination multi-agents
                          /     |       \
                    Posture   Menaces   Comportement → Projection indicative

Windows/macOS/Linux --- HTTPS + jeton individuel ---> /api/ingest
      |
psutil + pare-feu/Defender + FIM opt-in + JSON IDS tiers
      |
file locale bornée, réessai idempotent
```

Le serveur n’envoie jamais d’ordre d’exécution au collecteur. Les mesures sont non fiables tant qu’elles ne sont pas corroborées ; un appareil compromis peut fabriquer de la télémétrie. La console n’est **pas** une solution d’antivirus iOS/Android.

## Frontières de confiance

- Navigateur : authentification administrateur par mot de passe ; session `HttpOnly`, CSRF sur mutations.
- Terminal : jeton aléatoire par appareil, transmis sur HTTPS ; stockage local privé.
- Moteurs tiers : journaux JSON lus comme données ; aucune règle ne lance une commande distante.
- LLM local : conseil en lecture seule, jamais un agent outillé pilotant le système.

## Invariants

1. Pas de données fictives en production.
2. Pas de clés dans Git ni dans les rapports.
3. Aucune réponse destructive automatique.
4. Une alerte n’est pas une preuve d’intrusion.
5. Journal chaîné ≠ journal immuable.
