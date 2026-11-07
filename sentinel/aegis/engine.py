"""Explainable defensive multi-agent engine. No arbitrary commands or auto-remediation."""
import hashlib
import json
import statistics

SENSITIVE_PORTS = {21,22,23,139,445,1433,2375,3306,3389,5432,5900,6379,9200,11211,27017}
WEIGHTS = {"critical": 50, "high": 34, "medium": 16, "low": 7}


def finding(code: str, severity: str, title: str, description: str, evidence: dict | None = None, target: str = '') -> dict:
    key = hashlib.sha256(f"{code}:{target}".encode()).hexdigest()[:24]
    return {"key": key, "code": code, "severity": severity, "title": title,
            "description": description, "evidence": evidence or {}}


class PostureAgent:
    name = "AGENT POSTURE"

    def inspect(self, snapshot: dict, history: list[dict]) -> list[dict]:
        out = []
        checks = snapshot.get('checks', {})
        if checks.get('firewall') == 'disabled':
            out.append(finding('FIREWALL_DISABLED','high','Pare-feu désactivé',
                               'La vérification locale signale un pare-feu désactivé. Contrôler la configuration système.', checks))
        if checks.get('defender') == 'disabled':
            out.append(finding('DEFENDER_DISABLED','high','Protection antivirus désactivée',
                               'Microsoft Defender indique une protection temps réel désactivée. Vérifier si un autre antivirus la remplace.', checks))
        for listener in snapshot.get('listeners', []):
            try:
                port = int(listener.get('port', -1))
                addr = str(listener.get('ip', ''))
                if port in SENSITIVE_PORTS and addr in ('0.0.0.0','::','*'):
                    out.append(finding('SENSITIVE_PORT','medium',f'Service sensible sur le port {port}',
                                       'Écoute sur toutes les interfaces. Cela ne prouve pas une exposition à Internet : vérifier pare-feu et routage.',
                                       {'port':port, 'ip':addr,'process':str(listener.get('process',''))[:120]}, f'{port}:{addr}'))
            except (TypeError, ValueError):
                continue
        metrics = snapshot.get('metrics', {})
        if metrics.get('disk',0) >= 95:
            out.append(finding('DISK_SATURATION','low','Disque presque plein',
                               'L’espace disque libre est faible et peut perturber les journaux ou les mises à jour.',{'disk_percent':metrics['disk']}))
        return out


class ThreatAgent:
    name = "AGENT MENACES"

    def inspect(self, snapshot: dict, history: list[dict]) -> list[dict]:
        out = []
        for alert in snapshot.get('ids_alerts', []):
            kind = str(alert.get('source',''))
            if kind not in ('suricata','falco','wazuh','osquery','fim'):
                continue
            sig = str(alert.get('signature','Alerte sans signature'))[:250]
            sid = str(alert.get('id',''))[:80]
            # Severity for Suricata: 1 is highest severity; Falco uses named priorities.
            raw = alert.get('severity',3)
            if kind == 'suricata':
                severity = 'high' if str(raw)=='1' else 'medium' if str(raw)=='2' else 'low'
            elif kind == 'falco':
                severity = 'high' if str(raw).lower() in ('emergency','alert','critical','error') else 'medium'
            elif kind == 'wazuh':
                level = int(raw) if str(raw).isdigit() else 0
                severity = 'high' if level >= 12 else 'medium' if level >= 7 else 'low'
            elif kind == 'fim':
                severity = 'high' if str(raw).lower() == 'high' else 'medium'
            else:
                severity = 'medium'
            out.append(finding(f'IDS_{kind.upper()}',severity,f'Règle {kind} déclenchée',
                               f'Le moteur {kind} a signalé : {sig}. Examiner les journaux sources pour qualification.',
                               {'signature':sig,'id':sid,'source':kind,'origin_severity':str(raw)},f'{kind}:{sid}:{sig}'))
        return out


class BehaviorAgent:
    name = "AGENT COMPORTEMENT"

    def inspect(self, snapshot: dict, history: list[dict]) -> tuple[list[dict], str]:
        if len(history) < 12:
            return [], f'Apprentissage local ({len(history)}/12 mesures minimum)'
        fields = [('cpu',30),('memory',20),('established',20),('listener_count',5)]
        out = []
        m = snapshot['metrics']
        for field, minimum_jump in fields:
            values = [float(row[field]) for row in history if field in row]
            if len(values) < 12:
                continue
            median = statistics.median(values)
            mad = statistics.median(abs(v-median) for v in values)
            robust_sigma = max(1.4826 * mad, 1.0)
            value = float(m.get(field,0))
            if value-median >= max(minimum_jump, 3.5*robust_sigma):
                out.append(finding('BEHAVIOR_SPIKE','medium','Écart significatif de comportement',
                                   f'{field} : {value:g} contre une médiane historique de {median:.1f}. Anomalie statistique, pas preuve d’intrusion.',
                                   {'metric':field,'observed':value,'median':round(median,2)},field))
        model = 'Seuils statistiques robustes'
        if len(history) >= 30:
            try:
                from sklearn.ensemble import IsolationForest
                columns = ('cpu','memory','established','listener_count')
                matrix = [[float(r[c]) for c in columns] for r in history[-100:]]
                model = 'Isolation Forest : apprentissage local'
                if any(len(set(row[i] for row in matrix))>2 for i in range(4)):
                    clf = IsolationForest(n_estimators=60,contamination=0.05,random_state=42)
                    clf.fit(matrix)
                    sample = [[float(m.get(c,0)) for c in columns]]
                    if int(clf.predict(sample)[0]) == -1:
                        out.append(finding('MODEL_ANOMALY','medium','Anomalie multivariée détectée',
                                           'Le modèle local Isolation Forest juge cette mesure atypique. Vérification humaine recommandée.',
                                           {'algorithm':'IsolationForest','measurements':len(matrix)}))
            except ImportError:
                model = 'Seuils statistiques (scikit-learn absent)'
            except (ValueError, TypeError):
                model = 'Seuils statistiques (modèle indisponible)'
        return out, model


class ForecastAgent:
    name = "AGENT PRÉDICTION"

    def estimate(self, findings: list[dict], history: list[dict]) -> tuple[int,int | None]:
        # Score is an operational priority indicator, not probability of compromise.
        risk = min(100,sum(WEIGHTS.get(x['severity'],0) for x in findings))
        if len(history) < 5:
            return risk, None
        recent = [int(r['risk']) for r in history[-5:]]
        avg_old = sum(recent[:3])/3
        avg_new = sum(recent[3:])/2
        forecast = max(0,min(100,round(risk + 0.6*(avg_new-avg_old))))
        return risk,forecast


class CoordinatorAgent:
    name = "AGENT COORDINATEUR"

    def __init__(self):
        self.posture = PostureAgent()
        self.threat = ThreatAgent()
        self.behavior = BehaviorAgent()
        self.forecast = ForecastAgent()

    def analyze(self, snapshot: dict, history: list[dict]) -> dict:
        findings = self.posture.inspect(snapshot,history) + self.threat.inspect(snapshot,history)
        behavioral, model = self.behavior.inspect(snapshot,history)
        findings.extend(behavioral)
        unique = {x['key']:x for x in findings}
        findings = list(unique.values())
        risk, forecast = self.forecast.estimate(findings,history)
        return {'risk':risk,'forecast':forecast,'model':model,'findings':findings,
                'pipeline':['Posture','Menaces','Comportement','Prédiction','Coordination']}
