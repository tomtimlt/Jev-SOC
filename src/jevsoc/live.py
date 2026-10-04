"""Moteur de triage en flux : alertes -> clusters incrémentaux -> décisions versionnées.

Utilisé par la démo live (scripts/demo.py). Il ne fait aucune entrée/sortie : on lui donne
les alertes dans l'ordre du temps, il renvoie des événements (dict JSON) que la page de démo
affiche, ou qu'on enregistre pour les rejouer plus tard.

Événements produits :
  alert     une alerte Wazuh arrive (et le cluster qu'elle rejoint)
  merge     une alerte relie plusieurs clusters : ils fusionnent
  close     un cluster est resté inactif plus de max_gap : il est fermé
  decision  le modèle a (re)jugé un cluster ; nouvelle version, jamais écrasée

Quand re-décider ? Un appel au modèle par alerte serait inutile (et coûteux sur une rafale de
400 alertes identiques). On re-décide un cluster jugeable seulement si son résumé (state) a
changé de forme : nouvelle ligne de timeline, nouvel hôte... et au plus une fois toutes les
`min_interval_s` secondes de temps simulé. Une simple hausse d'un compteur ne suffit pas.
"""

from __future__ import annotations

from collections.abc import Callable

from jevsoc.collector import Alert
from jevsoc.correlator import IncrementalCorrelator, LiveCluster, is_judgeable
from jevsoc.models import Decision
from jevsoc.policy import policy
from jevsoc.serializer import serialize


def state_signature(state: dict) -> tuple:
    """Forme du résumé, sans les compteurs : ce qui change vraiment ce que voit le modèle."""
    return tuple(
        (e.get("host"), e.get("desc"), e.get("detail", "")[:60], e.get("flow")) for e in state["timeline"]
    ) + (tuple(state["hosts"]), tuple(state["users"]))


def mitre_chain(alerts: list[Alert], limit: int = 8) -> list[str]:
    """Techniques MITRE dans l'ordre d'apparition, sans doublon (déterministe, hors modèle)."""
    chain: list[str] = []
    for alert in alerts:
        for technique in alert.mitre:
            if technique not in chain:
                chain.append(technique)
    return chain[:limit]


class LiveEngine:
    def __init__(
        self,
        decide: Callable[[dict], Decision],
        thresholds: dict,
        correlation: dict,
        hubs: set[str],
        calibration: dict | None = None,
        min_interval_s: float = 20,
        truth_ids: set[str] | None = None,
    ):
        self.decide = decide
        self.thresholds = thresholds
        self.corr = correlation
        self.calibration = calibration or {}
        self.min_interval_s = min_interval_s
        self.truth_ids = truth_ids  # ids d'alertes de l'attaquant (vérité terrain, optionnelle)
        self.correlator = IncrementalCorrelator(
            correlation["max_gap_minutes"],
            correlation["window_minutes"],
            hubs,
            correlation["max_cluster_size"],
        )
        self.t0: float | None = None
        self.alert_count = 0
        self._signature: dict[str, tuple] = {}  # cluster -> forme du dernier state jugé
        self._last_decision: dict[str, float] = {}  # cluster -> temps simulé de la dernière décision
        self._pending: set[str] = set()  # clusters modifiés en attente de l'intervalle minimal
        self._decision_version: dict[str, int] = {}

    def _t(self, ts: float) -> float:
        return round(ts - self.t0, 3)

    def _judgeable(self, cluster: LiveCluster) -> bool:
        return is_judgeable(cluster.alerts, self.corr["min_alerts"], self.corr["min_entities"])

    def _maybe_decide(self, cluster: LiveCluster, now: float, force: bool = False) -> list[dict]:
        """Juge le cluster si son résumé a changé et que l'intervalle minimal est écoulé."""
        if cluster.merged_into or not self._judgeable(cluster):
            return []
        state = serialize(cluster.id, cluster.alerts, self.corr["max_timeline_entries"])
        signature = state_signature(state)
        if signature == self._signature.get(cluster.id):
            self._pending.discard(cluster.id)
            return []
        last = self._last_decision.get(cluster.id)
        if last is not None and not force and now - last < self.min_interval_s:
            self._pending.add(cluster.id)
            return []
        self._pending.discard(cluster.id)
        self._signature[cluster.id] = signature
        self._last_decision[cluster.id] = now
        return [self._decision_event(cluster, state, now)]

    def _decision_event(self, cluster: LiveCluster, state: dict, now: float) -> dict:
        decision = self.decide(state)
        derived = policy(decision, state, self.thresholds, self.calibration)
        self._decision_version[cluster.id] = self._decision_version.get(cluster.id, 0) + 1
        event = {
            "t": now,
            "type": "decision",
            "cluster": cluster.id,
            "version": self._decision_version[cluster.id],
            "alerts": len(cluster.alerts),
            "hosts": state["hosts"],
            "users": state["users"][:5],
            "max_level": state["max_rule_level"],
            "window_minutes": state["window_minutes"],
            "mitre": mitre_chain(cluster.alerts),
            "timeline": [
                {k: e[k] for k in ("t", "host", "level", "desc", "count") if k in e}
                for e in state["timeline"][:8]
            ],
            "p_raw": round(decision.noul("is_sophisticated_attack"), 3),
            "p": round(derived.p_attack, 3),
            "priority": round(decision.score("priority"), 2) if "priority" in decision.answers else None,
            "stage": decision.choice("furthest_stage") if "furthest_stage" in decision.answers else None,
            "action": derived.recommended_action,
            "actions": derived.actions,
            "flags": derived.flags,
            "justification": derived.justification,
            "latency_ms": round(decision.latency_ms),
        }
        if self.truth_ids is not None:
            event["truth"] = any(a.id in self.truth_ids for a in cluster.alerts)
        return event

    def ingest(self, alert: Alert) -> list[dict]:
        """Traite une alerte (dans l'ordre du temps) et renvoie les événements produits."""
        if self.t0 is None:
            self.t0 = alert.ts
        now = self._t(alert.ts)
        self.alert_count += 1
        events: list[dict] = []
        for cluster in self.correlator.close_stale(alert.ts):
            events.append({"t": now, "type": "close", "cluster": cluster.id})
            self._pending.discard(cluster.id)

        cluster, absorbed = self.correlator.add(alert)
        events.append(
            {
                "t": now,
                "type": "alert",
                "n": self.alert_count,
                "host": alert.host,
                "level": alert.level,
                "rule": alert.rule_id,
                "desc": alert.description[:120],
                "cluster": cluster.id,
            }
        )
        if absorbed:
            events.append(
                {"t": now, "type": "merge", "into": cluster.id, "absorbed": [c.id for c in absorbed]}
            )
            for other in absorbed:
                self._pending.discard(other.id)
        events.extend(self._maybe_decide(cluster, now))

        # Clusters modifiés plus tôt dont l'intervalle minimal est maintenant écoulé.
        for cluster_id in sorted(self._pending):
            other = self.correlator.clusters[cluster_id]
            if now - self._last_decision.get(cluster_id, -1e9) >= self.min_interval_s:
                events.extend(self._maybe_decide(other, now))
        return events

    def finish(self) -> list[dict]:
        """Fin du flux : juge ce qui attend encore, puis ferme tout."""
        if self.t0 is None:
            return []
        now = max(c.last for c in self.correlator.clusters.values()) - self.t0
        events = []
        for cluster_id in sorted(self._pending):
            events.extend(self._maybe_decide(self.correlator.clusters[cluster_id], round(now, 3), force=True))
        for cluster in self.correlator.clusters.values():
            if not cluster.closed and not cluster.merged_into:
                cluster.closed = True
                events.append({"t": round(now, 3), "type": "close", "cluster": cluster.id})
        return events
