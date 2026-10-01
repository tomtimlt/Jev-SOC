"""Politique de décision : des probabilités du modèle vers une action, des drapeaux et une justification.

Choix d'architecture : la décision est prise ICI, par des seuils lisibles et configurables,
et non par le modèle. Les questions du modèle sont indépendantes (rien ne garantit qu'elles
soient cohérentes entre elles) ; on les combine donc avec des règles explicites, et on
signale les contradictions au lieu de les cacher.

Fonction pure : mêmes entrées -> même sortie, aucun appel réseau, facile à tester.
"""

from __future__ import annotations

import re

from jevsoc.models import ACTION_ORDER, Decision, Derived

ATTACK = "is_sophisticated_attack"
PRIORITY = "priority"
STAGE = "furthest_stage"
EXFIL = "unauthorized_exfiltration"
CONTAIN = "should_contain_now"
ESCALATE = "should_escalate_to_ir"


def choose_actions(
    p_attack: float, priority: float, contain: float, escalate: float, alert_count: int, t: dict
) -> list[str]:
    """Applique les seuils. Renvoie la liste des actions retenues (au moins une)."""
    actions = []
    # Garde-fou : on n'isole ou n'escalade que si l'attaque est probable ET étayée par
    # plusieurs alertes. Les questions contain/escalate seules sont trop nerveuses.
    gate_open = p_attack >= t["sophisticated_high"] and alert_count >= t["action_min_alerts"]
    if gate_open and contain >= t["contain_min"]:
        actions.append("contain")
    if gate_open and escalate >= t["escalate_min"]:
        actions.append("escalate")
    if actions:
        return actions
    if p_attack < t["sophisticated_low"] and priority <= t["priority_monitor_max"]:
        return ["monitor"]
    # Zone grise (P entre les deux seuils, ou priorité au-dessus du monitor) : un humain regarde.
    return ["investigate"]


def find_inconsistencies(decision: Decision, t: dict) -> list[str]:
    """Contradictions entre réponses indépendantes, décrites en clair."""
    p_attack = decision.noul(ATTACK)
    issues = []
    if STAGE in decision.answers:
        stage = decision.choice(STAGE)
        exfil = decision.noul(EXFIL) if EXFIL in decision.answers else None
        if stage == "exfiltration" and exfil is not None and exfil < t["exfil_inconsistency_max"]:
            issues.append(f"étape exfiltration mais P(exfiltration non autorisée)={exfil:.2f}")
        if stage == "none_benign" and p_attack >= t["sophisticated_high"]:
            issues.append(f"étape none_benign mais P(attaque)={p_attack:.2f}")
        if stage != "none_benign" and p_attack < t["sophisticated_low"]:
            issues.append(f"étape {stage} mais P(attaque)={p_attack:.2f}")
    # Demander d'isoler ou d'escalader un cluster jugé bénin est contradictoire.
    for name, label, threshold in (
        (CONTAIN, "isoler", "contain_min"),
        (ESCALATE, "escalader", "escalate_min"),
    ):
        if (
            name in decision.answers
            and decision.noul(name) >= t[threshold]
            and p_attack < t["sophisticated_low"]
        ):
            issues.append(f"P({label})={decision.noul(name):.2f} mais P(attaque)={p_attack:.2f}")
    return issues


def _minutes(offset: str) -> int:
    """'+214m' -> 214 (format des offsets de la timeline)."""
    match = re.fullmatch(r"\+(\d+)m", offset)
    return int(match.group(1)) if match else 0


def build_justification(state: dict, decision: Decision, actions: list[str]) -> str:
    """Phrase déterministe : faits du cluster + probabilités clés + action. Aucun texte généré."""
    timeline = state.get("timeline", [])
    count = state.get("alert_count", len(timeline))
    hosts = len(state.get("hosts", []))
    minutes = state.get("window_minutes")
    if minutes is None and timeline:
        minutes = _minutes(timeline[-1]["t"]) - _minutes(timeline[0]["t"])
    mitre = []
    for event in timeline:  # techniques dans l'ordre d'apparition, sans doublon
        if event.get("mitre") and event["mitre"] not in mitre:
            mitre.append(event["mitre"])

    parts = [f"{count} alertes, {hosts} hôte{'s' if hosts > 1 else ''}, {minutes} min"]
    if mitre:
        parts.append(" → ".join(mitre))
    probs = [f"P(sophistiqué)={decision.noul(ATTACK):.2f}"]
    if PRIORITY in decision.answers:
        probs.append(f"priorité={decision.score(PRIORITY):.2f}/4")
    if STAGE in decision.answers:
        probs.append(f"étape={decision.choice(STAGE)}")
    parts.append(", ".join(probs))
    parts.append("action : " + " + ".join(actions))
    return " ; ".join(parts)


def policy(decision: Decision, state: dict, thresholds: dict) -> Derived:
    """Point d'entrée : réponses brutes + state du cluster -> Derived."""
    t = thresholds
    p_attack = decision.noul(ATTACK)
    priority = decision.score(PRIORITY) if PRIORITY in decision.answers else 0.0
    contain = decision.noul(CONTAIN) if CONTAIN in decision.answers else 0.0
    escalate = decision.noul(ESCALATE) if ESCALATE in decision.answers else 0.0
    alert_count = state.get("alert_count", len(state.get("timeline", [])))

    actions = choose_actions(p_attack, priority, contain, escalate, alert_count, t)
    confidence = abs(2 * p_attack - 1)
    inconsistencies = find_inconsistencies(decision, t)
    flags = []
    if inconsistencies:
        flags.append("inconsistent")
    if confidence < t["low_confidence_max"]:
        flags.append("low_confidence")

    return Derived(
        recommended_action=max(actions, key=ACTION_ORDER.index),
        actions=actions,
        confidence_overall=confidence,
        flags=flags,
        inconsistencies=inconsistencies,
        justification=build_justification(state, decision, actions),
    )
