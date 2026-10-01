import pytest

from jevsoc.config import load_config
from jevsoc.models import Decision
from jevsoc.policy import policy

THRESHOLDS = load_config()["policy"]

STATE = {
    "cluster_id": "c1",
    "hosts": ["WS-FIN-07", "SRV-FILE-02"],
    "alert_count": 3,
    "timeline": [
        {"t": "+0m", "mitre": "T1566.001"},
        {"t": "+1m", "mitre": "T1059.001"},
        {"t": "+214m", "mitre": "T1059.001"},
    ],
}


def decision(p_attack, priority=2.0, stage="none_benign", exfil=0.5, contain=0.1, escalate=0.1):
    """Décision construite à la main avec les 6 questions v2."""
    return Decision(
        cluster_id="c1",
        backend="mock",
        model_name="mock",
        questions_version="v2",
        latency_ms=0,
        answers={
            "is_sophisticated_attack": {"type": "noul", "probability": p_attack},
            "priority": {"type": "score", "score": priority, "confidence": 0.9, "probabilities": {}},
            "furthest_stage": {"type": "choice", "label": stage, "confidence": 0.9, "probabilities": {}},
            "unauthorized_exfiltration": {"type": "noul", "probability": exfil},
            "should_contain_now": {"type": "noul", "probability": contain},
            "should_escalate_to_ir": {"type": "noul", "probability": escalate},
        },
    )


def test_monitor_when_benign_and_low_priority():
    derived = policy(decision(0.1, priority=1.0), STATE, THRESHOLDS)
    assert derived.actions == ["monitor"] and derived.flags == []


def test_investigate_in_grey_zone():
    assert policy(decision(0.5), STATE, THRESHOLDS).recommended_action == "investigate"
    # P basse mais priorité au-dessus du seuil de monitor -> investigate aussi
    assert policy(decision(0.1, priority=3.5), STATE, THRESHOLDS).recommended_action == "investigate"


def test_contain_and_escalate_are_not_exclusive():
    derived = policy(decision(0.95, 3.9, "exfiltration", 0.9, 0.95, 0.97), STATE, THRESHOLDS)
    assert derived.actions == ["contain", "escalate"]
    assert derived.recommended_action == "contain"  # la plus grave


def test_gate_blocks_actions_on_single_alert():
    # Cas mesuré sur Jev : 1 seule alerte, isoler/escalader déjà très hauts.
    single = {**STATE, "alert_count": 1, "timeline": STATE["timeline"][:1]}
    derived = policy(decision(0.95, 3.5, "execution", contain=0.9, escalate=0.95), single, THRESHOLDS)
    assert derived.actions == ["investigate"]


def test_gate_blocks_actions_when_attack_unlikely():
    # Cas du patching SCCM bénin : P(attaque) basse mais P(escalader)=0,81.
    derived = policy(decision(0.1, 2.8, contain=0.67, escalate=0.81), STATE, THRESHOLDS)
    assert "escalate" not in derived.actions
    assert "inconsistent" in derived.flags
    assert any("escalader" in issue for issue in derived.inconsistencies)


def test_inconsistent_exfiltration_stage():
    derived = policy(decision(0.9, 3.5, "exfiltration", exfil=0.1), STATE, THRESHOLDS)
    assert "inconsistent" in derived.flags


def test_low_confidence_near_half():
    derived = policy(decision(0.55), STATE, THRESHOLDS)
    assert derived.confidence_overall == pytest.approx(0.1)  # |2 x 0,55 - 1|
    assert "low_confidence" in derived.flags
    assert "low_confidence" not in policy(decision(0.95), STATE, THRESHOLDS).flags


def test_justification_is_deterministic():
    derived = policy(decision(0.97, 3.99, "exfiltration", 0.9, 0.95, 0.97), STATE, THRESHOLDS)
    assert derived.justification == (
        "3 alertes, 2 hôtes, 214 min ; T1566.001 → T1059.001 ; "
        "P(sophistiqué)=0.97, priorité=3.99/4, étape=exfiltration ; action : contain + escalate"
    )


def test_volume_rule_raises_monitor_to_investigate_but_never_contains():
    burst = {**STATE, "alert_count": 5000}
    derived = policy(decision(0.05, 1.0, contain=0.9, escalate=0.9), burst, THRESHOLDS)
    assert derived.actions == ["investigate"] and "high_volume" in derived.flags
    assert "rafale de 5000 alertes" in derived.justification


def test_calibration_is_applied_before_thresholds():
    from jevsoc.calibration import Calibrator

    raw = decision(0.5, 1.0)
    assert policy(raw, STATE, THRESHOLDS).p_attack == 0.5
    calibrated = policy(raw, STATE, THRESHOLDS, {"is_sophisticated_attack": Calibrator(a=2.0, b=-2.0)})
    assert calibrated.calibrated and calibrated.p_attack == pytest.approx(0.119, abs=1e-3)
    assert "(calibrée)" in calibrated.justification
