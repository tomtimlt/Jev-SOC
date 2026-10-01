import json
from pathlib import Path

import pytest

from jevsoc.backends import build_backend
from jevsoc.backends.jev_backend import answer_from_api
from jevsoc.backends.mock_backend import MockBackend
from jevsoc.config import load_config, load_questions
from jevsoc.models import Decision

ROOT = Path(__file__).resolve().parents[1]
QUESTIONS, VERSION = load_questions(ROOT / "config" / "questions.v2.json")


def test_questions_version_from_filename():
    assert VERSION == "v2"
    assert set(QUESTIONS) >= {"is_sophisticated_attack", "furthest_stage", "priority"}


def test_mock_neutral_answers():
    decision = MockBackend(QUESTIONS, VERSION).decide({"cluster_id": "c1"})
    assert decision.backend == "mock" and decision.questions_version == "v2"
    assert decision.noul("is_sophisticated_attack") == 0.5
    assert decision.score("priority") == 2.0  # milieu de l'échelle P0..P4
    assert decision.choice("furthest_stage") == "none_benign"
    assert set(decision.answers) == set(QUESTIONS)


def test_mock_overrides_are_deterministic():
    overrides = {"c1": {"is_sophisticated_attack": {"type": "noul", "probability": 0.9}}}
    backend = MockBackend(QUESTIONS, VERSION, overrides=overrides)
    assert backend.decide({"cluster_id": "c1"}).noul("is_sophisticated_attack") == 0.9
    assert backend.decide({"cluster_id": "autre"}).noul("is_sophisticated_attack") == 0.5


def test_decision_typed_access_errors():
    decision = MockBackend(QUESTIONS, VERSION).decide({"cluster_id": "c1"})
    with pytest.raises(KeyError):
        decision.noul("priority")  # c'est un score, pas un noul
    with pytest.raises(KeyError):
        decision.noul("question_inexistante")


def test_decision_json_round_trip():
    decision = MockBackend(QUESTIONS, VERSION).decide({"cluster_id": "c1"})
    again = Decision.model_validate_json(decision.model_dump_json())
    assert again == decision  # les clés int du score survivent au passage en JSON


def test_jev_answer_conversion_from_recorded_response():
    # Réponse réelle de l'API enregistrée (cluster attack__full), aucun appel réseau.
    raw = json.loads((ROOT / "tests" / "fixtures" / "jev_response_attack_full.json").read_text())
    answers = {name: answer_from_api(a) for name, a in raw["answers"].items()}
    decision = Decision(
        cluster_id="attack-full",
        answers=answers,
        backend="jev",
        model_name=raw["model"],
        questions_version="v2",
        latency_ms=0,
    )
    assert decision.noul("is_sophisticated_attack") == pytest.approx(0.98)
    assert decision.choice("furthest_stage") == "exfiltration"
    assert decision.score("priority") == pytest.approx(3.99)
    assert decision.answers["priority"].probabilities[4] == pytest.approx(0.99)


def test_build_backend_from_config():
    config = load_config(ROOT / "config" / "config.yaml")
    assert isinstance(build_backend(config, "mock"), MockBackend)
    with pytest.raises(NotImplementedError):
        build_backend(config, "laya")
    with pytest.raises(ValueError):
        build_backend(config, "inconnu")
