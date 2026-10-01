"""Backend factice : réponses déterministes, aucun appel réseau.

Sert aux tests unitaires et au développement hors ligne. Par défaut chaque question
reçoit une réponse neutre (0,5, milieu d'échelle, distribution uniforme). Des
réponses précises peuvent être imposées par cluster via `overrides`.
"""

from __future__ import annotations

from jevsoc.backends.base import DecisionBackend
from jevsoc.models import Decision


def neutral_answer(question: dict) -> dict:
    """Réponse "je ne sais pas" pour une question typée."""
    qtype = question["type"]
    if qtype == "noul":
        return {"type": "noul", "probability": 0.5}
    if qtype == "choice":
        labels = list(question["criteria"])
        uniform = 1.0 / len(labels)
        return {
            "type": "choice",
            "label": labels[0],
            "confidence": uniform,
            "probabilities": {label: uniform for label in labels},
        }
    if qtype == "score":
        levels = len(question["criteria"])
        uniform = 1.0 / levels
        return {
            "type": "score",
            "score": (levels - 1) / 2,
            "confidence": uniform,
            "probabilities": {i: uniform for i in range(levels)},
        }
    raise ValueError(f"type de question inconnu : {qtype}")


class MockBackend(DecisionBackend):
    name = "mock"

    def __init__(self, questions: dict, questions_version: str, overrides: dict | None = None):
        super().__init__(questions, questions_version)
        # overrides = {cluster_id: {nom_question: réponse au format de jevsoc.models}}
        self.overrides = overrides or {}

    def decide(self, state: dict) -> Decision:
        cluster_id = state["cluster_id"]
        answers = {name: neutral_answer(q) for name, q in self.questions.items()}
        answers.update(self.overrides.get(cluster_id, {}))
        return Decision(
            cluster_id=cluster_id,
            answers=answers,
            backend="mock",
            model_name="mock",
            questions_version=self.questions_version,
            latency_ms=0.0,
        )
