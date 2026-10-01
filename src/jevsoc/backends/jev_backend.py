"""Backend Jev : API TypeSafe (POST /v1/systemone) via le SDK officiel `typesafe_sdk`.

Attention confidentialité : le state du cluster quitte le périmètre de l'organisation.
N'envoyer que des données de lab ou anonymisées. Le mode local (Laya) est recommandé
pour de vraies données.

La clé API est lue par le SDK dans la variable d'environnement TYPESAFE_API_KEY.
"""

from __future__ import annotations

import time

from jevsoc.backends.base import DecisionBackend
from jevsoc.models import Decision


def answer_from_api(raw: dict) -> dict:
    """Convertit une réponse de l'API (format observé) vers le format de jevsoc.models.

    API : {"type": "noul", "noul": 0.97}
          {"type": "choice", "choice": "exfiltration", "confidence": 1.0, "probabilities": {...}}
          {"type": "score", "score": 3.99, "confidence": 0.99, "legend": {...}, "probabilities": {...}}
    """
    qtype = raw["type"]
    if qtype == "noul":
        return {"type": "noul", "probability": raw["noul"]}
    if qtype == "choice":
        return {
            "type": "choice",
            "label": raw["choice"],
            "confidence": raw["confidence"],
            "probabilities": raw["probabilities"],
        }
    if qtype == "score":
        return {
            "type": "score",
            "score": raw["score"],
            "confidence": raw["confidence"],
            "probabilities": raw["probabilities"],
        }
    raise ValueError(f"type de réponse inconnu : {qtype}")


class JevBackend(DecisionBackend):
    name = "jev"

    def __init__(
        self, questions: dict, questions_version: str, model: str = "jev-latest", timeout_s: float = 120
    ):
        super().__init__(questions, questions_version)
        # Import ici pour que le reste du projet fonctionne sans le SDK installé.
        from typesafe_sdk import TypeSafeClient

        self.client = TypeSafeClient(model=model, timeout=timeout_s)

    def decide(self, state: dict) -> Decision:
        start = time.perf_counter()
        response = self.client.system_one(state=state, questions=self.questions)
        latency_ms = (time.perf_counter() - start) * 1000

        answers = {name: answer_from_api(a.model_dump(mode="json")) for name, a in response.answers.items()}
        usage = {k: v for k, v in response.usage.model_dump().items() if v is not None}
        return Decision(
            cluster_id=state["cluster_id"],
            answers=answers,
            backend="jev",
            model_name=response.model,
            questions_version=self.questions_version,
            latency_ms=latency_ms,
            usage=usage or None,
        )
