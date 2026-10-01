"""Modèles Pydantic des réponses du modèle de décision.

Jev et Laya sont des classifieurs : chaque question typée renvoie une réponse typée
avec des probabilités, jamais du texte libre. On garde ici les réponses brutes,
indépendamment du backend qui les a produites.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import BaseModel, Field


class NoulAnswer(BaseModel):
    """Question oui/non : probabilité que la réponse soit "vrai"."""

    type: Literal["noul"] = "noul"
    probability: float = Field(ge=0.0, le=1.0)


class ChoiceAnswer(BaseModel):
    """Choix unique : label retenu + probabilité de chaque option."""

    type: Literal["choice"] = "choice"
    label: str
    confidence: float = Field(ge=0.0, le=1.0)
    probabilities: dict[str, float]


class ScoreAnswer(BaseModel):
    """Échelle ordonnée : valeur attendue (fractionnaire) + probabilité de chaque niveau."""

    type: Literal["score"] = "score"
    score: float
    confidence: float = Field(ge=0.0, le=1.0)
    probabilities: dict[int, float]


# Le champ "type" indique à Pydantic quel modèle utiliser à la lecture.
Answer = Annotated[NoulAnswer | ChoiceAnswer | ScoreAnswer, Field(discriminator="type")]


class Decision(BaseModel):
    """Réponses du modèle pour un cluster, avec de quoi tracer d'où elles viennent."""

    cluster_id: str
    answers: dict[str, Answer]
    backend: Literal["mock", "jev", "laya"]
    model_name: str
    questions_version: str
    latency_ms: float
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    usage: dict[str, int] | None = None  # tokens consommés, si le backend les rapporte

    # Accès typés : lèvent une erreur claire si la question manque ou n'a pas le bon type.
    def noul(self, name: str) -> float:
        return self._get(name, NoulAnswer).probability

    def score(self, name: str) -> float:
        return self._get(name, ScoreAnswer).score

    def choice(self, name: str) -> str:
        return self._get(name, ChoiceAnswer).label

    def _get(self, name, expected_type):
        answer = self.answers.get(name)
        if not isinstance(answer, expected_type):
            raise KeyError(f"question '{name}' absente ou pas de type {expected_type.__name__}")
        return answer
