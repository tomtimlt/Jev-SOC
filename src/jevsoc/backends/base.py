"""Interface commune à tous les backends de décision (Laya, Jev, Mock)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from jevsoc.models import Decision


class DecisionBackend(ABC):
    """Un backend reçoit un state de cluster compact et renvoie une Decision.

    Les questions sont fixées à la construction : tous les clusters d'une même
    exécution sont jugés avec le même jeu de questions (et la même version).
    """

    name: str  # "mock", "jev" ou "laya" : enregistré dans chaque décision

    def __init__(self, questions: dict, questions_version: str):
        self.questions = questions
        self.questions_version = questions_version

    @abstractmethod
    def decide(self, state: dict) -> Decision:
        """Juge un cluster. `state` doit contenir au moins `cluster_id`."""
