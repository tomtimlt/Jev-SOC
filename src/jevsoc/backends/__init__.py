"""Choix du backend de décision à partir de la configuration (jamais en dur)."""

from __future__ import annotations

import json

from jevsoc.backends.base import DecisionBackend
from jevsoc.config import load_questions, resolve


def build_backend(config: dict, name: str | None = None) -> DecisionBackend:
    """Construit le backend demandé (`name`, sinon la clé `backend` de la config)."""
    name = name or config["backend"]
    questions, version = load_questions(resolve(config, config["questions_file"]))

    if name == "mock":
        fixtures = (config.get("mock") or {}).get("fixtures")
        overrides = json.loads(resolve(config, fixtures).read_text(encoding="utf-8")) if fixtures else None
        from jevsoc.backends.mock_backend import MockBackend

        return MockBackend(questions, version, overrides=overrides)
    if name == "jev":
        from jevsoc.backends.jev_backend import JevBackend

        jev = config.get("jev") or {}
        return JevBackend(
            questions, version, model=jev.get("model", "jev-latest"), timeout_s=jev.get("timeout_s", 120)
        )
    if name == "laya":
        raise NotImplementedError("LayaBackend arrive au jalon 4")
    raise ValueError(f"backend inconnu : {name} (attendu : mock, jev, laya)")


__all__ = ["DecisionBackend", "build_backend"]
