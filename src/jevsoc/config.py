"""Chargement de config/config.yaml et du jeu de questions."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

DEFAULT_CONFIG = Path(__file__).resolve().parents[2] / "config" / "config.yaml"


def load_config(path: str | Path = DEFAULT_CONFIG) -> dict:
    """Lit le YAML et mémorise son dossier pour résoudre les chemins relatifs."""
    path = Path(path).resolve()
    config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    config["_dir"] = path.parent
    return config


def resolve(config: dict, relative: str) -> Path:
    """Chemin d'un fichier cité dans la config, relatif au dossier de config.yaml."""
    return Path(config["_dir"]) / relative


def load_questions(path: str | Path) -> tuple[dict, str]:
    """Renvoie (questions, version). La version vient du nom : questions.v2.json -> "v2"."""
    path = Path(path)
    parts = path.name.split(".")
    if len(parts) != 3 or parts[0] != "questions":
        raise ValueError(f"nom attendu questions.<version>.json, reçu {path.name}")
    return json.loads(path.read_text(encoding="utf-8")), parts[1]
