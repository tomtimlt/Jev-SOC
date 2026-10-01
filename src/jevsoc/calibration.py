"""Recalibration des probabilités du modèle (méthode de Platt).

Problème mesuré sur AIT-ADS : Jev est sous-confiant. Une P(attaque) brute de 0,5 correspond
en pratique à une chaîne d'attaque quasi certaine. On corrige avec une petite régression
logistique sur le logit de la probabilité brute :

    P_calibrée = sigmoïde(a × logit(P_brute) + b)

Deux paramètres seulement (a = pente, b = décalage), ajustés sur le split de VALIDATION,
jamais sur le test. Les cibles sont lissées (méthode de Platt) : avec très peu d'exemples
positifs, cela évite des probabilités calibrées absurdes à 0 ou 1.

Les réponses brutes du modèle restent stockées telles quelles ; la calibration n'agit que
dans la couche de décision (policy).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

import yaml

EPS = 1e-4


def logit(p: float) -> float:
    p = min(max(p, EPS), 1 - EPS)
    return math.log(p / (1 - p))


def sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-x)) if x >= 0 else math.exp(x) / (1 + math.exp(x))


@dataclass(frozen=True)
class Calibrator:
    a: float = 1.0  # pente : > 1 rend le modèle plus tranché, < 1 plus prudent
    b: float = 0.0  # décalage : > 0 remonte toutes les probabilités

    def __call__(self, p: float) -> float:
        return sigmoid(self.a * logit(p) + self.b)


def fit_platt(probs: list[float], labels: list[int], iterations: int = 100) -> Calibrator:
    """Ajuste (a, b) par la méthode de Newton sur la log-vraisemblance, cibles lissées de Platt."""
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        raise ValueError("il faut des exemples des deux classes pour calibrer")
    high, low = (n_pos + 1) / (n_pos + 2), 1 / (n_neg + 2)
    targets = [high if y else low for y in labels]
    xs = [logit(p) for p in probs]

    a, b = 1.0, 0.0
    for _ in range(iterations):
        # Gradient et hessienne de la perte logistique (régression à une variable + biais).
        g_a = g_b = h_aa = h_ab = h_bb = 0.0
        for x, t in zip(xs, targets, strict=True):
            p = sigmoid(a * x + b)
            g_a += (p - t) * x
            g_b += p - t
            w = p * (1 - p)
            h_aa += w * x * x
            h_ab += w * x
            h_bb += w
        h_aa += 1e-9  # stabilité numérique
        h_bb += 1e-9
        det = h_aa * h_bb - h_ab * h_ab
        step_a = (h_bb * g_a - h_ab * g_b) / det
        step_b = (h_aa * g_b - h_ab * g_a) / det
        a, b = a - step_a, b - step_b
        if abs(step_a) < 1e-9 and abs(step_b) < 1e-9:
            break
    return Calibrator(a=a, b=b)


def load_calibration(path, backend: str) -> dict[str, Calibrator]:
    """Lit config/calibration.yaml et renvoie {question: Calibrator} pour ce backend ({} si absent)."""
    path = Path(path)
    if not path.exists():
        return {}
    data = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get(backend) or {}
    return {
        question: Calibrator(a=params["a"], b=params["b"])
        for question, params in data.items()
        if isinstance(params, dict) and "a" in params
    }
