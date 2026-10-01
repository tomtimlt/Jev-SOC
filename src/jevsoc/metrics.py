"""Métriques d'évaluation au niveau cluster (fonctions pures, sans dépendance).

Convention : y_true contient 1 pour "attack", 0 pour "benign".
"""

from __future__ import annotations

import math


def classification_report(y_true: list[int], y_pred: list[int]) -> dict:
    """Précision, rappel, F1 et exactitude d'une prédiction binaire."""
    tp = sum(1 for t, p in zip(y_true, y_pred, strict=True) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred, strict=True) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred, strict=True) if t == 1 and p == 0)
    tn = sum(1 for t, p in zip(y_true, y_pred, strict=True) if t == 0 and p == 0)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / len(y_true) if y_true else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
    }


def brier_score(y_true: list[int], probs: list[float]) -> float:
    """Erreur quadratique moyenne entre probabilité et vérité (0 = parfait, 0,25 = toujours 0,5)."""
    return sum((p - t) ** 2 for t, p in zip(y_true, probs, strict=True)) / len(y_true)


def reliability_table(y_true: list[int], probs: list[float], n_bins: int = 5) -> list[dict]:
    """Tableau de fiabilité : par tranche de probabilité, confiance moyenne vs fréquence réelle.

    Bien calibré = dans chaque tranche, `mean_prob` ≈ `frac_positive`.
    """
    bins = [[] for _ in range(n_bins)]
    for t, p in zip(y_true, probs, strict=True):
        index = min(int(p * n_bins), n_bins - 1)  # p = 1,0 tombe dans la dernière tranche
        bins[index].append((t, p))
    table = []
    for i, content in enumerate(bins):
        row = {
            "bin": f"{i / n_bins:.1f}-{(i + 1) / n_bins:.1f}",
            "n": len(content),
            "mean_prob": None,
            "frac_positive": None,
        }
        if content:
            row["mean_prob"] = sum(p for _, p in content) / len(content)
            row["frac_positive"] = sum(t for t, _ in content) / len(content)
        table.append(row)
    return table


def expected_calibration_error(y_true: list[int], probs: list[float], n_bins: int = 5) -> float:
    """ECE : écart moyen |confiance - fréquence réelle|, pondéré par la taille des tranches."""
    total = len(y_true)
    return sum(
        row["n"] / total * abs(row["mean_prob"] - row["frac_positive"])
        for row in reliability_table(y_true, probs, n_bins)
        if row["n"]
    )


def roc_auc(y_true: list[int], scores: list[float]) -> float | None:
    """AUC = probabilité qu'une attaque ait un score plus haut qu'un bénin (égalités = 0,5).

    Ne dépend d'aucun seuil, ce qui permet de comparer modèle et baselines.
    Renvoie None si une des deux classes est absente.
    """
    positives = [s for t, s in zip(y_true, scores, strict=True) if t == 1]
    negatives = [s for t, s in zip(y_true, scores, strict=True) if t == 0]
    if not positives or not negatives:
        return None
    wins = sum(1.0 if p > n else 0.5 if p == n else 0.0 for p in positives for n in negatives)
    return wins / (len(positives) * len(negatives))


def percentile(values: list[float], q: float) -> float:
    """Percentile par rang le plus proche (q entre 0 et 100)."""
    ordered = sorted(values)
    rank = max(1, math.ceil(q / 100 * len(ordered)))
    return ordered[rank - 1]
