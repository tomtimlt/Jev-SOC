"""Harnais d'évaluation : juge un dossier de clusters labellisés et calcule les métriques.

Usage (depuis la racine du dépôt) :
  python eval/eval.py                         # backend de config.yaml (mock par défaut)
  python eval/eval.py --backend jev           # API TypeSafe (TYPESAFE_API_KEY requise)
  python eval/eval.py --split test --out eval/results/jev.json

Prédiction du modèle : P(attaque) = réponse `is_sophisticated_attack`, seuil --threshold.
Baselines à battre (calculées sur les vrais niveaux de règle, `rule_levels`) :
  - max_level>=7    : au moins une alerte de niveau 7 ou plus
  - sum_levels      : somme des niveaux, seuil --sum-threshold (à fixer sur la validation)
Les baselines ne sont pas probabilistes : pas de Brier ni d'ECE pour elles, mais une AUC.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from jevsoc.backends import build_backend
from jevsoc.config import DEFAULT_CONFIG, load_config
from jevsoc.metrics import (
    brier_score,
    classification_report,
    expected_calibration_error,
    percentile,
    reliability_table,
    roc_auc,
)

ROOT = Path(__file__).resolve().parents[1]
ATTACK_QUESTION = "is_sophisticated_attack"
MIN_RELIABLE_N = 20  # en dessous, les métriques sont seulement indicatives


def load_clusters(data_dir: Path, split: str | None) -> list[dict]:
    """Charge les clusters labellisés (*.json), filtrés par split si demandé."""
    clusters = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(data_dir.glob("*.json"))]
    if split:
        splits = yaml.safe_load((ROOT / "data" / "splits.yaml").read_text(encoding="utf-8")) or {}
        clusters = [c for c in clusters if splits.get(c["scenario"]) == split]
    return clusters


def evaluate(clusters: list[dict], backend, threshold: float = 0.5, sum_threshold: float = 30) -> dict:
    """Interroge le backend sur chaque cluster et calcule toutes les métriques."""
    rows = []
    for c in clusters:
        decision = backend.decide(c["state"])
        rows.append(
            {
                "cluster_id": c["state"]["cluster_id"],
                "label": c["label"],
                "p_attack": decision.noul(ATTACK_QUESTION),
                "priority": decision.score("priority") if "priority" in decision.answers else None,
                "stage": decision.choice("furthest_stage") if "furthest_stage" in decision.answers else None,
                "max_level": max(c["rule_levels"]),
                "sum_levels": sum(c["rule_levels"]),
                "latency_ms": decision.latency_ms,
                "decision": decision.model_dump(mode="json"),
            }
        )

    y = [1 if r["label"] == "attack" else 0 for r in rows]
    probs = [r["p_attack"] for r in rows]
    methods = {
        "model": {
            **classification_report(y, [int(p >= threshold) for p in probs]),
            "auc": roc_auc(y, probs),
            "brier": brier_score(y, probs),
            "ece": expected_calibration_error(y, probs),
        },
        "max_level>=7": {
            **classification_report(y, [int(r["max_level"] >= 7) for r in rows]),
            "auc": roc_auc(y, [r["max_level"] for r in rows]),
            "brier": None,
            "ece": None,
        },
        f"sum_levels>={sum_threshold:g}": {
            **classification_report(y, [int(r["sum_levels"] >= sum_threshold) for r in rows]),
            "auc": roc_auc(y, [r["sum_levels"] for r in rows]),
            "brier": None,
            "ece": None,
        },
    }
    latencies = [r["latency_ms"] for r in rows]
    return {
        "n": len(rows),
        "n_attack": sum(y),
        "threshold": threshold,
        "backend": rows[0]["decision"]["backend"] if rows else None,
        "model_name": rows[0]["decision"]["model_name"] if rows else None,
        "questions_version": backend.questions_version,
        "methods": methods,
        "reliability": reliability_table(y, probs),
        "latency_ms": {"p50": percentile(latencies, 50), "p95": percentile(latencies, 95)} if rows else None,
        "rows": rows,
    }


def fmt(value) -> str:
    if value is None:
        return "-"
    return f"{value:.2f}" if isinstance(value, float) else str(value)


def print_report(result: dict) -> None:
    print(
        f"\nBackend : {result['backend']} ({result['model_name']}), questions {result['questions_version']}, "
        f"{result['n']} clusters dont {result['n_attack']} attaques"
    )
    if result["n"] < MIN_RELIABLE_N:
        print(f"ATTENTION : moins de {MIN_RELIABLE_N} clusters, métriques seulement indicatives.")

    print("\n## Par cluster\n| Cluster | Label | P(attaque) | Priorité | Étape |\n|---|---|---|---|---|")
    for r in result["rows"]:
        print(
            f"| {r['cluster_id']} | {r['label']} | {fmt(r['p_attack'])} | {fmt(r['priority'])} "
            f"| {fmt(r['stage'])} |"
        )

    print("\n## Modèle vs baselines\n| Méthode | Précision | Rappel | F1 | Exactitude | AUC | Brier | ECE |")
    print("|---|---|---|---|---|---|---|---|")
    for name, m in result["methods"].items():
        print(
            f"| {name} | {fmt(m['precision'])} | {fmt(m['recall'])} | {fmt(m['f1'])} | {fmt(m['accuracy'])} "
            f"| {fmt(m['auc'])} | {fmt(m['brier'])} | {fmt(m['ece'])} |"
        )

    print(
        "\n## Fiabilité du modèle (5 tranches)\n| Tranche | n | P moyenne | Fréquence réelle |\n|---|---|---|---|"
    )
    for row in result["reliability"]:
        print(f"| {row['bin']} | {row['n']} | {fmt(row['mean_prob'])} | {fmt(row['frac_positive'])} |")

    if result["latency_ms"]:
        lat = result["latency_ms"]
        print(f"\nLatence : p50 = {lat['p50']:.0f} ms, p95 = {lat['p95']:.0f} ms")


def main(argv: list[str] | None = None) -> dict:
    parser = argparse.ArgumentParser(description="Évalue un backend sur des clusters labellisés")
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    parser.add_argument(
        "--backend", choices=["mock", "jev", "laya"], help="remplace la clé backend de la config"
    )
    parser.add_argument("--data", default=ROOT / "data" / "ablation", type=Path)
    parser.add_argument("--split", choices=["train", "validation", "test"])
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--sum-threshold", type=float, default=30)
    parser.add_argument("--out", type=Path, help="écrit le résultat complet en JSON")
    args = parser.parse_args(argv)

    clusters = load_clusters(args.data, args.split)
    if not clusters:
        sys.exit(f"aucun cluster dans {args.data} (split={args.split})")
    backend = build_backend(load_config(args.config), args.backend)
    result = evaluate(clusters, backend, args.threshold, args.sum_threshold)
    print_report(result)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nRésultat complet : {args.out}")
    return result


if __name__ == "__main__":
    main()
