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
from collections import Counter
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
from jevsoc.policy import policy

ROOT = Path(__file__).resolve().parents[1]
ATTACK_QUESTION = "is_sophisticated_attack"
MIN_RELIABLE_N = 20  # en dessous, les métriques sont seulement indicatives


def load_clusters(data_dir: Path, split: str | None) -> list[dict]:
    """Charge les clusters labellisés (*.json sauf summary.json), filtrés par split si demandé."""
    clusters = []
    for path in sorted(data_dir.glob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        if "state" in record:
            clusters.append(record)
    if split:
        splits = yaml.safe_load((ROOT / "data" / "splits.yaml").read_text(encoding="utf-8")) or {}
        clusters = [c for c in clusters if splits.get(c["scenario"]) == split]
    return clusters


def baseline_report(y: list[int], scores: list[float], threshold: float) -> dict:
    """Une baseline = un score simple + un seuil. Pas probabiliste : ni Brier ni ECE."""
    return {
        **classification_report(y, [int(s >= threshold) for s in scores]),
        "auc": roc_auc(y, scores),
        "brier": None,
        "ece": None,
    }


def projected_false_positives(rows: list[dict], predictions: list[int], summary: dict) -> float | None:
    """Faux positifs par jour estimés sur TOUS les clusters bénins réels, pas seulement l'échantillon.

    Taux de faux positifs mesuré sur l'échantillon bénin de chaque scénario, multiplié par le
    nombre réel de clusters bénins du scénario (summary.json), divisé par sa durée en jours.
    """
    if not summary:
        return None
    per_day = []
    for scenario, info in summary.items():
        sample = [
            p
            for r, p in zip(rows, predictions, strict=True)
            if r["scenario"] == scenario and r["label"] == "benign"
        ]
        if sample and info.get("days"):
            per_day.append(sum(sample) / len(sample) * info["benign_clusters"] / info["days"])
    return sum(per_day) / len(per_day) if per_day else None  # moyenne par scénario (un SI par scénario)


def tuned_comparison(rows: list[dict], splits: dict, summary: dict | None) -> dict | None:
    """Comparaison équitable : seuil de chaque méthode choisi sur la validation, mesuré sur le test.

    Pour chaque méthode (modèle et baselines), on retient le seuil qui maximise le F1 sur les
    scénarios "validation", puis on rapporte précision / rappel / F1 / AUC / FP par jour sur
    les scénarios "test". Aucune méthode n'est réglée sur le test.
    """
    val = [r for r in rows if splits.get(r["scenario"]) == "validation"]
    test = [r for r in rows if splits.get(r["scenario"]) == "test"]
    if not val or not test or len({r["label"] for r in val}) < 2:
        return None
    scores = {
        "model": lambda r: r["p_attack"],
        "max_level": lambda r: r["max_level"],
        "sum_levels": lambda r: r["sum_levels"],
        "alert_count": lambda r: r["alert_count"],
    }
    y_val = [int(r["label"] == "attack") for r in val]
    y_test = [int(r["label"] == "attack") for r in test]
    out = {"n_validation": len(val), "n_test": len(test), "n_test_attack": sum(y_test), "methods": {}}
    for name, score in scores.items():
        candidates = sorted({score(r) for r in val})
        best = max(
            candidates,
            key=lambda t: (classification_report(y_val, [int(score(r) >= t) for r in val])["f1"], t),
        )
        preds = [int(score(r) >= best) for r in test]
        out["methods"][name] = {
            "threshold": best,
            **classification_report(y_test, preds),
            "auc": roc_auc(y_test, [score(r) for r in test]),
            "fp_per_day": projected_false_positives(test, preds, summary or {}),
        }
    return out


def evaluate(
    clusters: list[dict],
    backend,
    threshold: float = 0.5,
    sum_threshold: float = 30,
    count_threshold: float = 100,
    thresholds: dict | None = None,
    summary: dict | None = None,
) -> dict:
    """Interroge le backend sur chaque cluster et calcule toutes les métriques."""
    rows = []
    for c in clusters:
        decision = backend.decide(c["state"])
        derived = policy(decision, c["state"], thresholds) if thresholds else None
        rows.append(
            {
                "cluster_id": c["state"]["cluster_id"],
                "scenario": c["scenario"],
                "label": c["label"],
                "true_stage": c.get("kill_chain_stage"),
                "p_attack": decision.noul(ATTACK_QUESTION),
                "priority": decision.score("priority") if "priority" in decision.answers else None,
                "stage": decision.choice("furthest_stage") if "furthest_stage" in decision.answers else None,
                "action": derived.recommended_action if derived else None,
                "max_level": max(c["rule_levels"]),
                "sum_levels": sum(c["rule_levels"]),
                "alert_count": len(c["rule_levels"]),
                "latency_ms": decision.latency_ms,
                "decision": decision.model_dump(mode="json"),
                "derived": derived.model_dump(mode="json") if derived else None,
            }
        )

    y = [1 if r["label"] == "attack" else 0 for r in rows]
    probs = [r["p_attack"] for r in rows]
    predictions = {
        "model": [int(p >= threshold) for p in probs],
        "max_level>=7": [int(r["max_level"] >= 7) for r in rows],
        f"sum_levels>={sum_threshold:g}": [int(r["sum_levels"] >= sum_threshold) for r in rows],
        f"alert_count>={count_threshold:g}": [int(r["alert_count"] >= count_threshold) for r in rows],
    }
    methods = {
        "model": {
            **classification_report(y, predictions["model"]),
            "auc": roc_auc(y, probs),
            "brier": brier_score(y, probs),
            "ece": expected_calibration_error(y, probs),
        },
        "max_level>=7": baseline_report(y, [r["max_level"] for r in rows], 7),
        f"sum_levels>={sum_threshold:g}": baseline_report(y, [r["sum_levels"] for r in rows], sum_threshold),
        f"alert_count>={count_threshold:g}": baseline_report(
            y, [r["alert_count"] for r in rows], count_threshold
        ),
    }
    for name, preds in predictions.items():
        methods[name]["fp_per_day"] = projected_false_positives(rows, preds, summary or {})

    # Rappel par étape réelle : les étapes discrètes sont-elles trouvées ?
    by_stage = {}
    for stage in sorted({r["true_stage"] for r in rows if r["label"] == "attack"}):
        idx = [i for i, r in enumerate(rows) if r["label"] == "attack" and r["true_stage"] == stage]
        by_stage[stage] = {
            "n": len(idx),
            **{m: sum(p[i] for i in idx) / len(idx) for m, p in predictions.items()},
        }

    actions = Counter((r["label"], r["action"]) for r in rows if r["action"])
    splits = yaml.safe_load((ROOT / "data" / "splits.yaml").read_text(encoding="utf-8")) or {}
    latencies = [r["latency_ms"] for r in rows]
    return {
        "n": len(rows),
        "n_attack": sum(y),
        "threshold": threshold,
        "backend": rows[0]["decision"]["backend"] if rows else None,
        "model_name": rows[0]["decision"]["model_name"] if rows else None,
        "questions_version": backend.questions_version,
        "methods": methods,
        "recall_by_stage": by_stage,
        "tuned": tuned_comparison(rows, splits, summary),
        "actions": {f"{label}/{action}": n for (label, action), n in sorted(actions.items())},
        "reliability": reliability_table(y, probs),
        "latency_ms": {"p50": percentile(latencies, 50), "p95": percentile(latencies, 95)} if rows else None,
        "rows": rows,
    }


def fmt(value) -> str:
    if value is None:
        return "-"
    return f"{value:.2f}" if isinstance(value, float) else str(value)


def print_report(result: dict, show_clusters: bool = False) -> None:
    print(
        f"\nBackend : {result['backend']} ({result['model_name']}), questions {result['questions_version']}, "
        f"{result['n']} clusters dont {result['n_attack']} attaques"
    )
    if result["n"] < MIN_RELIABLE_N:
        print(f"ATTENTION : moins de {MIN_RELIABLE_N} clusters, métriques seulement indicatives.")

    if show_clusters:
        print("\n## Par cluster\n| Cluster | Label | P(attaque) | Priorité | Étape | Action |")
        print("|---|---|---|---|---|---|")
        for r in result["rows"]:
            print(
                f"| {r['cluster_id']} | {r['label']} | {fmt(r['p_attack'])} | {fmt(r['priority'])} "
                f"| {fmt(r['stage'])} | {fmt(r['action'])} |"
            )

    print("\n## Modèle vs baselines")
    print("| Méthode | Précision | Rappel | F1 | Exactitude | AUC | Brier | ECE | FP/jour estimés |")
    print("|---|---|---|---|---|---|---|---|---|")
    for name, m in result["methods"].items():
        print(
            f"| {name} | {fmt(m['precision'])} | {fmt(m['recall'])} | {fmt(m['f1'])} | {fmt(m['accuracy'])} "
            f"| {fmt(m['auc'])} | {fmt(m['brier'])} | {fmt(m['ece'])} | {fmt(m.get('fp_per_day'))} |"
        )

    if result["recall_by_stage"]:
        names = list(result["methods"])
        print("\n## Rappel par étape réelle\n| Étape | n | " + " | ".join(names) + " |")
        print("|---|---|" + "---|" * len(names))
        for stage, info in result["recall_by_stage"].items():
            print(f"| {stage} | {info['n']} | " + " | ".join(fmt(info[m]) for m in names) + " |")

    tuned = result.get("tuned")
    if tuned:
        print(
            f"\n## Comparaison équitable : seuils choisis sur validation ({tuned['n_validation']} clusters), "
            f"mesurés sur test ({tuned['n_test']} clusters dont {tuned['n_test_attack']} attaques)"
        )
        print(
            "| Méthode | Seuil | Précision | Rappel | F1 | AUC | FP/jour estimés |\n|---|---|---|---|---|---|---|"
        )
        for name, m in tuned["methods"].items():
            print(
                f"| {name} | {m['threshold']:g} | {fmt(m['precision'])} | {fmt(m['recall'])} | {fmt(m['f1'])} "
                f"| {fmt(m['auc'])} | {fmt(m['fp_per_day'])} |"
            )

    if result["actions"]:
        print("\n## Actions de la politique\n| Label / action | Clusters |\n|---|---|")
        for key, n in result["actions"].items():
            print(f"| {key} | {n} |")

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
    parser.add_argument("--count-threshold", type=float, default=100)
    parser.add_argument("--show-clusters", action="store_true", help="affiche une ligne par cluster")
    parser.add_argument("--out", type=Path, help="écrit le résultat complet en JSON")
    args = parser.parse_args(argv)

    clusters = load_clusters(args.data, args.split)
    if not clusters:
        sys.exit(f"aucun cluster dans {args.data} (split={args.split})")
    config = load_config(args.config)
    backend = build_backend(config, args.backend)
    summary_path = args.data / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else None
    result = evaluate(
        clusters,
        backend,
        args.threshold,
        args.sum_threshold,
        args.count_threshold,
        thresholds=config["policy"],
        summary=summary,
    )
    print_report(result, show_clusters=args.show_clusters or result["n"] <= 40)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nRésultat complet : {args.out}")
    return result


if __name__ == "__main__":
    main()
