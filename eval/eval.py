"""Harnais d'évaluation : juge un dossier de clusters labellisés et calcule les métriques.

Usage (depuis la racine du dépôt) :
  python eval/eval.py                                  # backend de config.yaml (mock par défaut)
  python eval/eval.py --backend jev --data data/ait --out eval/results/jev-ait.json
  python eval/eval.py --data data/ait --split test --replay eval/results/jev-ait.json
      (--replay : réutilise les décisions déjà enregistrées, aucun appel API)

Deux questions distinctes sont évaluées :
  1. toutes les attaques (scans compris) contre les bénins ;
  2. les chaînes multi-étapes (au-delà de la reconnaissance) contre les bénins : c'est ce
     que demande la question `is_sophisticated_attack`, et ce que le projet promet.

Méthodes comparées :
  - jev brut          : P(attaque) brute >= 0,5
  - jev calibré       : P recalibrée (config/calibration.yaml) >= seuil d'investigation (`sophisticated_low`)
  - volume            : au moins `volume_min_alerts` alertes
  - système complet   : action de la politique différente de "monitor" (modèle calibré + volume + garde-fous)
  Tous les seuils sont choisis sur la validation (eval/calibrate.py).
  - max_level>=7, sum_levels>=N : baselines d'une ligne, sur les vrais niveaux de règle
Les métriques d'un modèle calibré n'ont de valeur que sur le split de TEST (--split test).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import yaml

from jevsoc.backends import build_backend
from jevsoc.calibration import load_calibration
from jevsoc.config import DEFAULT_CONFIG, load_config, resolve
from jevsoc.metrics import (
    brier_score,
    classification_report,
    expected_calibration_error,
    percentile,
    reliability_table,
    roc_auc,
)
from jevsoc.models import Decision
from jevsoc.policy import policy

ROOT = Path(__file__).resolve().parents[1]
ATTACK_QUESTION = "is_sophisticated_attack"
MIN_RELIABLE_N = 20  # en dessous, les métriques sont seulement indicatives
RECON = "reconnaissance"


def load_splits() -> dict:
    return yaml.safe_load((ROOT / "data" / "splits.yaml").read_text(encoding="utf-8")) or {}


def load_clusters(data_dir: Path, split: str | None) -> list[dict]:
    """Charge les clusters labellisés (*.json sauf summary.json), filtrés par split si demandé."""
    clusters = []
    for path in sorted(data_dir.glob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        if "state" in record:
            clusters.append(record)
    if split:
        splits = load_splits()
        clusters = [c for c in clusters if splits.get(c["scenario"]) == split]
    return clusters


def is_multistage(row: dict) -> bool:
    """Chaîne multi-étapes : champ `multistage` du jeu s'il existe (APT29 : au moins 2 étapes
    distinctes), sinon attaque qui va au-delà de la simple reconnaissance (AIT)."""
    if row["label"] != "attack":
        return False
    if row.get("multistage") is not None:
        return row["multistage"]
    return row["true_stage"] != RECON


def projected_false_positives(rows: list[dict], predictions: list[int], summary: dict | None) -> float | None:
    """Faux positifs par jour estimés sur TOUS les clusters bénins réels, pas seulement l'échantillon.

    Taux de faux positifs mesuré sur l'échantillon bénin de chaque scénario, multiplié par le
    nombre réel de clusters bénins du scénario (summary.json), divisé par sa durée en jours,
    puis moyenné sur les scénarios (un scénario = un SI).
    """
    per_day = []
    for scenario, info in (summary or {}).items():
        sample = [
            p
            for r, p in zip(rows, predictions, strict=True)
            if r["scenario"] == scenario and r["label"] == "benign"
        ]
        if sample and info.get("days"):
            per_day.append(sum(sample) / len(sample) * info["benign_clusters"] / info["days"])
    return sum(per_day) / len(per_day) if per_day else None


def method_scores(rows: list[dict], volume_min: float, investigate_min: float, sum_threshold: float) -> dict:
    """Pour chaque méthode : (score continu pour l'AUC, prédiction binaire, probabiliste ?)."""
    methods = {"jev brut >=0.5": ([r["p_raw"] for r in rows], [int(r["p_raw"] >= 0.5) for r in rows], True)}
    p_best = "p_raw"
    if rows and all(r["p_cal"] is not None for r in rows):
        p_best = "p_cal"
        methods[f"jev calibré >={investigate_min:g}"] = (
            [r["p_cal"] for r in rows],
            [int(r["p_cal"] >= investigate_min) for r in rows],
            True,
        )
    volume = [int(r["alert_count"] >= volume_min) for r in rows]
    methods[f"volume>={volume_min:g}"] = ([r["alert_count"] for r in rows], volume, False)
    # Système complet = ce qui tournerait en production : action de la politique (modèle calibré,
    # garde-fous, règle de volume). Détecté = tout sauf "monitor". Score AUC : volume puis P.
    methods["système complet"] = (
        [v + r[p_best] for r, v in zip(rows, volume, strict=True)],
        [int(r["action"] != "monitor") for r in rows],
        False,
    )
    methods["max_level>=7"] = (
        [r["max_level"] for r in rows],
        [int(r["max_level"] >= 7) for r in rows],
        False,
    )
    methods[f"sum_levels>={sum_threshold:g}"] = (
        [r["sum_levels"] for r in rows],
        [int(r["sum_levels"] >= sum_threshold) for r in rows],
        False,
    )
    return methods


def compare(rows: list[dict], y: list[int], methods: dict, summary: dict | None) -> dict:
    """Précision / rappel / F1 / AUC / FP par jour (+ Brier, ECE pour les probabilités)."""
    out = {}
    for name, (scores, preds, probabilistic) in methods.items():
        out[name] = {
            **classification_report(y, preds),
            "auc": roc_auc(y, scores),
            "brier": brier_score(y, scores) if probabilistic else None,
            "ece": expected_calibration_error(y, scores) if probabilistic else None,
            "fp_per_day": projected_false_positives(rows, preds, summary),
        }
    return out


def subset(rows: list[dict], methods: dict, keep: list[bool]) -> tuple[list[dict], dict]:
    """Restreint les lignes et les scores de chaque méthode à un sous-ensemble."""
    kept_rows = [r for r, k in zip(rows, keep, strict=True) if k]
    kept_methods = {
        name: (
            [s for s, k in zip(scores, keep, strict=True) if k],
            [p for p, k in zip(preds, keep, strict=True) if k],
            probabilistic,
        )
        for name, (scores, preds, probabilistic) in methods.items()
    }
    return kept_rows, kept_methods


def evaluate(
    clusters: list[dict],
    decide,
    questions_version: str,
    thresholds: dict,
    calibration: dict | None = None,
    sum_threshold: float = 415,
    summary: dict | None = None,
) -> dict:
    """`decide(cluster) -> Decision` : appel au backend, ou relecture d'une décision enregistrée."""
    rows = []
    for c in clusters:
        decision = decide(c)
        derived = policy(decision, c["state"], thresholds, calibration)
        rows.append(
            {
                "cluster_id": c["state"]["cluster_id"],
                "scenario": c["scenario"],
                "label": c["label"],
                "true_stage": c.get("kill_chain_stage"),
                "multistage": c.get("multistage"),
                "p_raw": decision.noul(ATTACK_QUESTION),
                "p_cal": derived.p_attack if derived.calibrated else None,
                "priority": decision.score("priority") if "priority" in decision.answers else None,
                "stage": decision.choice("furthest_stage") if "furthest_stage" in decision.answers else None,
                "action": derived.recommended_action,
                "flags": derived.flags,
                "max_level": max(c["rule_levels"]),
                "sum_levels": sum(c["rule_levels"]),
                "alert_count": len(c["rule_levels"]),
                "latency_ms": decision.latency_ms,
                "decision": decision.model_dump(mode="json"),
                "derived": derived.model_dump(mode="json"),
            }
        )

    methods = method_scores(
        rows, thresholds.get("volume_min_alerts") or 10**9, thresholds["sophisticated_low"], sum_threshold
    )
    y_attack = [int(r["label"] == "attack") for r in rows]
    all_attacks = compare(rows, y_attack, methods, summary)

    # Chaînes multi-étapes contre bénins : on retire les scans seuls de la comparaison.
    keep = [not (r["label"] == "attack" and not is_multistage(r)) for r in rows]
    ms_rows, ms_methods = subset(rows, methods, keep)
    y_ms = [int(is_multistage(r)) for r in ms_rows]
    has_both = 0 < sum(y_ms) < len(y_ms)
    multistage = compare(ms_rows, y_ms, ms_methods, summary) if has_both else None

    by_stage = {}
    for stage in sorted({r["true_stage"] for r in rows if r["label"] == "attack"}):
        idx = [i for i, r in enumerate(rows) if r["label"] == "attack" and r["true_stage"] == stage]
        by_stage[stage] = {
            "n": len(idx),
            **{m: sum(p[i] for i in idx) / len(idx) for m, (_, p, _) in methods.items()},
        }

    reliability = {}
    if has_both:
        reliability["jev brut"] = reliability_table(y_ms, [r["p_raw"] for r in ms_rows])
        if rows and all(r["p_cal"] is not None for r in ms_rows):
            reliability["jev calibré"] = reliability_table(y_ms, [r["p_cal"] for r in ms_rows])

    def kind(r):
        if is_multistage(r):
            return "multi-étapes"
        if r["label"] == "attack":
            return "scan" if r["true_stage"] == RECON else "attaque 1 étape"
        return "bénin"

    actions = Counter((kind(r), r["action"]) for r in rows)
    latencies = [r["latency_ms"] for r in rows]
    return {
        "n": len(rows),
        "n_attack": sum(y_attack),
        "n_multistage": sum(int(is_multistage(r)) for r in rows),
        "backend": rows[0]["decision"]["backend"] if rows else None,
        "model_name": rows[0]["decision"]["model_name"] if rows else None,
        "questions_version": questions_version,
        "calibrated": any(m.startswith("jev calibré") for m in methods),
        "all_attacks": all_attacks,
        "multistage": multistage,
        "recall_by_stage": by_stage,
        "reliability": reliability,
        "actions": {f"{k}/{action}": n for (k, action), n in sorted(actions.items())},
        "latency_ms": {"p50": percentile(latencies, 50), "p95": percentile(latencies, 95)} if rows else None,
        "rows": rows,
    }


def fmt(value) -> str:
    if value is None:
        return "-"
    return f"{value:.2f}" if isinstance(value, float) else str(value)


def print_table(title: str, table: dict) -> None:
    print(f"\n## {title}")
    print("| Méthode | Précision | Rappel | F1 | AUC | Brier | ECE | FP/jour estimés |")
    print("|---|---|---|---|---|---|---|---|")
    for name, m in table.items():
        print(
            f"| {name} | {fmt(m['precision'])} | {fmt(m['recall'])} | {fmt(m['f1'])} | {fmt(m['auc'])} "
            f"| {fmt(m['brier'])} | {fmt(m['ece'])} | {fmt(m['fp_per_day'])} |"
        )


def print_report(result: dict, show_clusters: bool = False) -> None:
    print(
        f"\nBackend : {result['backend']} ({result['model_name']}), questions {result['questions_version']}, "
        f"calibration : {'oui' if result['calibrated'] else 'non'} ; {result['n']} clusters dont "
        f"{result['n_attack']} attaques ({result['n_multistage']} chaînes multi-étapes)"
    )
    if result["n"] < MIN_RELIABLE_N:
        print(f"ATTENTION : moins de {MIN_RELIABLE_N} clusters, métriques seulement indicatives.")

    if show_clusters:
        print("\n## Par cluster\n| Cluster | Label | P brute | P calibrée | Priorité | Étape | Action |")
        print("|---|---|---|---|---|---|---|")
        for r in result["rows"]:
            print(
                f"| {r['cluster_id']} | {r['label']} | {fmt(r['p_raw'])} | {fmt(r['p_cal'])} "
                f"| {fmt(r['priority'])} | {fmt(r['stage'])} | {r['action']} |"
            )

    if result["multistage"]:
        print_table("Chaînes multi-étapes contre bénins (scans seuls exclus)", result["multistage"])
    print_table("Toutes les attaques (scans compris) contre bénins", result["all_attacks"])

    names = list(result["all_attacks"])
    print("\n## Rappel par étape réelle\n| Étape | n | " + " | ".join(names) + " |")
    print("|---|---|" + "---|" * len(names))
    for stage, info in result["recall_by_stage"].items():
        print(f"| {stage} | {info['n']} | " + " | ".join(fmt(info[m]) for m in names) + " |")

    print("\n## Actions de la politique\n| Type de cluster / action | Clusters |\n|---|---|")
    for key, n in result["actions"].items():
        print(f"| {key} | {n} |")

    for name, table in result["reliability"].items():
        print(f"\n## Fiabilité {name} (chaînes multi-étapes)\n| Tranche | n | P moyenne | Fréquence réelle |")
        print("|---|---|---|---|")
        for row in table:
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
    parser.add_argument("--replay", type=Path, help="résultat JSON précédent : réutilise ses décisions")
    parser.add_argument("--no-calibration", action="store_true", help="ignore config/calibration.yaml")
    parser.add_argument("--sum-threshold", type=float, default=415)
    parser.add_argument("--show-clusters", action="store_true", help="affiche une ligne par cluster")
    parser.add_argument("--out", type=Path, help="écrit le résultat complet en JSON")
    args = parser.parse_args(argv)

    clusters = load_clusters(args.data, args.split)
    if not clusters:
        sys.exit(f"aucun cluster dans {args.data} (split={args.split})")
    config = load_config(args.config)

    if args.replay:
        recorded = {
            r["cluster_id"]: Decision.model_validate(r["decision"])
            for r in json.loads(args.replay.read_text(encoding="utf-8"))["rows"]
        }
        missing = [c["state"]["cluster_id"] for c in clusters if c["state"]["cluster_id"] not in recorded]
        if missing:
            sys.exit(f"{len(missing)} clusters absents de {args.replay} (ex. {missing[0]})")
        first = next(iter(recorded.values()))
        backend_name, questions_version = first.backend, first.questions_version

        def decide(c):
            return recorded[c["state"]["cluster_id"]]

    else:
        backend = build_backend(config, args.backend)
        backend_name, questions_version = backend.name, backend.questions_version

        def decide(c):
            return backend.decide(c["state"])

    calibration = {}
    if not args.no_calibration and config.get("calibration_file"):
        calibration = load_calibration(resolve(config, config["calibration_file"]), backend_name)
    summary_path = args.data / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else None

    result = evaluate(
        clusters, decide, questions_version, config["policy"], calibration, args.sum_threshold, summary
    )
    print_report(result, show_clusters=args.show_clusters or result["n"] <= 40)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nRésultat complet : {args.out}")
    return result


if __name__ == "__main__":
    main()
