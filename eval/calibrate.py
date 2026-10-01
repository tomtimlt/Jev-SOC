"""Ajuste la couche de décision sur le split de VALIDATION, à partir de décisions déjà enregistrées.

Deux réglages, sans aucun appel API :
  1. calibration de Platt de P(is_sophisticated_attack) ; cible = chaîne multi-étapes
     (attaque au-delà de la reconnaissance), car c'est ce que la question demande au modèle ;
  2. seuil de la règle de volume : le plus petit nombre d'alertes qu'aucun cluster bénin de
     validation n'atteint (zéro faux positif sur la validation).

Écrit config/calibration.yaml et affiche le seuil de volume à reporter dans config.yaml.
Le test n'est jamais utilisé pour régler : il est seulement affiché pour information.

Usage : python eval/calibrate.py --results eval/results/jev-ait.json --data data/ait
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from jevsoc.calibration import fit_platt
from jevsoc.metrics import brier_score, expected_calibration_error
from jevsoc.serializer import STATE_VERSION

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "eval"))
from eval import is_multistage, load_clusters, load_splits  # noqa: E402

QUESTION = "is_sophisticated_attack"


def main(argv: list[str] | None = None) -> dict:
    parser = argparse.ArgumentParser(description="Calibration et seuil de volume sur la validation")
    parser.add_argument("--results", type=Path, default=ROOT / "eval" / "results" / "jev-ait.json")
    parser.add_argument("--data", type=Path, default=ROOT / "data" / "ait")
    parser.add_argument("--out", type=Path, default=ROOT / "config" / "calibration.yaml")
    args = parser.parse_args(argv)

    result = json.loads(args.results.read_text(encoding="utf-8"))
    decisions = {r["cluster_id"]: r["decision"] for r in result["rows"]}
    splits = load_splits()
    rows = []
    for c in load_clusters(args.data, None):
        d = decisions[c["state"]["cluster_id"]]
        rows.append(
            {
                "split": splits.get(c["scenario"]),
                "label": c["label"],
                "true_stage": c["kill_chain_stage"],
                "alert_count": len(c["rule_levels"]),
                "p": d["answers"][QUESTION]["probability"],
                "model_name": d["model_name"],
                "backend": d["backend"],
                "questions_version": d["questions_version"],
            }
        )
    val = [r for r in rows if r["split"] == "validation"]
    test = [r for r in rows if r["split"] == "test"]
    y_val = [int(is_multistage(r)) for r in val]

    calibrator = fit_platt([r["p"] for r in val], y_val)
    print(f"Calibration ajustée sur {len(val)} clusters de validation ({sum(y_val)} chaînes multi-étapes) :")
    print(f"  P_calibrée = sigmoïde({calibrator.a:.3f} × logit(P_brute) + {calibrator.b:.3f})")
    for p in (0.2, 0.3, 0.4, 0.5, 0.6, 0.8):
        print(f"  P brute {p:.1f} -> calibrée {calibrator(p):.2f}")

    print("\n| Split | Probabilités | Brier | ECE |\n|---|---|---|---|")
    for name, part in (("validation", val), ("test", test)):
        y = [int(is_multistage(r)) for r in part]
        raw = [r["p"] for r in part]
        cal = [calibrator(p) for p in raw]
        print(f"| {name} | brutes | {brier_score(y, raw):.3f} | {expected_calibration_error(y, raw):.3f} |")
        print(
            f"| {name} | calibrées | {brier_score(y, cal):.3f} | {expected_calibration_error(y, cal):.3f} |"
        )

    # Seuil d'investigation : milieu de l'écart entre le bénin le plus suspect et la chaîne la
    # moins suspecte de la validation (marge maximale de part et d'autre), arrondi à 0,01.
    ms_cal = [calibrator(r["p"]) for r in val if is_multistage(r)]
    benign_cal = [calibrator(r["p"]) for r in val if r["label"] == "benign"]
    gap_low, gap_high = max(benign_cal), min(ms_cal)
    investigate_min = round((gap_low + gap_high) / 2, 2) if gap_low < gap_high else round(gap_high, 2)
    benign_flagged = sum(1 for p in benign_cal if p >= investigate_min)
    print(
        f"\nSeuil d'investigation : bénin de validation le plus haut = {gap_low:.2f}, "
        f"chaînes de validation = {sorted(round(p, 2) for p in ms_cal)}"
    )
    print(
        f"  -> sophisticated_low recommandé = {investigate_min:.2f} "
        f"({benign_flagged}/{len(benign_cal)} bénins de validation au-dessus)"
    )

    benign_max = max(r["alert_count"] for r in val if r["label"] == "benign")
    volume_min = benign_max + 1
    caught = sum(1 for r in val if r["label"] == "attack" and r["alert_count"] >= volume_min)
    print(f"\nRègle de volume : plus gros cluster bénin de validation = {benign_max} alertes")
    print(f"  -> volume_min_alerts recommandé = {volume_min} ({caught} attaques de validation au-dessus)")

    first = val[0]
    calibration = {
        first["backend"]: {
            QUESTION: {
                "a": round(calibrator.a, 4),
                "b": round(calibrator.b, 4),
                "target": "chaîne multi-étapes (attaque au-delà de la reconnaissance)",
                "fitted_on": "AIT-ADS, scénarios de validation : "
                + ", ".join(sorted({s for s, v in splits.items() if v == "validation"})),
                "n_positive": sum(y_val),
                "n_negative": len(y_val) - sum(y_val),
                "model_name": first["model_name"],
                "questions_version": first["questions_version"],
                "state_version": STATE_VERSION,
            }
        }
    }
    header = (
        "# Généré par eval/calibrate.py (ne pas éditer à la main). Ajusté sur la VALIDATION uniquement.\n"
    )
    args.out.write_text(
        header + yaml.safe_dump(calibration, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    print(f"\nÉcrit : {args.out}")
    return {"calibrator": calibrator, "volume_min_alerts": volume_min, "sophisticated_low": investigate_min}


if __name__ == "__main__":
    main()
