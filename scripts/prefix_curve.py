"""Courbe de soupçon : comment évolue la décision quand la chaîne se dévoile alerte par alerte.

Pour chaque scénario (variante full), on envoie au backend les k premières alertes,
pour k = 1..n, comme le ferait le système en production en re-décidant un cluster
à chaque nouvelle alerte. C'est la base de la démo live.

Pour ne pas souffler la suite au modèle, le state d'un préfixe ne contient que ce qui
est déjà visible : hôtes et niveau max des k premières alertes, et seulement les
comptes déjà apparus (le premier compte du scénario + ceux cités dans les descriptions).

Usage : python scripts/prefix_curve.py [--backend jev] [--out eval/results/prefix_curve.json]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

from jevsoc.backends import build_backend
from jevsoc.config import DEFAULT_CONFIG, load_config
from jevsoc.policy import policy

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ("attack", "benign", "adversarial")


def _load_make_variants():
    spec = importlib.util.spec_from_file_location("make_variants", ROOT / "scripts" / "make_variants.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


make_variants = _load_make_variants()


def prefix_state(scenario: str, k: int) -> dict:
    """State du cluster tel qu'il est connu après ses k premières alertes."""
    full = make_variants.build(scenario, "full")
    timeline = full["timeline"][:k]
    text = json.dumps(timeline)
    users = [u for i, u in enumerate(full["users"]) if i == 0 or u in text]
    return {
        "cluster_id": f"{scenario}-prefix{k}",
        "hosts": sorted({e["host"] for e in timeline}),
        "users": users,
        "alert_count": k,
        "timeline": timeline,
        "max_rule_level": max(e["level"] for e in timeline),
    }


def run(backend, thresholds: dict) -> list[dict]:
    rows = []
    for scenario in SCENARIOS:
        n = len(make_variants.CLUSTERS[scenario]["events"])
        for k in range(1, n + 1):
            state = prefix_state(scenario, k)
            d = backend.decide(state)
            derived = policy(d, state, thresholds)
            rows.append(
                {
                    "scenario": scenario,
                    "k": k,
                    "last_alert": state["timeline"][-1]["desc"],
                    "p_attack": d.noul("is_sophisticated_attack"),
                    "priority": d.score("priority"),
                    "stage": d.choice("furthest_stage"),
                    "contain": d.noul("should_contain_now"),
                    "escalate": d.noul("should_escalate_to_ir"),
                    "action": " + ".join(derived.actions),
                    "flags": ", ".join(derived.flags),
                    "latency_ms": d.latency_ms,
                }
            )
    return rows


def print_rows(rows: list[dict]) -> None:
    for scenario in SCENARIOS:
        print(
            f"\n## {scenario}\n| k | Dernière alerte | P(attaque) | Priorité | Étape | Isoler | Escalader | Action | Drapeaux |"
        )
        print("|---|---|---|---|---|---|---|---|---|")
        for r in (r for r in rows if r["scenario"] == scenario):
            print(
                f"| {r['k']} | {r['last_alert'][:60]} | {r['p_attack']:.2f} | {r['priority']:.2f} "
                f"| {r['stage']} | {r['contain']:.2f} | {r['escalate']:.2f} | {r['action']} | {r['flags'] or '-'} |"
            )


def main(argv: list[str] | None = None) -> list[dict]:
    parser = argparse.ArgumentParser(description="Courbe de soupçon par préfixe de chaîne")
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    parser.add_argument("--backend", choices=["mock", "jev", "laya"])
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)

    config = load_config(args.config)
    rows = run(build_backend(config, args.backend), config["policy"])
    print_rows(rows)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    return rows


if __name__ == "__main__":
    main()
