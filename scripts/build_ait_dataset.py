"""Construit des clusters labellisés à partir du jeu public AIT-ADS (vraies alertes Wazuh).

Source : AIT Alert Data Set, Landauer et al. 2024, licence CC-BY 4.0,
https://zenodo.org/record/8263181. Télécharger ait_ads.zip + labels.csv dans data/raw/ait_ads/.

Étapes, pour chaque scénario :
  1. lecture et normalisation des alertes Wazuh/Suricata (jevsoc.collector) ;
  2. corrélation en clusters (jevsoc.correlator), paramètres de config.yaml ;
  3. on ne garde que les clusters jugeables ;
  4. labellisation (voir `label_alert`) ;
  5. tous les clusters d'attaque + un échantillon aléatoire fixe de clusters bénins sont
     écrits dans data/ait/, au format lu par eval/eval.py ;
  6. data/ait/summary.json garde les vrais totaux, pour estimer le volume de faux positifs.

Labellisation (même principe que les auteurs du jeu, qui labellisent par fenêtres de temps) :
une alerte est "attaque" si elle tombe dans une fenêtre de phase d'attaque ET que sa règle
n'est pas du bruit de fond (règle vue hors attaque dans au moins 3 heures différentes,
ex. ClamAV, Dovecot). Un cluster est "attaque" s'il contient au moins une alerte d'attaque.

Usage : python scripts/build_ait_dataset.py [--benign-per-scenario 30] [--seed 0]
"""

from __future__ import annotations

import argparse
import csv
import json
import random
from collections import Counter
from pathlib import Path

import yaml

from jevsoc.collector import read_alerts
from jevsoc.config import load_config, resolve
from jevsoc.correlator import correlate, is_judgeable
from jevsoc.serializer import serialize

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw" / "ait_ads"
SCENARIOS = ("fox", "harrison", "russellmitchell", "santos", "shaw", "wardbeck", "wheeler", "wilson")
BACKGROUND_MIN_HOURS = 3

# Phase AIT -> étape de kill chain, dans l'ordre de progression.
PHASE_STAGE = {
    "network_scans": "reconnaissance",
    "service_scans": "reconnaissance",
    "wpscan": "reconnaissance",
    "dirb": "reconnaissance",
    "webshell": "initial_access",
    "cracking": "credential_access",
    "reverse_shell": "execution",
    "privilege_escalation": "privilege_escalation",
    "service_stop": "impact",
    "dnsteal": "exfiltration",
}
STAGE_ORDER = list(dict.fromkeys(PHASE_STAGE.values()))


def load_phases(scenario: str) -> list[tuple[float, float, str]]:
    with open(RAW / "labels.csv", encoding="utf-8") as handle:
        return [
            (float(r["start"]), float(r["end"]), r["attack"])
            for r in csv.DictReader(handle)
            if r["scenario"] == scenario
        ]


def phase_of(ts: float, phases) -> str | None:
    for start, end, name in phases:
        if start <= ts <= end:
            return name
    return None


def background_rules(alerts, phases) -> set[str]:
    """Règles qui se déclenchent aussi hors attaque, dans au moins N heures différentes."""
    hours: dict[str, set[int]] = {}
    for a in alerts:
        if phase_of(a.ts, phases) is None:
            hours.setdefault(a.rule_id, set()).add(int(a.ts // 3600))
    return {rule for rule, h in hours.items() if len(h) >= BACKGROUND_MIN_HOURS}


def label_alert(alert, phases, background) -> str | None:
    """Phase d'attaque de l'alerte, ou None si elle est bénigne / bruit de fond."""
    phase = phase_of(alert.ts, phases)
    return phase if phase and alert.rule_id not in background else None


def build_scenario(scenario: str, corr: dict, denylist: set[str], benign_n: int, rng: random.Random):
    alerts = list(read_alerts(RAW / f"{scenario}_wazuh.json"))
    phases = load_phases(scenario)
    background = background_rules(alerts, phases)
    clusters = correlate(
        alerts,
        corr["max_gap_minutes"],
        corr["window_minutes"],
        corr["hub_entity_max_ratio"],
        denylist,
        corr["max_cluster_size"],
    )
    judgeable = [c for c in clusters if is_judgeable(c, corr["min_alerts"], corr["min_entities"])]

    attack, benign = [], []
    for cluster in judgeable:
        phase_counts = Counter(p for a in cluster if (p := label_alert(a, phases, background)))
        (attack if phase_counts else benign).append((cluster, phase_counts))

    attack_alerts = sum(1 for a in alerts if label_alert(a, phases, background))
    covered = sum(sum(pc.values()) for _, pc in attack)
    summary = {
        "alerts": len(alerts),
        "attack_alerts": attack_alerts,
        "attack_alerts_in_judged_clusters": covered,
        "clusters": len(clusters),
        "judgeable_clusters": len(judgeable),
        "attack_clusters": len(attack),
        "benign_clusters": len(benign),
        "days": round((max(a.ts for a in alerts) - min(a.ts for a in alerts)) / 86400, 1),
        "missed_phases": sorted(
            {phase_of(a.ts, phases) for a in alerts if label_alert(a, phases, background)}
            - {p for _, pc in attack for p in pc}
        ),
    }
    sample = benign if len(benign) <= benign_n else rng.sample(benign, benign_n)
    return summary, attack, sample


def to_record(scenario: str, index: int, cluster, phase_counts, max_entries: int) -> dict:
    is_attack = bool(phase_counts)
    stage = "none_benign"
    if is_attack:
        stage = max((PHASE_STAGE[p] for p in phase_counts), key=STAGE_ORDER.index)
    cluster_id = f"{scenario}-{'att' if is_attack else 'ben'}{index:03d}"
    return {
        "scenario": scenario,
        "variant": "ait",
        "label": "attack" if is_attack else "benign",
        "kill_chain_stage": stage,
        "notes": ", ".join(f"{p}: {n}" for p, n in phase_counts.most_common()) or "bruit / activité normale",
        "rule_levels": [a.level for a in cluster],
        "state": serialize(cluster_id, cluster, max_entries),
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Clusters labellisés depuis AIT-ADS")
    parser.add_argument("--scenarios", nargs="*", default=list(SCENARIOS))
    parser.add_argument("--benign-per-scenario", type=int, default=30)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--out", type=Path, default=ROOT / "data" / "ait")
    args = parser.parse_args(argv)

    config = load_config()
    corr = config["correlation"]
    deny_yaml = yaml.safe_load(resolve(config, corr["denylist_file"]).read_text(encoding="utf-8")) or {}
    denylist = {str(x) for values in deny_yaml.values() for x in values}
    rng = random.Random(args.seed)

    args.out.mkdir(parents=True, exist_ok=True)
    for old in args.out.glob("*.json"):
        old.unlink()
    summaries = {}
    for scenario in args.scenarios:
        summary, attack, benign = build_scenario(scenario, corr, denylist, args.benign_per_scenario, rng)
        summaries[scenario] = summary
        for i, (cluster, pc) in enumerate(attack + benign):
            record = to_record(scenario, i, cluster, pc, corr["max_timeline_entries"])
            (args.out / f"{record['state']['cluster_id']}.json").write_text(
                json.dumps(record, ensure_ascii=False) + "\n", encoding="utf-8"
            )
        print(f"{scenario}: {summary}")
    (args.out / "summary.json").write_text(json.dumps(summaries, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
