"""Construit des clusters labellisés Windows à partir de l'émulation APT29 de MITRE (OTRF / Mordor).

Chaîne complète, sans VM Windows :
  1. journaux bruts Windows/Sysmon d'OTRF (jour 1 et jour 2 de l'évaluation ATT&CK APT29) ;
  2. rejoués dans un VRAI gestionnaire Wazuh 4.x par scripts/wazuh_replay.py -> alertes Wazuh ;
  3. corrélés (jevsoc.correlator), résumés (jevsoc.serializer), labellisés ici.

Sources : https://github.com/OTRF/Security-Datasets (compound/apt29), plan d'émulation public :
https://github.com/mitre-attack/attack-arsenal/tree/master/adversary_emulation/APT29

Labellisation : le jeu ne fournit pas de label par événement. On repère les alertes de l'attaquant
avec des INDICATEURS tirés du plan d'émulation public (charges, outils, techniques), chacun
rattaché à une étape. Les artefacts connus pour être bénins sont exclus d'abord. Un cluster est
"attack" s'il contient au moins une alerte indicatrice, et "multi-étapes" s'il couvre au moins
deux étapes différentes. Limite assumée : liste d'indicateurs écrite à la main, à partir du plan
d'émulation et de la lecture des alertes ; une alerte d'attaque sans indicateur reste "bénigne".

Usage : python scripts/build_apt29_dataset.py [--benign-per-day 40] [--seed 0]
"""

from __future__ import annotations

import argparse
import json
import random
import re
from collections import Counter
from pathlib import Path

import yaml

from jevsoc.collector import normalize_wazuh
from jevsoc.config import load_config, resolve
from jevsoc.correlator import correlate, hub_entities, is_judgeable
from jevsoc.serializer import serialize

ROOT = Path(__file__).resolve().parents[1]
ALERTS = ROOT / "data" / "raw" / "apt29" / "alerts"
DAYS = {"apt29_day1": "day1_wazuh.ndjson", "apt29_day2": "day2_wazuh.ndjson"}
HUB_BUCKET_MINUTES = 3  # enregistrements de ~35 min : tranches courtes pour repérer les hubs
# Hubs appris sur l'AUTRE journée (l'historique), jamais sur la journée jugée : l'attaque occupe
# tout l'enregistrement, donc ses propres indices (compte pbeesly, sdelete...) passeraient pour
# des entités de fond et ses liens seraient coupés.
HISTORY = {"apt29_day1": "apt29_day2", "apt29_day2": "apt29_day1"}

# Artefacts bénins connus, exclus AVANT de chercher des indicateurs.
BENIGN = [
    r"__psscriptpolicytest",  # fichier test créé à chaque démarrage de PowerShell
    r"explorer process was accessed by .*(runtimebroker|svchost|searchindexer|ctfmon|smartscreen|sppsvc"
    r"|sihost|userinit|csrss|lsass|onedrive|teams|outlook|azure|systemsettings|securityhealth"
    r"|applicationframehost|wmiprvse)",
    r"c:\\packages\\plugins|windowsazure|microsoft\.azure",  # agents Azure de la VM de lab
]

# Indicateurs du plan d'émulation APT29 -> étape. Recherche insensible à la casse dans la
# description de la règle et les champs Windows de l'alerte.
INDICATORS = [
    ("initial_access", r"3aka3|monkey\.png|\.scr\b|2016_united_states_policy"),
    (
        "execution",
        r"base64 encoded|cmd shell execution|command prompt started by an abnormal process"
        r"|(-nop|hidden).* -e(nc|ncodedcommand)? [a-z0-9+/=]{16,}|\(wmi\) created a powershell"
        r"|certutil to decode|rundll32 executing suspicious"
        r"|explorer process was accessed by .*(powershell|hostui|control\.exe|wsmprovhost)"
        r"|sysinternalssuite|__macosx|\\temp\\[a-z0-9]{8}\\[a-z0-9]{8}\.dll",
    ),
    ("persistence", r"hostui|javamtsup|start-up folder|wmiconsumerevent|user creation command"),
    ("privilege_escalation", r"sdclt|uac bypass|associated to uac|high integrity level"),
    ("defense_evasion", r"sdelete"),
    ("credential_access", r"vaultcli|\.pfx|lsass\)? process was accessed by .*(powershell|m\.exe)|\\m\.exe"),
    ("discovery", r"ldap activity from powershell|dcom/rpc activity from powershell"),
    (
        "lateral_movement",
        r"psexe(c|svc)|\\python\.exe|\\rar\.exe|winrm activity from 10\.|wsmprovhost"
        r"|admin shares by binary dropped|dropped in windows root|created in windows root folder"
        r"|by winrm process",
    ),
    ("collection", r"compression activity|working\.zip|officesupp|draft\.zip"),
    ("exfiltration", r"connection to cloud resource was started by .*powershell"),
]
STAGE_ORDER = [stage for stage, _ in INDICATORS]


def alert_text(raw: dict) -> str:
    """Texte recherché : description de la règle + champs Windows, antislashs dédoublés."""
    eventdata = ((raw.get("data") or {}).get("win") or {}).get("eventdata") or {}
    text = raw["rule"].get("description", "") + " " + " ".join(str(v) for v in eventdata.values())
    return text.replace("\\\\", "\\").lower()


def alert_stages(raw: dict) -> list[str]:
    text = alert_text(raw)
    if any(re.search(pattern, text) for pattern in BENIGN):
        return []
    return [stage for stage, pattern in INDICATORS if re.search(pattern, text)]


def history_hubs(name: str, corr: dict, denylist: set[str]) -> set[str]:
    """Hubs appris sur la journée d'historique associée."""
    with open(ALERTS / DAYS[HISTORY[name]], encoding="utf-8") as handle:
        history = [normalize_wazuh(json.loads(line)) for line in handle]
    return hub_entities(
        history, corr["hub_entity_max_ratio"], {d.lower() for d in denylist}, HUB_BUCKET_MINUTES
    )


def build_day(name: str, corr: dict, denylist: set[str], benign_n: int, rng: random.Random):
    raws = [json.loads(line) for line in open(ALERTS / DAYS[name], encoding="utf-8")]
    stages_by_id = {raw["id"]: alert_stages(raw) for raw in raws}
    alerts = [normalize_wazuh(raw) for raw in raws]
    clusters = correlate(
        alerts,
        corr["max_gap_minutes"],
        corr["window_minutes"],
        corr["hub_entity_max_ratio"],
        denylist,
        corr["max_cluster_size"],
        hubs=history_hubs(name, corr, denylist),
    )
    judgeable = [c for c in clusters if is_judgeable(c, corr["min_alerts"], corr["min_entities"])]

    attack, benign = [], []
    for cluster in judgeable:
        stages = Counter(s for a in cluster for s in stages_by_id.get(a.id, []))
        (attack if stages else benign).append((cluster, stages))
    attack_alerts = sum(1 for s in stages_by_id.values() if s)
    covered = sum(1 for c, _ in attack for a in c if stages_by_id.get(a.id))
    summary = {
        "alerts": len(alerts),
        "attack_alerts": attack_alerts,
        "attack_alerts_in_judged_clusters": covered,
        "clusters": len(clusters),
        "judgeable_clusters": len(judgeable),
        "attack_clusters": len(attack),
        "multistage_clusters": sum(1 for _, s in attack if len(s) >= 2),
        "benign_clusters": len(benign),
        "days": None,  # ~35 min d'enregistrement : pas d'estimation de faux positifs par jour
    }
    sample = benign if len(benign) <= benign_n else rng.sample(benign, benign_n)
    return summary, attack, sample, {id(c): i for i, c in enumerate(judgeable)}


def to_record(day: str, index: int, cluster, stages: Counter, max_entries: int) -> dict:
    is_attack = bool(stages)
    cluster_id = f"{day}-c{index:03d}"  # indépendant du label : corriger un label ne change pas l'id
    furthest = max(stages, key=STAGE_ORDER.index) if is_attack else "none_benign"
    return {
        "scenario": day,
        "variant": "apt29",
        "label": "attack" if is_attack else "benign",
        "kill_chain_stage": furthest,
        "multistage": len(stages) >= 2,
        "notes": ", ".join(f"{s}: {n}" for s, n in stages.most_common()) or "bruit / activité normale",
        "rule_levels": [a.level for a in cluster],
        "state": serialize(cluster_id, cluster, max_entries),
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Clusters labellisés depuis l'émulation APT29 rejouée dans Wazuh"
    )
    parser.add_argument("--benign-per-day", type=int, default=40)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--out", type=Path, default=ROOT / "data" / "apt29")
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
    for day in DAYS:
        summary, attack, benign, judgeable_index = build_day(day, corr, denylist, args.benign_per_day, rng)
        summaries[day] = summary
        for i, (cluster, stages) in sorted(
            ((judgeable_index[id(c)], (c, s)) for c, s in attack + benign), key=lambda x: x[0]
        ):
            record = to_record(day, i, cluster, stages, corr["max_timeline_entries"])
            (args.out / f"{record['state']['cluster_id']}.json").write_text(
                json.dumps(record, ensure_ascii=False) + "\n", encoding="utf-8"
            )
        print(f"{day}: {summary}")
    (args.out / "summary.json").write_text(json.dumps(summaries, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
