"""Construction du state compact d'un cluster (fonction pure, format versionné).

On n'envoie jamais le JSON brut des alertes : trop de bruit et de volume. Le state est un
résumé trié par temps, où les alertes répétées (même règle, même hôte, mêmes IP) sont
regroupées en une seule ligne avec un compteur `count`. Un scan de 7 000 requêtes devient
ainsi une ligne "x7000" au lieu de saturer le contexte du modèle.

Toute évolution de ce format change STATE_VERSION (enregistrée dans chaque décision).
"""

from __future__ import annotations

from jevsoc.collector import Alert

STATE_VERSION = "2"  # v2 : fusion des rafales et priorité aux lignes rares


def _group_key(alert: Alert) -> tuple:
    return (alert.rule_id, alert.host, alert.src_ip, alert.dst_ip, alert.detail[:60])


def _new_entry(alert: Alert, start: float) -> dict:
    entry = {"t": f"+{int((alert.ts - start) // 60)}m"}
    if alert.host:
        entry["host"] = alert.host
    if alert.src_ip or alert.dst_ip:
        entry["flow"] = f"{alert.src_ip or '?'} -> {alert.dst_ip or '?'}"
    if alert.users:
        entry["users"] = alert.users
    entry["level"] = alert.level
    if alert.mitre:
        entry["mitre"] = ",".join(alert.mitre)
    entry["desc"] = alert.description
    if alert.detail and alert.detail != alert.description:
        entry["detail"] = alert.detail
    entry["count"] = 0
    return entry


def build_timeline(
    cluster: list[Alert], max_entries: int = 30, max_variants: int = 3
) -> tuple[list[dict], int]:
    """Timeline regroupée. Renvoie (entrées, nombre de groupes omis faute de place).

    1. Les alertes identiques (même règle, hôte, IP, détail) forment un groupe avec un compteur.
    2. Une règle déclinée en plus de `max_variants` groupes (ex. une erreur 400 par URL lors
       d'un scan) est fusionnée en UNE ligne : le premier exemple + le total.
    3. S'il reste trop de lignes, on garde les plus RARES (puis les plus graves). Un `sudo`
       isolé de niveau 3 en dit plus long que la 7 000e erreur 400 : avec un tri par niveau
       seul (version 1), ces signaux discrets disparaissaient du state.
    """
    start = cluster[0].ts
    groups: dict[tuple, dict] = {}
    for alert in cluster:  # cluster déjà trié par temps : le premier vu fixe "t"
        key = _group_key(alert)
        if key not in groups:
            groups[key] = _new_entry(alert, start)
        groups[key]["count"] += 1

    # Fusion des rafales : règle -> groupes de cette règle
    by_rule: dict[str, list[tuple]] = {}
    for key in groups:
        by_rule.setdefault(key[0], []).append(key)
    entries = []
    for keys in by_rule.values():
        if len(keys) > max_variants:
            merged = dict(groups[keys[0]])  # premier exemple (chronologique)
            merged["count"] = sum(groups[k]["count"] for k in keys)
            merged["level"] = max(groups[k]["level"] for k in keys)
            merged["variants"] = len(keys)
            if len({k[1] for k in keys}) > 1:
                merged.pop("host", None)  # plusieurs hôtes : la liste est déjà dans "hosts"
            if len({(k[2], k[3]) for k in keys}) > 1:
                merged.pop("flow", None)
            entries.append(merged)
        else:
            entries.extend(groups[k] for k in keys)
    entries.sort(key=lambda e: int(e["t"][1:-1]))

    omitted = 0
    if len(entries) > max_entries:
        ranked = sorted(range(len(entries)), key=lambda i: (entries[i]["count"], -entries[i]["level"], i))
        omitted = len(entries) - max_entries
        entries = [entries[i] for i in sorted(ranked[:max_entries])]
    for entry in entries:
        if entry["count"] == 1:
            del entry["count"]  # compteur affiché seulement quand il apporte quelque chose
    return entries, omitted


def serialize(cluster_id: str, cluster: list[Alert], max_entries: int = 30) -> dict:
    """State compact envoyé au modèle de décision."""
    timeline, omitted = build_timeline(cluster, max_entries)
    state = {
        "cluster_id": cluster_id,
        "state_version": STATE_VERSION,
        "window_minutes": int((cluster[-1].ts - cluster[0].ts) // 60),
        "hosts": sorted({a.host for a in cluster if a.host}),
        "ips": sorted({ip for a in cluster for ip in (a.src_ip, a.dst_ip) if ip})[:20],
        "users": sorted({u for a in cluster for u in a.users}),
        "alert_count": len(cluster),
        "max_rule_level": max(a.level for a in cluster),
        "timeline": timeline,
    }
    if omitted:
        state["omitted_groups"] = omitted
    return state
