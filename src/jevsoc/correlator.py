"""Regroupement des alertes en clusters : union-find sur les entités partagées.

Principe : deux alertes sont reliées si elles partagent une entité (hôte, IP, utilisateur)
et si elles sont proches dans le temps (écart <= max_gap_minutes). Les composantes
connexes forment les clusters.

Protection contre les entités "hub" (manager Wazuh, DNS, SYSTEM...) qui relieraient tout :
  - denylist configurable (config/entity_denylist.yaml) ;
  - présence permanente : une entité vue dans plus de `hub_ratio` des heures ne crée aucun lien ;
  - durée et taille max : un cluster trop long ou trop gros est découpé en tranches de temps.

Version hors ligne (tout le fichier d'un coup), suffisante pour l'évaluation. La version
incrémentale (cluster ouvert re-décidé à chaque nouvelle alerte) viendra pour la démo live.
"""

from __future__ import annotations

from jevsoc.collector import Alert


class UnionFind:
    """Structure classique : chaque élément pointe vers un représentant de son groupe."""

    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]  # compression de chemin
            i = self.parent[i]
        return i

    def union(self, a: int, b: int) -> None:
        self.parent[self.find(a)] = self.find(b)


def hub_entities(alerts: list[Alert], hub_ratio: float, denylist: set[str]) -> set[str]:
    """Entités qui ne doivent créer aucun lien : denylist + entités présentes en permanence.

    "Permanente" = vue dans plus de `hub_ratio` des heures couvertes par les alertes. On ne
    compte PAS le nombre d'alertes : un attaquant qui scanne génère énormément d'alertes en
    peu de temps, et le prendre pour un hub couperait justement la chaîne qu'on cherche.
    Un serveur mail ou un DNS, eux, apparaissent heure après heure.
    """
    hours_by_entity: dict[str, set[int]] = {}
    for alert in alerts:
        for entity in alert.entities():
            hours_by_entity.setdefault(entity, set()).add(int(alert.ts // 3600))
    total_hours = len({int(a.ts // 3600) for a in alerts}) or 1
    permanent = {e for e, hours in hours_by_entity.items() if len(hours) > hub_ratio * total_hours}
    denied = {e for e in hours_by_entity if e.split(":", 1)[1].lower() in denylist}
    return permanent | denied


def _split(cluster: list[Alert], window_s: float, max_size: int) -> list[list[Alert]]:
    """Découpe un cluster trop long (durée > fenêtre) ou trop gros en tranches consécutives."""
    chunks, current = [], []
    for alert in cluster:
        if current and (alert.ts - current[0].ts > window_s or len(current) >= max_size):
            chunks.append(current)
            current = []
        current.append(alert)
    if current:
        chunks.append(current)
    return chunks


def correlate(
    alerts: list[Alert],
    max_gap_minutes: float = 60,
    window_minutes: float = 240,
    hub_ratio: float = 0.2,
    denylist: set[str] | None = None,
    max_cluster_size: int = 5000,
) -> list[list[Alert]]:
    """Renvoie les clusters, chacun trié par temps, eux-mêmes triés par début."""
    alerts = sorted(alerts, key=lambda a: a.ts)
    hubs = hub_entities(alerts, hub_ratio, {d.lower() for d in denylist or set()})
    uf = UnionFind(len(alerts))
    last_seen: dict[str, int] = {}  # entité -> index de la dernière alerte qui la portait
    max_gap_s = max_gap_minutes * 60
    for i, alert in enumerate(alerts):
        for entity in alert.entities():
            if entity in hubs:
                continue
            j = last_seen.get(entity)
            if j is not None and alert.ts - alerts[j].ts <= max_gap_s:
                uf.union(i, j)
            last_seen[entity] = i

    groups: dict[int, list[Alert]] = {}
    for i, alert in enumerate(alerts):
        groups.setdefault(uf.find(i), []).append(alert)
    clusters = []
    for group in groups.values():
        clusters.extend(_split(group, window_minutes * 60, max_cluster_size))
    return sorted(clusters, key=lambda c: c[0].ts)


def is_judgeable(cluster: list[Alert], min_alerts: int = 3, min_entities: int = 2) -> bool:
    """Un cluster ne vaut jugement que s'il a assez d'alertes ou assez d'hôtes/utilisateurs."""
    entities = {e for a in cluster for e in a.entities() if e.startswith(("host:", "user:"))}
    return len(cluster) >= min_alerts or len(entities) >= min_entities
