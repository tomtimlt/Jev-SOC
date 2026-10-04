"""Regroupement des alertes en clusters : union-find sur les entités partagées.

Principe : deux alertes sont reliées si elles partagent une entité (hôte, IP, utilisateur)
et si elles sont proches dans le temps (écart <= max_gap_minutes). Les composantes
connexes forment les clusters.

Protection contre les entités "hub" (manager Wazuh, DNS, SYSTEM...) qui relieraient tout :
  - denylist configurable (config/entity_denylist.yaml) ;
  - présence permanente : une entité vue dans plus de `hub_ratio` des heures ne crée aucun lien ;
  - durée et taille max : un cluster trop long ou trop gros est découpé en tranches de temps.

Deux versions qui appliquent la même règle de liaison :
  - `correlate` : hors ligne, tout un fichier d'un coup (évaluation) ;
  - `IncrementalCorrelator` : en flux, une alerte à la fois (production, démo live). Un cluster
    ouvert s'étend ou fusionne avec un autre quand une alerte les relie ; chaque changement
    incrémente sa version, pour que la décision soit re-prise et versionnée, jamais écrasée.
"""

from __future__ import annotations

from dataclasses import dataclass, field

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


def hub_entities(
    alerts: list[Alert], hub_ratio: float, denylist: set[str], bucket_minutes: float = 60
) -> set[str]:
    """Entités qui ne doivent créer aucun lien : denylist + entités présentes en permanence.

    "Permanente" = vue dans plus de `hub_ratio` des tranches de temps (1 h par défaut ; plus
    court pour un enregistrement de quelques dizaines de minutes) couvertes par les alertes. On ne
    compte PAS le nombre d'alertes : un attaquant qui scanne génère énormément d'alertes en
    peu de temps, et le prendre pour un hub couperait justement la chaîne qu'on cherche.
    Un serveur mail ou un DNS, eux, apparaissent heure après heure.
    """
    hours_by_entity: dict[str, set[int]] = {}
    for alert in alerts:
        for entity in alert.entities():
            hours_by_entity.setdefault(entity, set()).add(int(alert.ts // (bucket_minutes * 60)))
    total_hours = len({int(a.ts // (bucket_minutes * 60)) for a in alerts}) or 1
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
    hub_bucket_minutes: float = 60,
    hubs: set[str] | None = None,
) -> list[list[Alert]]:
    """Renvoie les clusters, chacun trié par temps, eux-mêmes triés par début.

    `hubs` : hubs appris ailleurs (sur l'historique). Sinon, calculés sur ces alertes mêmes, ce
    qui n'est sûr que pour des enregistrements longs où l'attaque ne couvre qu'une petite partie
    du temps : sur un enregistrement court occupé par l'attaque, les indices de l'attaquant
    deviendraient eux-mêmes des hubs.
    """
    alerts = sorted(alerts, key=lambda a: a.ts)
    if hubs is None:
        hubs = hub_entities(alerts, hub_ratio, {d.lower() for d in denylist or set()}, hub_bucket_minutes)
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
    """Un cluster ne vaut jugement que s'il a assez d'alertes, ou s'il s'étend sur plusieurs
    hôtes ou plusieurs utilisateurs (au moins 2 alertes dans ce cas).

    On compte les hôtes et les utilisateurs SÉPARÉMENT : une alerte isolée qui porte un hôte et
    un utilisateur ne décrit pas une activité étendue.
    """
    if len(cluster) >= min_alerts:
        return True
    hosts = {a.host for a in cluster if a.host}
    users = {u for a in cluster for u in a.users}
    return len(cluster) >= 2 and (len(hosts) >= min_entities or len(users) >= min_entities)


@dataclass
class LiveCluster:
    """Cluster ouvert en flux. `version` augmente à chaque alerte ajoutée ou fusion."""

    id: str
    alerts: list[Alert] = field(default_factory=list)
    version: int = 0
    closed: bool = False
    merged_into: str | None = None
    continues: str | None = None  # cluster précédent, si celui-ci prolonge une fenêtre pleine

    @property
    def start(self) -> float:
        return self.alerts[0].ts

    @property
    def last(self) -> float:
        return self.alerts[-1].ts


class IncrementalCorrelator:
    """Corrélation en flux : même règle que `correlate`, une alerte à la fois.

    Une alerte rejoint le cluster de la dernière alerte qui partageait une de ses entités, si
    celle-ci date de moins de `max_gap_minutes`. Si elle relie plusieurs clusters ouverts, ils
    fusionnent dans le plus ancien. Un cluster sans nouvelle alerte depuis `max_gap_minutes`
    est fermé. Les hubs ne peuvent pas être calculés sur le futur : on les fournit, appris sur
    l'historique (ex. la journée précédente) avec `hub_entities`.
    """

    def __init__(
        self,
        max_gap_minutes: float = 60,
        window_minutes: float = 240,
        hubs: set[str] | None = None,
        max_cluster_size: int = 100000,
    ):
        self.max_gap_s = max_gap_minutes * 60
        self.window_s = window_minutes * 60
        self.hubs = hubs or set()
        self.max_cluster_size = max_cluster_size
        self.clusters: dict[str, LiveCluster] = {}
        self._entity: dict[str, tuple[str, float]] = {}  # entité -> (cluster, heure de dernière vue)
        self._counter = 0

    def _new(self, continues: str | None = None) -> LiveCluster:
        self._counter += 1
        cluster = LiveCluster(id=f"clu-{self._counter:04d}", continues=continues)
        self.clusters[cluster.id] = cluster
        return cluster

    def _resolve(self, cluster_id: str) -> LiveCluster:
        cluster = self.clusters[cluster_id]
        while cluster.merged_into:  # un cluster absorbé renvoie vers celui qui l'a absorbé
            cluster = self.clusters[cluster.merged_into]
        return cluster

    def close_stale(self, now: float) -> list[LiveCluster]:
        """Ferme les clusters inactifs depuis plus de max_gap. Renvoie ceux qui viennent de fermer."""
        closed = []
        for cluster in self.clusters.values():
            if not cluster.closed and not cluster.merged_into and now - cluster.last > self.max_gap_s:
                cluster.closed = True
                closed.append(cluster)
        return closed

    def add(self, alert: Alert) -> tuple[LiveCluster, list[LiveCluster]]:
        """Ajoute une alerte (dans l'ordre du temps). Renvoie (cluster mis à jour, clusters absorbés)."""
        entities = [e for e in alert.entities() if e not in self.hubs]
        candidates: dict[str, LiveCluster] = {}
        for entity in entities:
            seen = self._entity.get(entity)
            if seen and alert.ts - seen[1] <= self.max_gap_s:
                cluster = self._resolve(seen[0])
                if not cluster.closed:
                    candidates[cluster.id] = cluster

        absorbed = []
        if not candidates:
            target = self._new()
        else:
            ordered = sorted(candidates.values(), key=lambda c: c.start)
            target = ordered[0]
            for other in ordered[1:]:  # l'alerte relie plusieurs clusters : ils fusionnent
                target.alerts = sorted(target.alerts + other.alerts, key=lambda a: a.ts)
                other.merged_into = target.id
                absorbed.append(other)
            # Fenêtre ou taille dépassée : un nouveau cluster prend le relais (lien "continues").
            if alert.ts - target.start > self.window_s or len(target.alerts) >= self.max_cluster_size:
                target.closed = True
                target = self._new(continues=target.id)

        target.alerts.append(alert)
        target.version += 1
        for entity in entities:
            self._entity[entity] = (target.id, alert.ts)
        return target, absorbed
