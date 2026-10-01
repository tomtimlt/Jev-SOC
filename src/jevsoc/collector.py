"""Lecture des alertes Wazuh et normalisation en un format interne simple.

Mode fichier (JSON/NDJSON, une alerte par ligne) : sert aux tests et aux jeux de données
publics comme AIT-ADS. Le mode indexeur OpenSearch (wazuh-alerts-*) viendra au jalon 7
et produira les mêmes objets `Alert`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# Préfixe syslog "Jan 24 04:37:58 hote programme[pid]: " : redondant avec les autres champs.
SYSLOG_PREFIX = re.compile(r"^[A-Z][a-z]{2} +\d+ [\d:]+ \S+ \S+?(\[\d+\])?: ")
# Bruit qui change à chaque événement sans rien apprendre au modèle.
NOISE = [
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<guid>"),
    (re.compile(r"session=<[^>]*>"), "session=<…>"),
    (re.compile(r"\b(pid|mpid)=\d+"), r"\1=<n>"),
]


@dataclass
class Alert:
    """Une alerte Wazuh réduite à ce qui sert à corréler et à décrire."""

    id: str
    ts: float  # horodatage Unix (secondes)
    level: int
    rule_id: str
    description: str
    detail: str = ""  # extrait utile du log d'origine, normalisé
    host: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    users: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)

    def entities(self) -> list[str]:
        """Entités typées qui peuvent relier deux alertes (ex. 'ip:10.0.0.5')."""
        out = []
        if self.host:
            out.append(f"host:{self.host}")
        for ip in {self.src_ip, self.dst_ip} - {None}:
            out.append(f"ip:{ip}")
        out.extend(f"user:{u}" for u in self.users)
        # La règle elle-même relie une rafale d'alertes identiques (scan, brute force). Utile
        # quand un proxy masque l'IP de l'attaquant. Les règles de fond (présentes en
        # permanence, ex. Dovecot) sont neutralisées comme hubs par le correlator.
        out.append(f"rule:{self.rule_id}")
        return out


def _strip_port(value: str | None) -> str | None:
    """'91.189.95.85:80' -> '91.189.95.85'."""
    if not value:
        return None
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


def clean_text(text: str, limit: int = 160) -> str:
    """Retire le préfixe syslog et le bruit (GUID, pid, sessions), puis tronque."""
    text = SYSLOG_PREFIX.sub("", text.strip())
    for pattern, repl in NOISE:
        text = pattern.sub(repl, text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def normalize_wazuh(raw: dict) -> Alert:
    """Alerte Wazuh brute (format de l'indexeur / alerts.json) -> Alert."""
    rule = raw.get("rule", {})
    data = raw.get("data", {})
    host = (raw.get("predecoder") or {}).get("hostname")

    users = []
    for key in ("srcuser", "dstuser", "user"):
        if isinstance(data.get(key), str):
            # Wazuh décode parfois "www-data:jhall" en "data:jhall" : on garde la partie utile.
            users.append(data[key].split(":")[-1])
    win_user = ((data.get("win") or {}).get("eventdata") or {}).get("user")
    if win_user:
        users.append(win_user)

    suricata = (data.get("alert") or {}).get("signature")
    detail = suricata or raw.get("full_log", "")
    return Alert(
        id=str(raw.get("id", "")),
        ts=datetime.fromisoformat(raw["@timestamp"].replace("Z", "+00:00")).timestamp(),
        level=int(rule.get("level", 0)),
        rule_id=str(rule.get("id", "")),
        description=rule.get("description", ""),
        detail=clean_text(detail),
        host=host,
        src_ip=_strip_port(data.get("srcip") or data.get("src_ip")),
        dst_ip=_strip_port(data.get("dstip") or data.get("dest_ip")),
        users=sorted(set(users)),
        mitre=list((rule.get("mitre") or {}).get("id", [])),
    )


def read_alerts(path: str | Path) -> Iterator[Alert]:
    """Lit un fichier NDJSON d'alertes Wazuh (une alerte JSON par ligne)."""
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield normalize_wazuh(json.loads(line))
