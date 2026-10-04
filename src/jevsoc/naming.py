"""Noms simples et déterministes pour les clusters (« Intrusion SCRANTON → NASHUA »).

Le modèle ne génère pas de texte : le nom est construit par des règles fixes à partir de ce
qu'on sait déjà du cluster (machines touchées dans l'ordre, techniques MITRE issues des règles
Wazuh, action recommandée par la politique). Même entrée, même nom.
"""

from __future__ import annotations

import re
from collections import Counter

from jevsoc.collector import Alert

# Technique MITRE -> libellé court en français, compréhensible hors du SOC.
# La correspondance la plus précise gagne (T1021.006 avant T1021).
TECHNIQUE_LABELS = {
    "T1003": "vol d'identifiants (LSASS)",
    "T1018": "repérage du réseau",
    "T1021": "connexion à distance",
    "T1021.002": "partages administratifs",
    "T1021.004": "connexion SSH",
    "T1021.006": "commande à distance (WinRM)",
    "T1041": "exfiltration",
    "T1046": "scan de services",
    "T1047": "exécution via WMI",
    "T1048": "exfiltration",
    "T1053": "tâche planifiée",
    "T1055": "injection de code",
    "T1059": "exécution de scripts",
    "T1059.001": "PowerShell",
    "T1059.003": "invite de commandes",
    "T1070": "effacement de traces",
    "T1078": "compte valide détourné",
    "T1087": "inventaire des comptes",
    "T1102": "service web détourné",
    "T1105": "dépôt d'outils",
    "T1110": "force brute",
    "T1112": "modification du registre",
    "T1136": "création de compte",
    "T1140": "décodage de fichier",
    "T1190": "exploitation web",
    "T1218": "binaire système détourné",
    "T1505": "webshell",
    "T1529": "arrêt du système",
    "T1543": "service malveillant",
    "T1546": "persistance par événement",
    "T1547": "persistance au démarrage",
    "T1548": "contournement de l'UAC",
    "T1552": "vol de clés privées",
    "T1555": "vol de mots de passe",
    "T1560": "archivage de données",
    "T1567": "exfiltration vers le cloud",
    "T1569": "exécution de service",
    "T1570": "copie d'outils entre machines",
    "T1574": "détournement de DLL",
    "T1595": "scan de vulnérabilités",
}


def technique_label(technique: str) -> str | None:
    """Libellé de la technique la plus précise connue (T1021.006 -> WinRM, T1021.999 -> connexion)."""
    if technique in TECHNIQUE_LABELS:
        return TECHNIQUE_LABELS[technique]
    return TECHNIQUE_LABELS.get(technique.split(".")[0])


def hosts_in_order(alerts: list[Alert]) -> list[str]:
    """Machines dans l'ordre où le cluster les touche pour la première fois."""
    order: list[str] = []
    for alert in alerts:
        if alert.host and alert.host not in order:
            order.append(alert.host)
    return order


def technique_summary(alerts: list[Alert], limit: int = 3) -> list[str]:
    """Libellés des techniques, dans l'ordre d'apparition. L'injection de code (règle Wazuh très
    bruyante sur Windows) passe après les autres techniques quand il y en a."""
    labels: list[str] = []
    for alert in alerts:
        for technique in alert.mitre:
            label = technique_label(technique)
            if label and label not in labels:
                labels.append(label)
    noisy = "injection de code"
    if noisy in labels and len(labels) > 1:
        labels.remove(noisy)
        labels.append(noisy)
    return labels[:limit]


def _short_rule(description: str) -> str:
    """Description de règle Wazuh raccourcie : chemins Windows réduits au nom du fichier."""
    text = description.replace("\\\\", "\\")
    text = re.sub(r"[A-Za-z]:\\(?:[^\\ ,]+\\)*([^\\ ,]+)", r"\1", text)
    text = re.split(r",| - ", text)[0].strip().rstrip(".")
    return text if len(text) <= 60 else text[:59] + "…"


def _hosts_text(hosts: list[str]) -> str:
    if not hosts:
        return "hôte inconnu"
    return " → ".join(hosts[:3]) + (f" (+{len(hosts) - 3})" if len(hosts) > 3 else "")


def name_cluster(alerts: list[Alert], action: str) -> dict:
    """Nom simple du cluster selon l'action recommandée.

    contain / escalate -> « Intrusion A → B »          (kind = attack)
    investigate        -> « Activité suspecte sur A »  (kind = suspect)
    monitor            -> « Bruit de fond sur A »      (kind = noise)
    """
    hosts = hosts_in_order(alerts)
    summary = technique_summary(alerts)
    if action in ("contain", "escalate"):
        kind, name = "attack", f"Intrusion {_hosts_text(hosts)}"
    elif action == "investigate":
        where = _hosts_text(hosts) if len(hosts) > 1 else (hosts[0] if hosts else "hôte inconnu")
        kind, name = "suspect", f"Activité suspecte {'sur ' if len(hosts) <= 1 else ''}{where}"
    else:
        kind, name = "noise", f"Bruit de fond sur {_hosts_text(hosts)}"
    dominant = Counter(a.description for a in alerts).most_common(1)[0][0] if alerts else ""
    return {
        "name": name,
        "kind": kind,
        "summary": summary,
        "hosts_order": hosts,
        "dominant": _short_rule(dominant),
    }
