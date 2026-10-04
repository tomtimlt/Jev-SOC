"""Noms simples des clusters : déterministes, lisibles, conformes à l'action recommandée."""

from jevsoc.collector import Alert
from jevsoc.naming import name_cluster, technique_label, technique_summary


def alert(i, host, mitre=(), desc="Regle Wazuh"):
    return Alert(
        id=str(i), ts=1000.0 + i, level=7, rule_id="r", description=desc, host=host, mitre=list(mitre)
    )


def test_technique_label_prefers_most_specific():
    assert technique_label("T1021.006") == "commande à distance (WinRM)"
    assert technique_label("T1021.999") == "connexion à distance"  # repli sur la technique parente
    assert technique_label("T9999") is None


def test_summary_keeps_order_and_pushes_noisy_injection_last():
    alerts = [alert(1, "A", ["T1055"]), alert(2, "A", ["T1059.003"]), alert(3, "A", ["T1105", "T1055"])]
    assert technique_summary(alerts) == ["invite de commandes", "dépôt d'outils", "injection de code"]


def test_names_follow_action_and_host_order():
    alerts = [alert(1, "SCRANTON", ["T1059.003"]), alert(2, "NASHUA", ["T1021.002"]), alert(3, "SCRANTON")]
    attack = name_cluster(alerts, "contain")
    assert attack["name"] == "Intrusion SCRANTON → NASHUA"
    assert attack["kind"] == "attack" and attack["hosts_order"] == ["SCRANTON", "NASHUA"]
    assert name_cluster(alerts[:1], "investigate")["name"] == "Activité suspecte sur SCRANTON"
    assert name_cluster(alerts, "investigate")["kind"] == "suspect"
    assert name_cluster(alerts[:1], "monitor")["kind"] == "noise"
    assert name_cluster(alerts, "monitor")["name"] == "Bruit de fond sur SCRANTON → NASHUA"


def test_dominant_rule_shortens_windows_paths():
    desc = "File dropped: C:\\\\Users\\\\x\\\\AppData\\\\evil.exe, by malware"
    named = name_cluster([alert(1, "H", desc=desc), alert(2, "H", desc=desc)], "monitor")
    assert named["dominant"] == "File dropped: evil.exe"
