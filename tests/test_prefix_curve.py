import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("prefix_curve", ROOT / "scripts" / "prefix_curve.py")
prefix_curve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prefix_curve)


def test_prefix_state_does_not_leak_future():
    # À 4 alertes, l'attaquant n'a pas encore utilisé svc_backup ni touché SRV-FILE-02.
    state = prefix_curve.prefix_state("attack", 4)
    assert state["users"] == ["j.martin"]
    assert state["hosts"] == ["WS-FIN-07"]
    assert state["alert_count"] == 4 and len(state["timeline"]) == 4
    assert prefix_curve.prefix_state("attack", 1)["max_rule_level"] == 5
    assert "svc_backup" in prefix_curve.prefix_state("attack", 5)["users"]


def test_run_with_mock(capsys):
    rows = prefix_curve.main(["--backend", "mock"])
    assert len(rows) == 8 + 8 + 7  # un appel par préfixe de chaque scénario
    assert rows[0]["scenario"] == "attack" and rows[0]["k"] == 1
    assert "## adversarial" in capsys.readouterr().out
