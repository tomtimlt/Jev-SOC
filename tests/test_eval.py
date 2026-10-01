import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_script(path: Path):
    """Importe un script (eval/eval.py, scripts/make_variants.py) comme un module."""
    spec = importlib.util.spec_from_file_location(path.stem + "_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


make_variants = load_script(ROOT / "scripts" / "make_variants.py")
eval_script = load_script(ROOT / "eval" / "eval.py")


def test_variants_ablation():
    full = make_variants.build("attack", "full")
    assert full["max_rule_level"] == 7 and all("mitre" in e for e in full["timeline"])
    assert all("mitre" not in e for e in make_variants.build("attack", "no_mitre")["timeline"])
    no_level = make_variants.build("attack", "no_level")
    assert "max_rule_level" not in no_level and all("level" not in e for e in no_level["timeline"])
    # blind enlève les indices de contexte mais garde le nombre d'alertes
    blind = make_variants.build("benign", "blind")
    assert "SCCM distribution point" not in json.dumps(blind)
    assert blind["alert_count"] == full["alert_count"]


def test_labelled_keeps_true_levels_even_in_no_level():
    cluster = make_variants.labelled("adversarial", "no_level")
    assert cluster["label"] == "attack" and max(cluster["rule_levels"]) == 7


def test_committed_data_is_up_to_date(tmp_path):
    # Le dossier data/ablation versionné doit correspondre à ce que génère le script.
    make_variants.main(["--out", str(tmp_path)])
    generated = sorted(tmp_path.glob("*.json"))
    assert len(generated) == 12
    for path in generated:
        assert path.read_text() == (ROOT / "data" / "ablation" / path.name).read_text(), path.name


def test_eval_end_to_end_with_mock(capsys):
    result = eval_script.main(["--backend", "mock"])
    assert result["n"] == 12 and result["n_attack"] == 8 and result["n_multistage"] == 8
    assert not result["calibrated"]  # pas de calibration pour le backend mock
    # Mock neutre : P = 0,5 partout -> tout est prédit "attaque"
    model = result["all_attacks"]["jev brut >=0.5"]
    assert model["recall"] == 1.0 and model["precision"] == pytest.approx(8 / 12)
    assert model["auc"] == 0.5 and model["brier"] == pytest.approx(0.25)
    # Les trois scénarios ont max_level = 7 : la baseline ne sépare rien
    assert result["all_attacks"]["max_level>=7"]["auc"] == 0.5
    assert "Chaînes multi-étapes contre bénins" in capsys.readouterr().out


def test_eval_replay_reuses_recorded_decisions(tmp_path, capsys):
    first = eval_script.main(["--backend", "mock", "--out", str(tmp_path / "r.json")])
    again = eval_script.main(["--replay", str(tmp_path / "r.json")])
    assert again["all_attacks"] == first["all_attacks"]


def test_eval_split_filter():
    assert len(eval_script.load_clusters(ROOT / "data" / "ablation", "test")) == 12
    assert eval_script.load_clusters(ROOT / "data" / "ablation", "train") == []
