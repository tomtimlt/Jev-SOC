import pytest

from jevsoc.calibration import Calibrator, fit_platt, load_calibration, logit, sigmoid


def test_identity_calibrator():
    assert Calibrator()(0.3) == pytest.approx(0.3)
    assert sigmoid(logit(0.8)) == pytest.approx(0.8)


def test_fit_platt_corrects_an_underconfident_model():
    # Modèle sous-confiant : les attaques sortent à 0,6, les bénins à 0,4.
    probs = [0.6] * 20 + [0.4] * 20
    labels = [1] * 20 + [0] * 20
    cal = fit_platt(probs, labels)
    assert cal.a > 1  # la calibration rend le modèle plus tranché
    assert cal(0.6) > 0.9 and cal(0.4) < 0.1
    assert cal(0.6) < 1.0  # cibles lissées de Platt : jamais exactement 1


def test_fit_platt_needs_both_classes():
    with pytest.raises(ValueError):
        fit_platt([0.2, 0.3], [0, 0])


def test_load_calibration(tmp_path):
    path = tmp_path / "calibration.yaml"
    path.write_text("jev:\n  is_sophisticated_attack: {a: 2.0, b: -1.0, target: x}\n")
    assert load_calibration(path, "jev")["is_sophisticated_attack"] == Calibrator(2.0, -1.0)
    assert load_calibration(path, "mock") == {}
    assert load_calibration(tmp_path / "absent.yaml", "jev") == {}
