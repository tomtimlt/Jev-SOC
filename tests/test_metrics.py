import pytest

from jevsoc.metrics import (
    brier_score,
    classification_report,
    expected_calibration_error,
    percentile,
    reliability_table,
    roc_auc,
)


def test_classification_report():
    # 2 VP, 1 FP, 1 FN, 1 VN
    report = classification_report([1, 1, 1, 0, 0], [1, 1, 0, 1, 0])
    assert (report["tp"], report["fp"], report["fn"], report["tn"]) == (2, 1, 1, 1)
    assert report["precision"] == pytest.approx(2 / 3)
    assert report["recall"] == pytest.approx(2 / 3)
    assert report["f1"] == pytest.approx(2 / 3)
    assert report["accuracy"] == pytest.approx(3 / 5)


def test_classification_report_no_positive_prediction():
    assert classification_report([1, 0], [0, 0])["precision"] == 0.0


def test_brier():
    assert brier_score([1, 0], [1.0, 0.0]) == 0.0
    assert brier_score([1, 0], [0.5, 0.5]) == pytest.approx(0.25)


def test_reliability_and_ece():
    y = [1, 0, 1, 1]
    p = [0.9, 0.1, 0.8, 1.0]  # 1,0 doit tomber dans la dernière tranche
    table = reliability_table(y, p)
    assert [row["n"] for row in table] == [1, 0, 0, 0, 3]
    assert table[4]["mean_prob"] == pytest.approx(0.9)
    # tranche 0 : |0,1 - 0| = 0,1 ; tranche 4 : |0,9 - 1| = 0,1 -> ECE = 0,1
    assert expected_calibration_error(y, p) == pytest.approx(0.1)


def test_auc():
    assert roc_auc([1, 1, 0, 0], [0.9, 0.8, 0.2, 0.1]) == 1.0
    assert roc_auc([1, 0], [0.5, 0.5]) == 0.5  # égalité
    assert roc_auc([1, 1], [0.9, 0.8]) is None  # une seule classe


def test_percentile():
    values = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    assert percentile(values, 50) == 50
    assert percentile(values, 95) == 100
