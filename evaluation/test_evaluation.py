import pytest
from evaluation.metrics import (
    compute_binary_metrics,
    compute_per_class_metrics,
    compute_per_language_metrics,
    compute_confidence_calibration,
)
from evaluation.eval_model import extract_json_from_response


def test_compute_binary_metrics_perfect():
    y_true = [True, True, False, False]
    y_pred = [True, True, False, False]
    metrics = compute_binary_metrics(y_true, y_pred)
    assert metrics["accuracy"] == 1.0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["specificity"] == 1.0
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["false_negative_rate"] == 0.0
    assert metrics["f1_score"] == 1.0


def test_compute_binary_metrics_with_errors():
    # 2 TP, 1 FP, 1 FN, 2 TN
    y_true = [True, True, True, False, False, False]
    y_pred = [True, True, False, True, False, False]
    metrics = compute_binary_metrics(y_true, y_pred)
    assert metrics["true_positives"] == 2
    assert metrics["false_positives"] == 1
    assert metrics["false_negatives"] == 1
    assert metrics["true_negatives"] == 2
    assert round(metrics["precision"], 2) == 0.67
    assert round(metrics["recall"], 2) == 0.67
    assert round(metrics["false_positive_rate"], 2) == 0.33
    assert round(metrics["false_negative_rate"], 2) == 0.33


def test_compute_per_class_metrics_tracks_sample_sizes():
    records = [
        {"true_vuln_class": "auth_bypass", "pred_vuln_class": "auth_bypass"},
        {"true_vuln_class": "auth_bypass", "pred_vuln_class": "none"},
        {"true_vuln_class": "IDOR", "pred_vuln_class": "IDOR"},
        {"true_vuln_class": "none", "pred_vuln_class": "none"},
    ]
    res = compute_per_class_metrics(records, target_classes=["auth_bypass", "IDOR"])
    assert res["auth_bypass"]["ground_truth_samples"] == 2
    assert res["auth_bypass"]["predicted_samples"] == 1
    assert res["auth_bypass"]["recall"] == 0.5
    assert res["IDOR"]["ground_truth_samples"] == 1
    assert res["IDOR"]["recall"] == 1.0


def test_compute_per_language_metrics():
    records = [
        {"language": "python", "true_is_vulnerable": True, "pred_is_vulnerable": True},
        {"language": "python", "true_is_vulnerable": False, "pred_is_vulnerable": False},
        {"language": "go", "true_is_vulnerable": True, "pred_is_vulnerable": False},
    ]
    res = compute_per_language_metrics(records)
    assert "python" in res
    assert res["python"]["accuracy"] == 1.0
    assert res["python"]["total_samples"] == 2
    assert res["go"]["accuracy"] == 0.0
    assert res["go"]["total_samples"] == 1


def test_confidence_calibration_ece():
    # Model predicts 0.90 for correct positive, 0.10 for correct negative
    records = [
        {"true_is_vulnerable": True, "true_vuln_class": "IDOR", "pred_confidence": 0.90, "pred_vuln_class": "IDOR"},
        {"true_is_vulnerable": False, "true_vuln_class": "none", "pred_confidence": 0.10, "pred_vuln_class": "none"},
    ]
    res = compute_confidence_calibration(records, num_bins=5)
    assert res["expected_calibration_error"] < 0.20
    assert res["overconfident_error_count"] == 0


def test_confidence_calibration_detects_overconfident_errors():
    # False positive at 0.95 confidence
    records = [
        {"true_is_vulnerable": False, "true_vuln_class": "none", "pred_confidence": 0.95, "pred_vuln_class": "auth_bypass", "code_unit": "def clean(): pass"},
    ]
    res = compute_confidence_calibration(records, num_bins=5)
    assert res["overconfident_error_count"] == 1
    assert res["overconfident_errors"][0]["pred_conf"] == 0.95


def test_extract_json_from_response_code_fence():
    text = 'Here is the finding:\n```json\n{"is_vulnerable": true, "vulnerability_class": "auth_bypass", "confidence": 0.95, "explanation": "No token check"}\n```'
    parsed = extract_json_from_response(text)
    assert parsed["is_vulnerable"] is True
    assert parsed["vulnerability_class"] == "auth_bypass"
    assert parsed["confidence"] == 0.95


def test_extract_json_from_response_trained_schema():
    text = '{\n  "vulnerable": true,\n  "vuln_class": "incorrect_authz",\n  "confidence": 0.94,\n  "explanation": "Missing role verification."\n}'
    parsed = extract_json_from_response(text)
    assert parsed["is_vulnerable"] is True
    assert parsed["vulnerability_class"] == "incorrect_authz"
    assert parsed["confidence"] == 0.94


def test_extract_json_from_response_fallback_regex():
    text = 'Analysis indicates "is_vulnerable": false, "vulnerability_class": "none", "confidence": 0.05'
    parsed = extract_json_from_response(text)
    assert parsed["is_vulnerable"] is False
    assert parsed["vulnerability_class"] == "none"
    assert parsed["confidence"] == 0.05
