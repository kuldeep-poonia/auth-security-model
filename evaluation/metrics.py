import math
from typing import Any, Dict, List, Optional, Tuple


def compute_binary_metrics(y_true: List[bool], y_pred: List[bool]) -> Dict[str, Any]:
    """Compute standard binary classification metrics: Precision, Recall, FPR, FNR, Accuracy, Specificity, F1."""
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt and yp)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if not yt and yp)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if not yt and not yp)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt and not yp)

    total = len(y_true)
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "total_samples": total,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "specificity": round(specificity, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "f1_score": round(f1, 4),
    }


def compute_per_class_metrics(
    records: List[Dict[str, Any]],
    target_classes: Optional[List[str]] = None,
) -> Dict[str, Dict[str, Any]]:
    """Compute precision, recall, FPR, FNR, accuracy, and sample size for each vulnerability class."""
    if target_classes is None:
        target_classes = ["auth_bypass", "missing_authz_check", "incorrect_authz", "IDOR"]

    per_class_results = {}
    for cls_name in target_classes:
        tp = sum(1 for r in records if r["true_vuln_class"] == cls_name and r["pred_vuln_class"] == cls_name)
        fp = sum(1 for r in records if r["true_vuln_class"] != cls_name and r["pred_vuln_class"] == cls_name)
        fn = sum(1 for r in records if r["true_vuln_class"] == cls_name and r["pred_vuln_class"] != cls_name)
        tn = sum(1 for r in records if r["true_vuln_class"] != cls_name and r["pred_vuln_class"] != cls_name)

        ground_truth_count = sum(1 for r in records if r["true_vuln_class"] == cls_name)
        predicted_count = sum(1 for r in records if r["pred_vuln_class"] == cls_name)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        per_class_results[cls_name] = {
            "ground_truth_samples": ground_truth_count,
            "predicted_samples": predicted_count,
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
            "f1_score": round(f1, 4),
        }

    return per_class_results


def compute_per_language_metrics(records: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Compute binary classification metrics broken down per programming language with sample size."""
    languages = sorted(list(set(r["language"] for r in records)))
    per_lang_results = {}

    for lang in languages:
        lang_records = [r for r in records if r["language"] == lang]
        y_true = [r["true_is_vulnerable"] for r in lang_records]
        y_pred = [r["pred_is_vulnerable"] for r in lang_records]

        metrics = compute_binary_metrics(y_true, y_pred)
        metrics["vuln_samples"] = sum(1 for yt in y_true if yt)
        metrics["clean_samples"] = sum(1 for yt in y_true if not yt)
        per_lang_results[lang] = metrics

    return per_lang_results


def compute_cross_language_matrix(records: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Analyze vulnerability precision and recall across all languages for each CWE class."""
    target_classes = ["auth_bypass", "missing_authz_check", "incorrect_authz", "IDOR"]
    languages = ["go", "java", "javascript", "php", "python", "typescript"]

    matrix = {}
    for cls_name in target_classes:
        matrix[cls_name] = {}
        for lang in languages:
            gt_subset = [r for r in records if r["true_vuln_class"] == cls_name and r["language"] == lang]
            pred_subset = [r for r in records if r["pred_vuln_class"] == cls_name and r["language"] == lang]

            gt_count = len(gt_subset)
            pred_count = len(pred_subset)

            if gt_count == 0 and pred_count == 0:
                matrix[cls_name][lang] = {
                    "sample_size": 0,
                    "precision": None,
                    "recall": None,
                    "f1_score": None,
                    "tp": 0,
                    "fp": 0,
                    "fn": 0,
                }
                continue

            tp = sum(1 for r in gt_subset if r["pred_vuln_class"] == cls_name)
            fp = sum(1 for r in pred_subset if r["true_vuln_class"] != cls_name)
            fn = gt_count - tp

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / gt_count if gt_count > 0 else 0.0
            f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

            matrix[cls_name][lang] = {
                "sample_size": gt_count,
                "predicted_count": pred_count,
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1, 4),
            }

    return matrix


def compute_hard_case_analysis(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze behavior on edge cases:

    1. 'Looks clean but is vulnerable' (subtle IDOR / logic flaws in seemingly structured code)
    2. 'Looks suspicious but is clean' (complex custom permission checks or non-standard token validations)
    """
    # 1. Subtle vulnerabilities (e.g. incorrect_authz or IDOR where standard checks exist but fail on ownership)
    subtle_vulns = [
        r for r in records
        if r["true_is_vulnerable"] and r["true_vuln_class"] in ["incorrect_authz", "IDOR"]
    ]
    subtle_total = len(subtle_vulns)
    subtle_detected = sum(1 for r in subtle_vulns if r["pred_is_vulnerable"])
    subtle_missed = subtle_total - subtle_detected
    subtle_fnr = subtle_missed / subtle_total if subtle_total > 0 else 0.0

    # 2. Suspicious-looking clean code (clean records that contain security-sensitive keywords like token, auth, role, admin)
    security_keywords = ["auth", "token", "role", "admin", "permission", "password", "jwt", "session", "access"]
    suspicious_clean = [
        r for r in records
        if (not r["true_is_vulnerable"]) and any(kw in (r.get("code_unit", "") or r.get("code", "")).lower() for kw in security_keywords)
    ]
    suspicious_total = len(suspicious_clean)
    suspicious_correct = sum(1 for r in suspicious_clean if not r["pred_is_vulnerable"])
    suspicious_fps = suspicious_total - suspicious_correct
    suspicious_fpr = suspicious_fps / suspicious_total if suspicious_total > 0 else 0.0

    return {
        "subtle_vulnerable_cases": {
            "sample_size": subtle_total,
            "detected_count": subtle_detected,
            "missed_count": subtle_missed,
            "detection_rate": round(subtle_detected / subtle_total, 4) if subtle_total > 0 else 0.0,
            "false_negative_rate": round(subtle_fnr, 4),
        },
        "suspicious_clean_cases": {
            "sample_size": suspicious_total,
            "correct_clean_count": suspicious_correct,
            "false_positive_count": suspicious_fps,
            "specificity": round(suspicious_correct / suspicious_total, 4) if suspicious_total > 0 else 0.0,
            "false_positive_rate": round(suspicious_fpr, 4),
        },
    }


def compute_confidence_calibration(
    records: List[Dict[str, Any]],
    num_bins: int = 5,
) -> Dict[str, Any]:
    """Compute Expected Calibration Error (ECE) and reliability table."""
    bins: List[Dict[str, Any]] = []
    bin_width = 1.0 / num_bins

    total_samples = len(records)
    ece = 0.0

    for i in range(num_bins):
        bin_lower = i * bin_width
        bin_upper = (i + 1) * bin_width
        if i == num_bins - 1:
            bin_records = [r for r in records if bin_lower <= r["pred_confidence"] <= bin_upper]
        else:
            bin_records = [r for r in records if bin_lower <= r["pred_confidence"] < bin_upper]

        bin_count = len(bin_records)
        if bin_count == 0:
            bins.append({
                "bin_range": f"[{bin_lower:.2f}, {bin_upper:.2f})",
                "count": 0,
                "avg_confidence": 0.0,
                "expected_accuracy": round((bin_lower + bin_upper) / 2.0, 4),
                "actual_accuracy": 0.0,
                "calibration_gap": 0.0,
            })
            continue

        avg_conf = sum(r["pred_confidence"] for r in bin_records) / bin_count

        correct_count = 0
        for r in bin_records:
            pred_decision = r["pred_confidence"] >= 0.50
            if pred_decision == r["true_is_vulnerable"]:
                correct_count += 1

        bin_acc = correct_count / bin_count
        expected_accuracy = avg_conf if avg_conf >= 0.5 else (1.0 - avg_conf)
        gap = abs(bin_acc - expected_accuracy)
        ece += (bin_count / total_samples) * gap

        bins.append({
            "bin_range": f"[{bin_lower:.2f}, {bin_upper:.2f})",
            "count": bin_count,
            "avg_confidence": round(avg_conf, 4),
            "expected_accuracy": round(expected_accuracy, 4),
            "actual_accuracy": round(bin_acc, 4),
            "calibration_gap": round(gap, 4),
        })

    overconfident_errors = []
    for r in records:
        pred_decision = r["pred_confidence"] >= 0.50
        if pred_decision != r["true_is_vulnerable"] and r["pred_confidence"] >= 0.85:
            code_text = r.get("code_unit") or r.get("code", "")
            overconfident_errors.append({
                "record_id": r.get("record_id", ""),
                "code_preview": code_text[:120].replace("\n", " "),
                "language": r.get("language"),
                "true_vuln": r["true_is_vulnerable"],
                "true_class": r["true_vuln_class"],
                "pred_conf": r["pred_confidence"],
                "pred_class": r["pred_vuln_class"],
                "explanation": r.get("pred_explanation", ""),
            })

    return {
        "num_bins": num_bins,
        "expected_calibration_error": round(ece, 4),
        "reliability_bins": bins,
        "overconfident_error_count": len(overconfident_errors),
        "overconfident_errors": overconfident_errors,
    }
