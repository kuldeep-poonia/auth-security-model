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
        cls_records = [r for r in records if r["true_vuln_class"] == cls_name or r["pred_vuln_class"] == cls_name]
        # In one-vs-all evaluation:
        # True positive: true == cls_name and pred == cls_name
        # False positive: true != cls_name and pred == cls_name
        # True negative: true != cls_name and pred != cls_name
        # False negative: true == cls_name and pred != cls_name
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
    """Analyze vulnerability detection accuracy across languages for each CWE class."""
    target_classes = ["auth_bypass", "missing_authz_check", "incorrect_authz", "IDOR"]
    languages = sorted(list(set(r["language"] for r in records)))

    matrix = {}
    for cls_name in target_classes:
        matrix[cls_name] = {}
        for lang in languages:
            subset = [r for r in records if r["true_vuln_class"] == cls_name and r["language"] == lang]
            count = len(subset)
            if count == 0:
                matrix[cls_name][lang] = {"sample_size": 0, "recall": None}
                continue
            detected = sum(1 for r in subset if r["pred_is_vulnerable"])
            exact_match = sum(1 for r in subset if r["pred_vuln_class"] == cls_name)
            matrix[cls_name][lang] = {
                "sample_size": count,
                "vuln_detected_count": detected,
                "detection_rate": round(detected / count, 4),
                "exact_class_match_rate": round(exact_match / count, 4),
            }

    return matrix


def compute_confidence_calibration(
    records: List[Dict[str, Any]],
    num_bins: int = 5,
) -> Dict[str, Any]:
    """Compute Expected Calibration Error (ECE) and reliability table.

    Confidence represents P(vulnerable = true).
    For predictions with confidence >= 0.50, predicted label is True (Vulnerable).
    For predictions with confidence < 0.50, predicted label is False (Clean).
    Calibration accuracy in bin evaluates whether the predicted binary class matches ground truth.
    """
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
                "accuracy": 0.0,
                "calibration_gap": 0.0,
            })
            continue

        avg_conf = sum(r["pred_confidence"] for r in bin_records) / bin_count

        # Evaluate correctness of decision made at this confidence level
        correct_count = 0
        for r in bin_records:
            # If confidence >= 0.5, predicted vuln = True; if < 0.5, predicted vuln = False
            pred_decision = r["pred_confidence"] >= 0.50
            if pred_decision == r["true_is_vulnerable"]:
                correct_count += 1

        bin_acc = correct_count / bin_count
        # Expected probability of being correct for this confidence:
        # If conf in [0.8, 1.0], expected correctness ~ conf
        # If conf in [0.0, 0.2], expected correctness ~ 1.0 - conf
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

    # Identify overconfident errors (confidence >= 0.85 but prediction is wrong)
    overconfident_errors = []
    for r in records:
        pred_decision = r["pred_confidence"] >= 0.50
        if pred_decision != r["true_is_vulnerable"] and r["pred_confidence"] >= 0.85:
            overconfident_errors.append({
                "code_preview": r.get("code_unit", "")[:120].replace("\n", " "),
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
