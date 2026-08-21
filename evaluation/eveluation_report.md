[OK] Baseline predictions written to evaluation/results/test_predictions_baseline.jsonl
[OK] Metrics JSON written to evaluation/results/evaluation_metrics.json
/kaggle/working/repo/evaluation/eval_runner.py:36: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  md.append(f"**Generated:** {datetime.utcnow().isoformat()}Z  ")
[OK] Evaluation report written to: evaluation/evaluation_report.md
# Phase 6 — Model Evaluation & Benchmark Report

**Generated:** 2026-08-20T14:47:57.901277Z  
**Evaluation Corpus:** Held-out Test Split (`data/splits/test.json`)  
**Test Set Composition:** 236 Records (100% Real Code, 0 Synthetic Mutations, 0 Data Leakage)

---

## 1. Overall Binary Classification Performance

| Metric | Fine-Tuned Model | Base Model Baseline | Description |
| :--- | :--- | :--- | :--- |
| **Accuracy** | **49.15%** | 54.24% | Overall correctness across vulnerable & clean units |
| **Precision** | **49.25%** | 55.42% | $TP / (TP + FP)$ (Alert trustworthiness) |
| **Recall** | **83.76%** | 39.32% | $TP / (TP + FN)$ (Vulnerability capture rate) |
| **F1-Score** | **0.6203** | 0.4600 | Harmonic mean of precision and recall |
| **Specificity** | **15.13%** | 68.91% | $TN / (TN + FP)$ (Clean code pass rate) |
| **False Positive Rate (FPR)** | **84.87%** | 31.09% | $FP / (FP + TN)$ (Noise rate on clean code) |
| **False Negative Rate (FNR)** | **16.24%** | 60.68% | $FN / (FN + TP)$ (Miss rate on real vulnerabilities) |

*Confusion Matrix:* **TP: 98**, **FP: 101**, **TN: 18**, **FN: 19** (Total $N = 236$)

---

## 2. Per-Class Performance Breakdown

> [!NOTE]
> Per-class sample sizes ($N$) are explicitly listed. Small test slices ($N < 30$) reflect natural real-world distribution and are highlighted accordingly.

| Vulnerability Class | Ground Truth $N$ | Predicted $N$ | Precision | Recall | FPR | FNR | F1-Score |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`auth_bypass`** | 13 | 21 | 19.1% | 30.8% | 7.6% | 69.2% | 0.2353 |
| **`missing_authz_check`** | 33 | 62 | 21.0% | 39.4% | 24.1% | 60.6% | 0.2737 |
| **`incorrect_authz`** | 46 | 97 | 22.7% | 47.8% | 39.5% | 52.2% | 0.3077 |
| **`IDOR`** | 25 | 19 | 31.6% | 24.0% | 6.2% | 76.0% | 0.2727 |

---

## 3. Multi-Language Slicing & Generalization

| Language | Total $N$ (Vuln / Clean) | Accuracy | Precision | Recall | Specificity | FPR | FNR | F1-Score |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`go`** | 29 (14 / 15) | 48.3% | 47.6% | 71.4% | 26.7% | 73.3% | 28.6% | 0.5714 |
| **`java`** | 10 (5 / 5) | 50.0% | 50.0% | 80.0% | 20.0% | 80.0% | 20.0% | 0.6154 |
| **`javascript`** | 46 (23 / 23) | 50.0% | 50.0% | 91.3% | 8.7% | 91.3% | 8.7% | 0.6462 |
| **`php`** | 93 (46 / 47) | 50.5% | 50.0% | 84.8% | 17.0% | 83.0% | 15.2% | 0.6290 |
| **`python`** | 22 (11 / 11) | 50.0% | 50.0% | 81.8% | 18.2% | 81.8% | 18.2% | 0.6207 |
| **`typescript`** | 36 (18 / 18) | 44.4% | 46.9% | 83.3% | 5.6% | 94.4% | 16.7% | 0.6000 |

---

## 4. Cross-Language CWE Matrix (Precision / Recall / $N$)

| Vulnerability Class | Go | Java | JavaScript | PHP | Python | TypeScript |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`auth_bypass`** | P: 0% / R: 0% ($N=4$) | — ($N=0$) | P: 18% / R: 67% ($N=3$) | P: 25% / R: 25% ($N=4$) | P: 50% / R: 50% ($N=2$) | — ($N=0$) |
| **`missing_authz_check`** | P: 25% / R: 33% ($N=3$) | P: 0% / R: 0% ($N=3$) | P: 10% / R: 40% ($N=5$) | P: 9% / R: 12% ($N=8$) | P: 36% / R: 67% ($N=6$) | P: 38% / R: 62% ($N=8$) |
| **`incorrect_authz`** | P: 12% / R: 50% ($N=4$) | P: 20% / R: 50% ($N=2$) | P: 33% / R: 22% ($N=9$) | P: 26% / R: 64% ($N=25$) | P: 0% / R: 0% ($N=1$) | P: 17% / R: 20% ($N=5$) |
| **`IDOR`** | P: 0% / R: 0% ($N=3$) | — ($N=0$) | P: 50% / R: 33% ($N=6$) | P: 0% / R: 0% ($N=9$) | P: 33% / R: 50% ($N=2$) | P: 30% / R: 60% ($N=5$) |

---

## 5. Hard-Case Behavior Analysis

| Hard-Case Category | Sample Size ($N$) | Correct | Errors (FP / FN) | Success Rate | Error Rate |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Subtle Vulnerabilities (Looks Clean)** | 71 | 60 | 11 FN | **84.5%** | 15.5% FNR |
| **Suspicious-Looking Clean Code** | 88 | 15 | 73 FP | **17.1%** | 83.0% FPR |

---

## 6. Confidence Calibration & Reliability Diagram (ECE)

**Expected Calibration Error (ECE):** **`0.4409`**  
**Overconfident Error Count ($P \ge 0.85$ on incorrect prediction):** **`100`**

| Confidence Bin Range | Sample Count ($N$) | Avg Predicted Conf | Expected Acc | Actual Accuracy | Calibration Gap |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `[0.00, 0.20)` | 37 | 7.4% | 92.6% | 48.6% | 43.9% |
| `[0.20, 0.40)` | 0 | 0.0% | 30.0% | 0.0% | 0.0% |
| `[0.40, 0.60)` | 0 | 0.0% | 50.0% | 0.0% | 0.0% |
| `[0.60, 0.80)` | 1 | 63.0% | 63.0% | 0.0% | 63.0% |
| `[0.80, 1.00)` | 198 | 93.5% | 93.5% | 49.5% | 44.0% |