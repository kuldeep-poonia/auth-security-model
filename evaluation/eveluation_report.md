# Phase 6 — Model Evaluation & Benchmark Report

**Generated:** 2026-08-20T09:14:00.458640Z  
**Evaluation Corpus:** Held-out Test Split (`data/splits/test.json`)  
**Test Set Composition:** 236 Records (100% Real Code, 0 Synthetic Mutations, 0 Data Leakage)

---

## 1. Overall Binary Classification Performance

| Metric | Fine-Tuned Model | Base Model Baseline | Description |
| :--- | :--- | :--- | :--- |
| **Accuracy** | **50.85%** | 54.24% | Overall correctness across vulnerable & clean units |
| **Precision** | **57.14%** | 55.42% | $TP / (TP + FP)$ (Alert trustworthiness) |
| **Recall** | **3.42%** | 39.32% | $TP / (TP + FN)$ (Vulnerability capture rate) |
| **F1-Score** | **0.0645** | 0.4600 | Harmonic mean of precision and recall |
| **Specificity** | **97.48%** | 68.91% | $TN / (TN + FP)$ (Clean code pass rate) |
| **False Positive Rate (FPR)** | **2.52%** | 31.09% | $FP / (FP + TN)$ (Noise rate on clean code) |
| **False Negative Rate (FNR)** | **96.58%** | 60.68% | $FN / (FN + TP)$ (Miss rate on real vulnerabilities) |

*Confusion Matrix:* **TP: 4**, **FP: 3**, **TN: 116**, **FN: 113** (Total $N = 236$)

---

## 2. Per-Class Performance Breakdown

> [!NOTE]
> Per-class sample sizes ($N$) are explicitly listed. Small test slices ($N < 30$) reflect natural real-world distribution and are highlighted accordingly.

| Vulnerability Class | Ground Truth $N$ | Predicted $N$ | Precision | Recall | FPR | FNR | F1-Score |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`auth_bypass`** | 13 | 0 | 0.0% | 0.0% | 0.0% | 100.0% | 0.0000 |
| **`missing_authz_check`** | 33 | 0 | 0.0% | 0.0% | 0.0% | 100.0% | 0.0000 |
| **`incorrect_authz`** | 46 | 7 | 28.6% | 4.3% | 2.6% | 95.7% | 0.0755 |
| **`IDOR`** | 25 | 0 | 0.0% | 0.0% | 0.0% | 100.0% | 0.0000 |

---

## 3. Multi-Language Slicing & Generalization

| Language | Total $N$ (Vuln / Clean) | Accuracy | Precision | Recall | Specificity | FPR | FNR | F1-Score |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`go`** | 29 (14 / 15) | 48.3% | 0.0% | 0.0% | 93.3% | 6.7% | 100.0% | 0.0000 |
| **`java`** | 10 (5 / 5) | 50.0% | 0.0% | 0.0% | 100.0% | 0.0% | 100.0% | 0.0000 |
| **`javascript`** | 46 (23 / 23) | 50.0% | 0.0% | 0.0% | 100.0% | 0.0% | 100.0% | 0.0000 |
| **`php`** | 93 (46 / 47) | 51.6% | 60.0% | 6.5% | 95.7% | 4.3% | 93.5% | 0.1176 |
| **`python`** | 22 (11 / 11) | 50.0% | 0.0% | 0.0% | 100.0% | 0.0% | 100.0% | 0.0000 |
| **`typescript`** | 36 (18 / 18) | 52.8% | 100.0% | 5.6% | 100.0% | 0.0% | 94.4% | 0.1053 |

---

## 4. Cross-Language CWE Matrix (Precision / Recall / $N$)

| Vulnerability Class | Go | Java | JavaScript | PHP | Python | TypeScript |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`auth_bypass`** | P: 0% / R: 0% ($N=4$) | — ($N=0$) | P: 0% / R: 0% ($N=3$) | P: 0% / R: 0% ($N=4$) | P: 0% / R: 0% ($N=2$) | — ($N=0$) |
| **`missing_authz_check`** | P: 0% / R: 0% ($N=3$) | P: 0% / R: 0% ($N=3$) | P: 0% / R: 0% ($N=5$) | P: 0% / R: 0% ($N=8$) | P: 0% / R: 0% ($N=6$) | P: 0% / R: 0% ($N=8$) |
| **`incorrect_authz`** | P: 0% / R: 0% ($N=4$) | P: 0% / R: 0% ($N=2$) | P: 0% / R: 0% ($N=9$) | P: 40% / R: 8% ($N=25$) | P: 0% / R: 0% ($N=1$) | P: 0% / R: 0% ($N=5$) |
| **`IDOR`** | P: 0% / R: 0% ($N=3$) | — ($N=0$) | P: 0% / R: 0% ($N=6$) | P: 0% / R: 0% ($N=9$) | P: 0% / R: 0% ($N=2$) | P: 0% / R: 0% ($N=5$) |

---

## 5. Hard-Case Behavior Analysis

| Hard-Case Category | Sample Size ($N$) | Correct | Errors (FP / FN) | Success Rate | Error Rate |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Subtle Vulnerabilities (Looks Clean)** | 71 | 2 | 69 FN | **2.8%** | 97.2% FNR |
| **Suspicious-Looking Clean Code** | 88 | 86 | 2 FP | **97.7%** | 2.3% FPR |

---

## 6. Confidence Calibration & Reliability Diagram (ECE)

**Expected Calibration Error (ECE):** **`0.4460`**  
**Overconfident Error Count ($P \ge 0.85$ on incorrect prediction):** **`3`**

| Confidence Bin Range | Sample Count ($N$) | Avg Predicted Conf | Expected Acc | Actual Accuracy | Calibration Gap |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `[0.00, 0.20)` | 229 | 4.5% | 95.5% | 50.7% | 44.9% |
| `[0.20, 0.40)` | 0 | 0.0% | 30.0% | 0.0% | 0.0% |
| `[0.40, 0.60)` | 0 | 0.0% | 50.0% | 0.0% | 0.0% |
| `[0.60, 0.80)` | 0 | 0.0% | 70.0% | 0.0% | 0.0% |
| `[0.80, 1.00)` | 7 | 93.4% | 93.4% | 57.1% | 36.3% |