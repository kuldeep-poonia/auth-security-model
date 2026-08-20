# Finalized Dataset Splits Summary (Phase 3 & Phase 4)

**Generated:** 2026-08-20T03:40:23.600571+00:00
**Total Corpus Volume:** 4222 records across Train / Val / Test

---

## 1. Split Allocation & Class Balance Overview

| Partition | Total Records | Positive (Vulnerable) | Negative (Clean) | Real Seed Count | Synthetic / Mutated | Real Share % |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Train** | 3752 | 1876 (50.0%) | 1876 (50.0%) | 1876 | 1876 | 50.0% |
| **Val** | 234 | 117 (50.0%) | 117 (50.0%) | 234 | 0 | 100.0% |
| **Test (Held-Out)** | 236 | 117 (49.6%) | 119 (50.4%) | 236 | **0** | **100.0%** |
| **Total** | **4222** | **2110** | **2112** | **2346** | **1876** | — |

---

## 2. Vulnerability Class Distribution by Split

| `vuln_class` Identifier | Train Count | Val Count | Test Count | Total |
| :--- | :--- | :--- | :--- | :--- |
| `auth_bypass` | 431 | 23 | 13 | 467 |
| `missing_authz_check` | 497 | 39 | 33 | 569 |
| `incorrect_authz` | 518 | 33 | 46 | 597 |
| `IDOR` | 430 | 22 | 25 | 477 |
| `none` (Clean Negatives) | 1876 | 117 | 119 | 2112 |

---

## 3. Multi-Language Coverage by Split

| Language | Train | Val | Test | Total |
| :--- | :--- | :--- | :--- | :--- |
| `go` | 684 | 18 | 29 | 731 |
| `java` | 362 | 34 | 10 | 406 |
| `javascript` | 281 | 26 | 46 | 353 |
| `php` | 1175 | 80 | 93 | 1348 |
| `python` | 864 | 34 | 22 | 920 |
| `typescript` | 386 | 42 | 36 | 464 |

---

## 4. Leakage & Split Discipline Verification
- [x] **Zero Code Overlap:** `train_code_hashes ∩ test_code_hashes == ∅`
- [x] **Zero Source Overlap:** All records partitioned by source repository and CVE ID cluster.
- [x] **Pristine Test Set:** Test set contains 0 synthetic or mutated examples (100% held-out real data).
- [x] **50:50 Class Balance:** Balanced representation of positive (vulnerable) and negative (clean) instances to prevent false-positive bias.
