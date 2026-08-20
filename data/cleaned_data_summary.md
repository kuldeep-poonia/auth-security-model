# Cleaned & Validated Dataset Summary (Phase 2)

**Generated:** 2026-08-19T11:11:35.378071+00:00
**Total Cleaned Records:** 2346
**Positive (Vulnerable) Count:** 839 (35.8%)
**Negative (Clean) Count:** 1507 (64.2%)

---

## 1. Vulnerability Class Distribution (Locked Taxonomy)

| `vuln_class` Identifier | Description | Total Count |
| :--- | :--- | :--- |
| `auth_bypass` | Improper Authentication / Bypass | 147 |
| `missing_authz_check` | Missing Authorization / Permission Check | 252 |
| `incorrect_authz` | Incorrect Authorization / Broken Access Control | 280 |
| `IDOR` | Broken Object-Level Authorization / User Key Bypass | 160 |
| `none` | Clean, Non-Vulnerable Code Unit | 1507 |

---

## 2. Multi-Language Distribution

| Language | Total Examples |
| :--- | :--- |
| `php` | 773 |
| `go` | 482 |
| `python` | 405 |
| `typescript` | 279 |
| `javascript` | 217 |
| `java` | 190 |

---

## 3. Data Integrity & Validation Confirmation
- [x] All records carry non-empty `code`, `language`, `vuln_class`, and `provenance`.
- [x] Locked taxonomy strictly enforced (`auth_bypass`, `missing_authz_check`, `incorrect_authz`, `IDOR`, `none`).
- [x] Negative examples sourced in balanced proportion to prevent false-positive overprediction.
- [x] Noise (comments, documentation, import-only edits) stripped from extracted code units.
