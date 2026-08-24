<div align="center">

# 🛡️ AuthGuard-1.5B: Autonomous AI Security Auditor
### *Next-Gen LLM for Detecting Authentication & Authorization Flaws with 100% Recall*

[![GitHub Stars](https://img.shields.io/github/stars/kuldeep-poonia/auth-security-model?style=for-the-badge&color=ffd166&logo=github)](https://github.com/kuldeep-poonia/auth-security-model/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Accuracy](https://img.shields.io/badge/Hardcore_Benchmark-98.33%25-brightgreen?style=for-the-badge&logo=target)](https://github.com/kuldeep-poonia/auth-security-model)
[![Recall](https://img.shields.io/badge/Security_Recall-100.0%25-success?style=for-the-badge&logo=shield)](https://github.com/kuldeep-poonia/auth-security-model)
[![VRAM](https://img.shields.io/badge/VRAM_Footprint-1.2_GB-blueviolet?style=for-the-badge&logo=nvidia)](https://github.com/kuldeep-poonia/auth-security-model)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)

<p align="center">
  <b>A specialized, high-precision security model fine-tuned & adversarially reinforced to catch IDORs, Broken Object-Level Auth (BOLA), Privilege Escalations, and Auth Bypasses across 6 languages.</b>
</p>

```
========================================================================================
  [001/001] [VULNERABLE: IDOR] api/invoices.py (python) - 48ms (confidence: 0.92)
  Trace: [Data Flow] Route parameter `invoice_id` queried directly without verifying
         `tenant_id` or caller ownership. Allows cross-tenant data exfiltration.
  Flagged Lines: [4, 5]
========================================================================================
```

[⚡ Quick Start](#-quick-start) • [📊 Hardcore Benchmark](#-benchmark-results) • [🔬 Architecture](./architecture.md) • [📦 GGUF / CPU Deployment](#-quantization--gguf)

</div>

---

## 💥 The Problem: Why Traditional SAST Tools Fail

Traditional Static Application Security Testing (SAST) tools rely on regex rules and simplistic AST heuristics:
- ❌ **50%+ False Positive Rates:** Flagging clean code with secure defensive checks.
- ❌ **Blind to Business Logic:** Inability to detect missing tenant scoping, inverted role hierarchies, or subtle SpEL parameter mismatches.
- ❌ **Framework Blindness:** Fails on Next.js 14 Server Actions, Strawberry GraphQL, FastAPI async dependencies, and Spring Boot method security.

**AuthGuard-1.5B** understands **semantic data flow and security intent**, dropping False Positives to just **3.57%** while maintaining a **flawless 100% Recall (0 Missed Vulnerabilities)**.

---

## ✨ Key Features

- 🎯 **100% Security Recall:** Catches 32 out of 32 hardcore adversarial vulnerability patterns without missing a single flaw.
- 🌐 **True Multi-Language Mastery:** Python, Go (Golang), TypeScript, JavaScript, Java (Spring Boot), C# (.NET Core), and PHP (Laravel).
- ⚡ **Ultra-Lightweight & Fast:** 1.54B parameters — consumes only **1.2 GB VRAM** in 4-bit mode (~50ms inference per function).
- 💻 **Zero-GPU CPU Mode:** Easily exported to **GGUF format (`Q4_K_M`)** to run at 200+ tokens/sec on any developer laptop.
- 🤖 **Deterministic JSON Contract:** Guaranteed structured output (`is_vulnerable`, `vuln_class`, `confidence`, `explanation`, `flagged_lines`) for direct CI/CD DevSecOps integration.

---

## 📊 Benchmark Results (60 Hardcore Multi-Language Adversarial Suite)

Tested against 60 deeply obfuscated, real-world authorization challenges across 12 frameworks:

| Evaluation Metric | Raw Base Model (`Qwen2.5-1.5B`) | After LoRA Fine-Tuning | **AuthGuard-1.5B (Reinforced)** |
|---|:---:|:---:|:---:|
| **Binary Accuracy** | 73.33% (44 / 60) | 96.67% (58 / 60) | 🚀 **98.33% (59 / 60)** |
| **Security Recall (Flaws Caught)** | 100.00% (32 / 32) | 100.00% (32 / 32) | 🎯 **100.00% (32 / 32 - 0 Missed Flaws)** |
| **False Positive Rate** | 57.14% (16 False Alarms) | 7.14% (2 False Alarms) | 🛡️ **3.57% (Only 1 False Alarm)** |
| **F1-Score** | 0.8000 | 0.9697 | 🏆 **0.9846** |

### Per-Language Breakdown:
- 🟢 **Python (FastAPI, Django, Flask, GraphQL):** **10 / 10 (100.0%)**
- 🟢 **Go (Gin, Chi, Fiber, GORM):** **10 / 10 (100.0%)**
- 🟢 **C# / .NET (ASP.NET Core, EF Core):** **10 / 10 (100.0%)**
- 🟢 **JavaScript (Express, Sequelize):** **3 / 3 (100.0%)**
- 🟢 **Java (Spring Boot, Quarkus):** **10 / 10 (100.0% Binary Correct)**
- 🟢 **TypeScript (Next.js 14, NestJS):** **7 / 7 (100.0% Binary Correct)**
- 🟢 **PHP (Laravel, Symfony, Slim):** **9 / 10 (90.0% Correct)**

---

## ⚡ Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/kuldeep-poonia/auth-security-model.git
cd auth-security-model

# Install dependencies
pip install -r requirements.txt
```

### 2. Command-Line Security Audit

Scan any file or entire project repository with colored terminal output:

```bash
# Scan a single source code file
python -m inference.cli audit ./path/to/controller.py

# Recursively scan an entire backend repository
python -m inference.cli audit ./my_backend_project

# Export machine-readable JSON for CI/CD pipelines
python -m inference.cli audit ./my_backend_project --json
```

### 3. Python SDK Usage

```python
from inference.detector import AuthSecurityDetector

# Initialize detector (Auto-detects CUDA / CPU / 4-bit)
detector = AuthSecurityDetector(device="cuda")

code_snippet = """
@app.get("/api/user/{user_id}/invoices/{invoice_id}")
async def get_invoice(user_id: int, invoice_id: int, db: Session = Depends(get_db)):
    # Flaw: Direct query without checking if invoice belongs to authenticated user
    return db.query(Invoice).filter(Invoice.id == invoice_id).first()
"""

# Audit code snippet
report = detector.audit_code(code_snippet, language="python")

print(f"Vulnerable: {report['is_vulnerable']}")
print(f"Class:      {report['vulnerability_class']}")
print(f"Confidence: {report['confidence']}")
print(f"Trace:      {report['explanation']}")
```

**Output:**
```json
{
  "is_vulnerable": true,
  "vulnerability_class": "IDOR",
  "confidence": 0.92,
  "explanation": "Direct database query on `Invoice.id == invoice_id` fails to assert tenant or user ownership with `user_id`.",
  "flagged_lines": [4, 5],
  "latency_ms": 42.15
}
```

---

## 📦 Quantization & GGUF (0-GPU CPU Deployment)

Run this model on any average developer laptop with zero dedicated GPU requirements:

```bash
# 1. Merge LoRA weights into standalone weights
python model_packaging/merge_lora.py --output_dir checkpoints/merged_model

# 2. Export and quantize to GGUF Q4_K_M (Only ~800 MB footprint!)
python model_packaging/export_gguf.py --model_dir checkpoints/merged_model --quant_type q4_k_m
```

---

## 🛡️ Covered Vulnerability Taxonomy

| Vulnerability | CWE ID | Description |
|---|:---:|---|
| **IDOR / BOLA** | `CWE-639` | Insecure Direct Object References in single/batch queries and nested sub-resources. |
| **Auth Bypass** | `CWE-287` | JWT algorithm `'none'`, timing attacks in HMAC/signatures, trusted client headers. |
| **Missing Authz Check** | `CWE-862` | Unprotected destructive reset/admin endpoints lacking decorators or middleware. |
| **Incorrect Authz** | `CWE-863` | Inverted enum role comparisons, bitmask default bypasses, SpEL mismatch. |
| **Sound Clean Code** | `None` | Constant-time comparisons, scoped queries, single-use atomic tokens. |

---

## 🤝 Contributing & Star History

We welcome contributions! If you found this project helpful, please consider giving it a ⭐ **Star** on GitHub!

<div align="center">

[![Star History Chart](https://api.star-history.com/svg?repos=kuldeep-poonia/auth-security-model&type=Date)](https://star-history.com/#kuldeep-poonia/auth-security-model&Date)

</div>

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
