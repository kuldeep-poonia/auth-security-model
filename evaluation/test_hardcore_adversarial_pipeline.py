"""Unit tests for the 60-case hardcore adversarial benchmark & error mining pipeline."""

import json
import pytest
from evaluation.hardcore_benchmark_100 import get_hardcore_benchmark_cases
from evaluation.adversarial_error_miner import generate_diagnostic_critique


def test_benchmark_has_60_unique_cases():
    cases = get_hardcore_benchmark_cases()
    assert len(cases) == 60, f"Expected 60 cases, got {len(cases)}"
    
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), "Case IDs must be strictly unique"


def test_benchmark_language_coverage():
    cases = get_hardcore_benchmark_cases()
    languages = {c["language"] for c in cases}
    required_langs = {"python", "go", "typescript", "javascript", "java", "csharp", "php"}
    assert required_langs.issubset(languages), f"Missing required languages: {required_langs - languages}"


def test_benchmark_balanced_ground_truth():
    cases = get_hardcore_benchmark_cases()
    vuln = [c for c in cases if c["true_is_vulnerable"]]
    clean = [c for c in cases if not c["true_is_vulnerable"]]
    
    assert len(vuln) > 0, "Must contain vulnerable cases"
    assert len(clean) > 0, "Must contain clean hard negative cases"
    # Ensure reasonable balance
    assert 25 <= len(vuln) <= 40
    assert 20 <= len(clean) <= 35


def test_generate_diagnostic_critique_false_positive():
    sample_case = {
        "id": "test-clean-01",
        "title": "Clean Test",
        "language": "python",
        "code": "def foo(): pass",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code using row locks."
    }
    critique = generate_diagnostic_critique(
        test_case=sample_case,
        pred_vuln=True,
        pred_class="IDOR",
        confidence=0.92,
        pred_explanation="Flagged"
    )
    assert critique["error_type"] == "FALSE_POSITIVE"
    assert critique["penalty_weight"] == 4.0
    assert critique["is_vulnerable"] is False
    assert "False Alarm Critique" in critique["critique"]


def test_generate_diagnostic_critique_false_negative():
    sample_case = {
        "id": "test-vuln-01",
        "title": "Vuln Test",
        "language": "go",
        "code": "func bar() {}",
        "true_is_vulnerable": True,
        "true_vuln_class": "auth_bypass",
        "flaw_description": "Accepts none algorithm."
    }
    critique = generate_diagnostic_critique(
        test_case=sample_case,
        pred_vuln=False,
        pred_class="none",
        confidence=0.10,
        pred_explanation="Clean"
    )
    assert critique["error_type"] == "FALSE_NEGATIVE"
    assert critique["penalty_weight"] == 4.0
    assert critique["is_vulnerable"] is True
    assert "Missed Vulnerability Critique" in critique["critique"]
