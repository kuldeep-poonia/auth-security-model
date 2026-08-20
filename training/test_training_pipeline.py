import json
import os
import pytest

from training.dataset_formatter import (
    format_user_prompt,
    format_assistant_response,
    format_record_to_chat,
    load_and_format_dataset,
    SYSTEM_PROMPT,
)


def test_format_user_prompt():
    code = "def check(): return True"
    prompt = format_user_prompt(code, "python")
    assert "Language: python" in prompt
    assert "```python" in prompt
    assert "def check(): return True" in prompt


def test_format_assistant_response_positive():
    record = {
        "id": "CVE-2023-01",
        "source": "github_advisories",
        "is_vulnerable": True,
        "vuln_class": "IDOR",
        "explanation": "Missing user_id scoping.",
        "code": "def get(id):\n    return db.find(id)",
    }
    resp_str = format_assistant_response(record)
    parsed = json.loads(resp_str)
    assert parsed["vulnerable"] is True
    assert parsed["vuln_class"] == "IDOR"
    assert 0.90 <= parsed["confidence"] <= 0.98
    assert parsed["explanation"] == "Missing user_id scoping."
    assert parsed["flagged_lines"] == [1, 2]


def test_format_assistant_response_negative():
    record = {
        "id": "clean-01",
        "source": "real_framework_negative",
        "is_vulnerable": False,
        "vuln_class": "none",
        "explanation": "Properly enforced authorization check.",
        "code": "def get(user, id):\n    if user.is_admin:\n        return db.find(id)",
    }
    resp_str = format_assistant_response(record)
    parsed = json.loads(resp_str)
    assert parsed["vulnerable"] is False
    assert parsed["vuln_class"] == "none"
    assert 0.02 <= parsed["confidence"] <= 0.08
    assert parsed["flagged_lines"] == []


def test_derive_calibrated_confidence_tiers():
    from training.dataset_formatter import derive_calibrated_confidence

    # High certainty CVE -> 0.90 to 0.98
    cve_rec = {"id": "CVE-2023-1234", "source": "github_advisories", "is_vulnerable": True}
    cve_conf = derive_calibrated_confidence(cve_rec)
    assert 0.90 <= cve_conf <= 0.98

    # High certainty Injected Mutation (100% Ground Truth by Construction) -> 0.85 to 0.95
    mut_rec = {"id": "mutated-01", "source": "real_code_mutation", "is_synthetic": True, "is_vulnerable": True}
    mut_conf = derive_calibrated_confidence(mut_rec)
    assert 0.85 <= mut_conf <= 0.95

    # Medium certainty Third-Party Disclosures -> 0.78 to 0.88
    disc_rec = {"id": "h1-01", "source": "hackerone_disclosures", "is_vulnerable": True}
    disc_conf = derive_calibrated_confidence(disc_rec)
    assert 0.78 <= disc_conf <= 0.88

    # Lower certainty Pattern-Mined -> 0.55 to 0.72 (Borderline)
    pm_rec = {"id": "pattern-mined-01", "source": "github_pattern_mining", "is_vulnerable": True}
    pm_conf = derive_calibrated_confidence(pm_rec)
    assert 0.55 <= pm_conf <= 0.72

    # High certainty Clean Framework negative -> 0.02 to 0.08
    clean_rec = {"id": "django-mixins-01", "source": "real_framework_negative", "is_vulnerable": False}
    clean_conf = derive_calibrated_confidence(clean_rec)
    assert 0.02 <= clean_conf <= 0.08

    # Ambiguous Suspicious Clean code -> 0.25 to 0.45
    amb_rec = {"id": "suspicious-clean-01", "source": "curated_suspicious_clean", "is_vulnerable": False}
    amb_conf = derive_calibrated_confidence(amb_rec)
    assert 0.25 <= amb_conf <= 0.45


def test_format_record_to_chat():
    record = {
        "id": "test-01",
        "is_vulnerable": True,
        "vuln_class": "missing_authz_check",
        "confidence_target": 1.0,
        "explanation": "No auth guard.",
        "code": "def delete(): pass",
        "language": "python",
    }
    chat = format_record_to_chat(record)
    assert len(chat) == 3
    assert chat[0]["role"] == "system"
    assert "expert security auditor" in chat[0]["content"]
    assert chat[1]["role"] == "user"
    assert chat[2]["role"] == "assistant"
    # Ensure assistant content is valid JSON
    assistant_json = json.loads(chat[2]["content"])
    assert assistant_json["vuln_class"] == "missing_authz_check"


def test_load_and_format_dataset_train_split():
    train_path = "data/splits/train.json"
    if not os.path.exists(train_path):
        pytest.skip("Train split not found")

    items = load_and_format_dataset(train_path)
    assert len(items) > 0
    first = items[0]
    assert "id" in first
    assert "messages" in first
    assert len(first["messages"]) == 3
    # Check that assistant payload parses
    resp = json.loads(first["messages"][2]["content"])
    assert "vulnerable" in resp
    assert "vuln_class" in resp
