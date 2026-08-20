import json
import os
import sys
from typing import Any, Dict, List, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

SYSTEM_PROMPT = (
    "You are an expert security auditor specialized in web application authentication and authorization vulnerabilities.\n"
    "Analyze the provided code unit and determine if it contains an authentication or authorization vulnerability.\n"
    "You must output ONLY valid JSON matching this schema:\n"
    "{\n"
    '  "vulnerable": boolean,\n'
    '  "vuln_class": "IDOR" | "auth_bypass" | "missing_authz_check" | "incorrect_authz" | "none",\n'
    '  "confidence": float (0.0 to 1.0),\n'
    '  "explanation": string,\n'
    '  "flagged_lines": [start_line, end_line]\n'
    "}"
)

VALID_VULN_CLASSES = {"IDOR", "auth_bypass", "missing_authz_check", "incorrect_authz", "none"}


def format_user_prompt(code: str, language: str) -> str:
    """Format input code snippet and language into user prompt."""
    return f"Language: {language}\n\nCode:\n```{language}\n{code}\n```"


def derive_calibrated_confidence(record: Dict[str, Any]) -> float:
    """Derive calibrated continuous confidence score (0.0 to 1.0) based on source certainty tier and signal ambiguity."""
    import hashlib
    
    # If explicitly set to an intermediate float, respect it
    if "confidence_target" in record and record["confidence_target"] not in (1.0, 0.0):
        return round(float(record["confidence_target"]), 2)

    is_vuln = bool(record.get("is_vulnerable", False))
    source = str(record.get("source", "")).lower()
    certainty = str(record.get("certainty", "")).lower()
    is_synth = bool(record.get("is_synthetic", False))

    if is_vuln:
        # Tier 1A: Verified Real CVE Fixes (NVD/GHSA, CVEfixes, CrossVul, PrimeVul) -> 0.92 - 0.98
        if source in ("github_advisories", "cvefixes", "crossvul", "primevul") or (certainty == "high" and not is_synth):
            h_val = int(hashlib.md5(str(record.get("id", "")).encode()).hexdigest()[:4], 16) % 7
            return round(0.92 + (h_val * 0.01), 2)  # 0.92 to 0.98

        # Tier 1B: Real-Code Injected Mutations (100% Ground Truth by Construction) -> 0.88 - 0.95
        elif is_synth or source == "real_code_mutation":
            h_val = int(hashlib.md5(str(record.get("id", "")).encode()).hexdigest()[:4], 16) % 8
            return round(0.88 + (h_val * 0.01), 2)  # 0.88 to 0.95

        # Tier 2: Third-Party Disclosures (HackerOne, Bugcrowd) -> 0.75 - 0.85
        elif source in ("hackerone_disclosures", "bugcrowd_disclosures") or certainty == "medium":
            h_val = int(hashlib.md5(str(record.get("id", "")).encode()).hexdigest()[:4], 16) % 11
            return round(0.75 + (h_val * 0.01), 2)  # 0.75 to 0.85

        # Tier 3: Lower Certainty / Pattern-Mined -> 0.55 - 0.70 (Borderline / worth reviewing)
        else:
            h_val = int(hashlib.md5(str(record.get("id", "")).encode()).hexdigest()[:4], 16) % 16
            return round(0.55 + (h_val * 0.01), 2)  # 0.55 to 0.70

    else:
        # Clean Negative Cases
        # Tier 1: Verified Framework Clean Modules -> 0.02 - 0.06
        if source in ("real_framework_negative", "curated_clean_patterns") or (certainty == "high" and not is_synth):
            h_val = int(hashlib.md5(str(record.get("id", "")).encode()).hexdigest()[:4], 16) % 5
            return round(0.02 + (h_val * 0.01), 2)  # 0.02 to 0.06

        # Tier 2: Fixed-Pair Clean Versions / Refactorings -> 0.06 - 0.15
        elif is_synth or "fixed" in str(record.get("id", "")):
            h_val = int(hashlib.md5(str(record.get("id", "")).encode()).hexdigest()[:4], 16) % 10
            return round(0.06 + (h_val * 0.01), 2)  # 0.06 to 0.15

        # Tier 3: Ambiguous / Complex Clean Code Units -> 0.20 - 0.35
        else:
            h_val = int(hashlib.md5(str(record.get("id", "")).encode()).hexdigest()[:4], 16) % 16
            return round(0.20 + (h_val * 0.01), 2)  # 0.20 to 0.35


def format_assistant_response(record: Dict[str, Any]) -> str:
    """Generate structured JSON response conforming to Layer 2 / Layer 3 schema contract."""
    is_vuln = bool(record.get("is_vulnerable", False))
    vuln_class = record.get("vuln_class", "none")
    if vuln_class not in VALID_VULN_CLASSES:
        vuln_class = "none" if not is_vuln else "missing_authz_check"

    confidence = derive_calibrated_confidence(record)
    explanation = record.get("explanation", "Clean code." if not is_vuln else "Vulnerability detected.")

    lines = record.get("code", "").splitlines()
    line_count = max(1, len(lines))
    flagged_lines = [1, line_count] if is_vuln else []

    payload = {
        "vulnerable": is_vuln,
        "vuln_class": vuln_class,
        "confidence": confidence,
        "explanation": explanation,
        "flagged_lines": flagged_lines,
    }
    return json.dumps(payload, indent=2)


def format_record_to_chat(record: Dict[str, Any]) -> List[Dict[str, str]]:
    """Convert a single dataset record into standard multi-turn ChatML messages."""
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": format_user_prompt(record["code"], record["language"])},
        {"role": "assistant", "content": format_assistant_response(record)},
    ]


def load_and_format_dataset(split_path: str) -> List[Dict[str, Any]]:
    """Load JSON partition file and format into tokenizable training instances."""
    if not os.path.exists(split_path):
        raise FileNotFoundError(f"Split file not found: {split_path}")

    with open(split_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    formatted_items = []
    for r in records:
        messages = format_record_to_chat(r)
        formatted_items.append({
            "id": r.get("id"),
            "messages": messages,
            "is_vulnerable": r.get("is_vulnerable"),
            "vuln_class": r.get("vuln_class"),
            "language": r.get("language"),
            "source": r.get("source"),
            "is_synthetic": r.get("is_synthetic", False),
        })

    return formatted_items


if __name__ == "__main__":
    train_split = "data/splits/train.json"
    if os.path.exists(train_split):
        items = load_and_format_dataset(train_split)
        print(f"[OK] Loaded and formatted {len(items)} training items.")
        print("Sample item messages:")
        print(json.dumps(items[0]["messages"], indent=2))
