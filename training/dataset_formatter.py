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

    is_vuln = bool(record.get("is_vulnerable", False))
    source = str(record.get("source", "")).lower()
    certainty = str(record.get("certainty", "")).lower()
    is_synth = bool(record.get("is_synthetic", False))
    rec_id = str(record.get("id", ""))
    h_val = int(hashlib.md5(rec_id.encode()).hexdigest()[:4], 16)

    if is_vuln:
        # Tier 1 (High Certainty): Verified Real CVE Fixes (NVD/GHSA, CVEfixes, CrossVul, PrimeVul) -> 0.90 - 0.98
        if source in ("github_advisories", "cvefixes", "crossvul", "primevul") or (certainty == "high" and not is_synth):
            offset = (h_val % 9) * 0.01
            return round(0.90 + offset, 2)  # 0.90 to 0.98

        # Tier 2 (Moderate-High Certainty): Third-Party Disclosures & Verified Bug Bounties -> 0.78 - 0.88
        elif source in ("hackerone_disclosures", "bugcrowd_disclosures") or certainty == "medium":
            offset = (h_val % 11) * 0.01
            return round(0.78 + offset, 2)  # 0.78 to 0.88

        # Tier 3 (Intermediate / Borderline Vuln): Pattern-Mined / Static Heuristic Signals -> 0.55 - 0.72
        elif source in ("github_pattern_mining", "heuristic_scans") or certainty == "low":
            offset = (h_val % 18) * 0.01
            return round(0.55 + offset, 2)  # 0.55 to 0.72

        # Tier 4 (Mutations): Real-Code Injected Mutations -> 0.85 - 0.95
        else:
            offset = (h_val % 11) * 0.01
            return round(0.85 + offset, 2)  # 0.85 to 0.95

    else:
        # Clean Negative Cases
        # Tier 1: Verified Framework Clean Modules (Pure Core) -> 0.02 - 0.08
        if source in ("real_framework_negative", "curated_clean_patterns") and "hard_negative" not in source:
            offset = (h_val % 7) * 0.01
            return round(0.02 + offset, 2)  # 0.02 to 0.08

        # Tier 2: Fixed-Pair Clean Versions / Post-Patch Refactorings -> 0.08 - 0.20
        elif "fixed" in rec_id or "patch" in rec_id or source in ("cvefixes_fixed", "crossvul_fixed"):
            offset = (h_val % 13) * 0.01
            return round(0.08 + offset, 2)  # 0.08 to 0.20

        # Tier 3: Intermediate Suspicious Clean / Hard Negatives (Complex Handlers) -> 0.25 - 0.45
        elif "hard_negative" in source or source in ("curated_suspicious_clean", "github_pattern_mining") or certainty in ("medium", "low"):
            offset = (h_val % 21) * 0.01
            return round(0.25 + offset, 2)  # 0.25 to 0.45

        # Tier 4: Standard Clean Negative Base -> 0.05 - 0.15
        else:
            offset = (h_val % 11) * 0.01
            return round(0.05 + offset, 2)  # 0.05 to 0.15


def format_assistant_response(record: Dict[str, Any]) -> str:
    """Generate structured JSON response conforming to Layer 2 / Layer 3 schema contract."""
    is_vuln = bool(record.get("is_vulnerable", False))
    vuln_class = record.get("vuln_class", "none")
    if vuln_class not in VALID_VULN_CLASSES:
        vuln_class = "none" if not is_vuln else "missing_authz_check"

    confidence = derive_calibrated_confidence(record)
    
    raw_explanation = str(record.get("explanation", "")).strip()
    if not raw_explanation:
        explanation = "No vulnerability detected in authentication/authorization logic." if not is_vuln else "Authentication or authorization vulnerability detected."
    else:
        # Extract first concise paragraph / sentence and cap to max 180 chars
        first_chunk = raw_explanation.split("\n\n")[0].split("\n*")[0].replace("\n", " ").strip()
        if len(first_chunk) > 180:
            explanation = first_chunk[:177] + "..."
        else:
            explanation = first_chunk

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
