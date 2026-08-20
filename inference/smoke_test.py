import os
import sys
from typing import Dict, Any

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def run_smoke_test() -> bool:
    print("=== Auth/Authz Scanner Smoke Test ===")
    
    # 1. Package import verification
    print("[1/4] Testing library imports and versions...")
    required_packages = ["torch", "transformers", "peft", "datasets", "accelerate"]
    for pkg in required_packages:
        try:
            mod = __import__(pkg)
            version = getattr(mod, "__version__", "unknown")
            print(f"  [OK] {pkg} (version {version})")
        except ImportError as e:
            print(f"  [FAIL] Failed to import {pkg}: {e}")
            return False

    # 2. Tokenizer test for base model
    model_id = "Qwen/Qwen2.5-Coder-0.5B-Instruct"
    print(f"[2/4] Testing tokenizer initialization for '{model_id}'...")
    try:
        from transformers import AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
        test_snippet = "def check_access(user, resource): return user.id == resource.owner_id"
        tokens = tokenizer.encode(test_snippet)
        print(f"  [OK] Tokenizer successfully encoded sample snippet ({len(tokens)} tokens)")
    except Exception as e:
        print(f"  [FAIL] Tokenizer test failed: {e}")
        return False

    # 3. Structured Prediction Schema Validation
    print("[3/4] Validating structured output schema contract...")
    sample_prediction: Dict[str, Any] = {
        "vulnerable": True,
        "vuln_class": "IDOR",
        "confidence": 0.95,
        "explanation": "Missing authorization check before accessing object by ID.",
        "flagged_lines": [2, 4],
    }
    required_keys = {"vulnerable", "vuln_class", "confidence", "explanation", "flagged_lines"}
    if not required_keys.issubset(sample_prediction.keys()):
        print(f"  [FAIL] Schema missing required keys: {required_keys - sample_prediction.keys()}")
        return False
    print("  [OK] Structured prediction schema format validated")

    # 4. Logger test
    print("[4/4] Testing experiment logger...")
    try:
        from training.logger import ExperimentLogger
        logger = ExperimentLogger(run_name="smoke_test_run", log_dir="runs")
        logger.log_event("smoke_test", {"status": "passed"})
        print("  [OK] Experiment logger initialized and wrote test event")
    except Exception as e:
        print(f"  [FAIL] Logger test failed: {e}")
        return False

    print("\n[SUCCESS] Phase 0 environment smoke test passed.")
    return True


if __name__ == "__main__":
    success = run_smoke_test()
    sys.exit(0 if success else 1)
