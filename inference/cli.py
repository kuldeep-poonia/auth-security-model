"""Command-Line Security Auditor CLI.

Scan single source files or entire directories for authentication,
authorization, IDOR, and privilege escalation vulnerabilities.

Usage:
    python -m inference.cli audit path/to/code.py
    python -m inference.cli scan ./my_project --recursive
"""

import argparse
import json
import os
import sys
import time
from typing import List

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from inference.detector import AuthSecurityDetector, LANGUAGE_EXTENSIONS


def scan_path(detector: AuthSecurityDetector, target_path: str, recursive: bool = True) -> List[dict]:
    results = []

    if os.path.isfile(target_path):
        files_to_scan = [target_path]
    elif os.path.isdir(target_path):
        files_to_scan = []
        for root, _, files in os.walk(target_path):
            if not recursive and root != target_path:
                continue
            # Skip hidden folders, node_modules, .venv, git
            if any(part.startswith(".") or part in ["node_modules", "venv", ".venv", "__pycache__"] for part in root.split(os.sep)):
                continue
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in LANGUAGE_EXTENSIONS:
                    files_to_scan.append(os.path.join(root, f))
    else:
        print(f"[ERROR] Target path does not exist: {target_path}")
        return results

    print(f"[INFO] Scanning {len(files_to_scan)} source files...")
    print("=" * 80)

    vulnerable_count = 0

    for idx, fpath in enumerate(files_to_scan, 1):
        rel_path = os.path.relpath(fpath, PROJECT_ROOT) if fpath.startswith(PROJECT_ROOT) else fpath
        try:
            report = detector.audit_file(fpath)
            is_vuln = report["is_vulnerable"]
            vclass = report["vulnerability_class"]
            conf = report["confidence"]
            expl = report["explanation"]
            lat = report["latency_ms"]

            if is_vuln:
                vulnerable_count += 1
                status = f"\033[91m[VULNERABLE: {vclass.upper()}]\033[0m"
            else:
                status = "\033[92m[CLEAN / SOUND]\033[0m"

            print(f"[{idx:03d}/{len(files_to_scan):03d}] {status} {rel_path} ({report['language']}) - {lat}ms (conf: {conf:.2f})")
            if is_vuln:
                print(f"        \033[93mTrace:\033[0m {expl[:120]}...")
                if report.get("flagged_lines"):
                    print(f"        \033[93mLines:\033[0m {report['flagged_lines']}")

            results.append(report)
        except Exception as e:
            print(f"[{idx:03d}/{len(files_to_scan):03d}] \033[91m[ERROR]\033[0m {rel_path}: {e}")

    print("=" * 80)
    print(f"SCAN COMPLETE: Scanned {len(files_to_scan)} files | Found {vulnerable_count} vulnerable files.")
    print("=" * 80)
    return results


def main():
    parser = argparse.ArgumentParser(description="Auth Security AI Auditor CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    audit_parser = subparsers.add_parser("audit", help="Audit a file or directory")
    audit_parser.add_argument("path", type=str, help="Path to file or directory to scan")
    audit_parser.add_argument("--model_path", type=str, default="checkpoints_1.5b/final_adapter", help="Model adapter or merged model path")
    audit_parser.add_argument("--base_model", type=str, default="Qwen/Qwen2.5-Coder-1.5B-Instruct", help="Base model ID")
    audit_parser.add_argument("--device", type=str, default=None, help="Device (cpu or cuda)")
    audit_parser.add_argument("--json", action="store_true", help="Output results in raw JSON format")
    audit_parser.add_argument("--no-recursive", action="store_true", help="Do not scan subdirectories recursively")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "audit":
        detector = AuthSecurityDetector(
            model_path=args.model_path,
            base_model_id=args.base_model,
            device=args.device,
        )
        results = scan_path(detector, args.path, recursive=not args.no_recursive)

        if args.json:
            print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
