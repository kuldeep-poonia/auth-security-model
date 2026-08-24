"""Unit tests for packaging and inference modules."""

import os
import sys
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from inference.detector import (
    LANGUAGE_EXTENSIONS,
    AuthSecurityDetector,
    format_user_prompt,
    normalize_prediction,
    extract_json_from_response,
)
from model_packaging.merge_lora import parse_args as parse_merge_args
from model_packaging.export_gguf import parse_args as parse_gguf_args


def test_language_extension_mappings():
    assert LANGUAGE_EXTENSIONS[".py"] == "python"
    assert LANGUAGE_EXTENSIONS[".go"] == "go"
    assert LANGUAGE_EXTENSIONS[".js"] == "javascript"
    assert LANGUAGE_EXTENSIONS[".ts"] == "typescript"
    assert LANGUAGE_EXTENSIONS[".java"] == "java"
    assert LANGUAGE_EXTENSIONS[".cs"] == "csharp"
    assert LANGUAGE_EXTENSIONS[".php"] == "php"


def test_merge_lora_args_defaults():
    args = parse_merge_args([])
    assert args.base_model_id == "Qwen/Qwen2.5-Coder-1.5B-Instruct"
    assert args.adapter_path == "checkpoints_1.5b/final_adapter"
    assert args.output_dir == "checkpoints/merged_model"


def test_export_gguf_args_defaults():
    args = parse_gguf_args([])
    assert args.model_dir == "checkpoints/merged_model"
    assert args.quant_type == "q4_k_m"
    assert args.out_type == "f16"


def test_json_extraction():
    sample_text = '{"vulnerable": true, "vuln_class": "IDOR", "confidence": 0.95, "explanation": "Test"}'
    parsed = extract_json_from_response(sample_text)
    assert parsed["is_vulnerable"] is True
    assert parsed["vulnerability_class"] == "IDOR"
    assert parsed["confidence"] == 0.95


def test_user_prompt_format():
    prompt = format_user_prompt("def test(): pass", "python")
    assert "Language: python" in prompt
    assert "def test(): pass" in prompt
